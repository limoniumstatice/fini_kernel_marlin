/*
 * fs/f2fs/data.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/fs.h>
#include <linux/f2fs_fs.h>
#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include <linux/aio.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/swap.h>
#include <linux/prefetch.h>

#include "f2fs.h"
#include "node.h"
#include "segment.h"
#include <trace/events/f2fs.h>

#define NUM_PREALLOC_POST_READ_CTXS	128

static struct kmem_cache *bio_post_read_ctx_cache;
static mempool_t *bio_post_read_ctx_pool;

static bool __is_cp_guaranteed(struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode;
	struct f2fs_sb_info *sbi;

	if (!mapping)
		return false;

	inode = mapping->host;
	sbi = F2FS_I_SB(inode);

	if (inode->i_ino == F2FS_META_INO(sbi) ||
			inode->i_ino ==  F2FS_NODE_INO(sbi) ||
			S_ISDIR(inode->i_mode) ||
			(S_ISREG(inode->i_mode) &&
			(f2fs_is_atomic_file(inode) || IS_NOQUOTA(inode))) ||
			is_cold_data(page))
		return true;
	return false;
}

static enum count_type __read_io_type(struct page *page)
{
	struct address_space *mapping = page_file_mapping(page);

	if (mapping) {
		struct inode *inode = mapping->host;
		struct f2fs_sb_info *sbi = F2FS_I_SB(inode);

		if (inode->i_ino == F2FS_META_INO(sbi))
			return F2FS_RD_META;

		if (inode->i_ino == F2FS_NODE_INO(sbi))
			return F2FS_RD_NODE;
	}
	return F2FS_RD_DATA;
}

/* postprocessing steps for read bios */
enum bio_post_read_step {
	STEP_INITIAL = 0,
	STEP_DECRYPT,
};

struct bio_post_read_ctx {
	struct bio *bio;
	struct work_struct work;
	unsigned int cur_step;
	unsigned int enabled_steps;
};

static void __read_end_io(struct bio *bio, int err)
{
	struct bio_vec *bvec;
	int i;

	bio_for_each_segment_all(bvec, bio, i) {
		struct page *page = bvec->bv_page;

		if (!err) {
			SetPageUptodate(page);
		} else {
			ClearPageUptodate(page);
			SetPageError(page);
		}
		unlock_page(page);
	}
	bio_put(bio);
}

static void f2fs_write_end_io(struct bio *bio, int err)
{
	struct f2fs_sb_info *sbi = bio->bi_private;
	struct bio_vec *bvec;
	int i;

	bio_for_each_segment_all(bvec, bio, i) {
		struct page *page = bvec->bv_page;

		if (unlikely(err)) {
			set_page_dirty(page);
			set_bit(AS_EIO, &page->mapping->flags);
			f2fs_stop_checkpoint(sbi);
		}
		end_page_writeback(page);
		dec_page_count(sbi, F2FS_WRITEBACK);
	}

	if (sbi->wait_io) {
		complete(sbi->wait_io);
		sbi->wait_io = NULL;
	}

	if (!get_pages(sbi, F2FS_WRITEBACK) &&
			!list_empty(&sbi->cp_wait.task_list))
		wake_up(&sbi->cp_wait);

	bio_put(bio);
}

/*
 * Low-level block read/write IO operations.
 */
static struct bio *__bio_alloc(struct f2fs_sb_info *sbi, block_t blk_addr,
				int npages, bool is_read)
{
	struct bio *bio;

	/* No failure on bio allocation */
	bio = bio_alloc(GFP_NOIO, npages);

	bio->bi_bdev = sbi->sb->s_bdev;
	bio->bi_iter.bi_sector = SECTOR_FROM_BLOCK(blk_addr);
	bio->bi_end_io = is_read ? f2fs_read_end_io : f2fs_write_end_io;
	bio->bi_private = sbi;

	return bio;
}

static void __submit_merged_bio(struct f2fs_bio_info *io)
{
	struct f2fs_io_info *fio = &io->fio;
	int rw;

	if (!io->bio)
		return;

	rw = fio->rw;

	if (is_read_io(rw)) {
		trace_f2fs_submit_read_bio(io->sbi->sb, rw,
						fio->type, io->bio);
		submit_bio(rw, io->bio);
	} else {
		trace_f2fs_submit_write_bio(io->sbi->sb, rw,
						fio->type, io->bio);
		/*
		 * META_FLUSH is only from the checkpoint procedure, and we
		 * should wait this metadata bio for FS consistency.
		 */
		if (fio->type == META_FLUSH) {
			DECLARE_COMPLETION_ONSTACK(wait);
			io->sbi->wait_io = &wait;
			submit_bio(rw, io->bio);
			wait_for_completion(&wait);
		} else {
			submit_bio(rw, io->bio);
		}
	}

	io->bio = NULL;
}

void f2fs_submit_merged_bio(struct f2fs_sb_info *sbi,
				enum page_type type, int rw)
{
	enum page_type btype = PAGE_TYPE_OF_BIO(type);
	struct f2fs_bio_info *io;

	io = is_read_io(rw) ? &sbi->read_io : &sbi->write_io[btype];

	down_write(&io->io_rwsem);

	/* change META to META_FLUSH in the checkpoint procedure */
	if (type >= META_FLUSH) {
		io->fio.type = META_FLUSH;
		if (test_opt(sbi, NOBARRIER))
			io->fio.rw = WRITE_FLUSH | REQ_META | REQ_PRIO;
		else
			io->fio.rw = WRITE_FLUSH_FUA | REQ_META | REQ_PRIO;
	}
	__submit_merged_bio(io);
	up_write(&io->io_rwsem);
}

/*
 * Fill the locked page with data located in the block address.
 * Return unlocked page.
 */
int f2fs_submit_page_bio(struct f2fs_sb_info *sbi, struct page *page,
					block_t blk_addr, int rw)
{
	struct bio *bio;
	struct page *page = fio->encrypted_page ?
			fio->encrypted_page : fio->page;

	if (!f2fs_is_valid_blkaddr(fio->sbi, fio->new_blkaddr,
			fio->is_por ? META_POR : (__is_meta_io(fio) ?
			META_GENERIC : DATA_GENERIC_ENHANCE)))
		return -EFSCORRUPTED;

	trace_f2fs_submit_page_bio(page, blk_addr, rw);

	/* Allocate a new bio */
	bio = __bio_alloc(sbi, blk_addr, 1, is_read_io(rw));

	if (bio_add_page(bio, page, PAGE_CACHE_SIZE, 0) < PAGE_CACHE_SIZE) {
		bio_put(bio);
		f2fs_put_page(page, 1);
		return -EFAULT;
	}

	if (fio->io_wbc && !is_read_io(fio->op))
		wbc_account_io(fio->io_wbc, page, PAGE_SIZE);

	bio_set_op_attrs(bio, fio->op, fio->op_flags);

	inc_page_count(fio->sbi, is_read_io(fio->op) ?
			__read_io_type(page): WB_DATA_TYPE(fio->page));

	__submit_bio(fio->sbi, bio, fio->type);
	return 0;
}

int f2fs_merge_page_bio(struct f2fs_io_info *fio)
{
	struct bio *bio = *fio->bio;
	struct page *page = fio->encrypted_page ?
			fio->encrypted_page : fio->page;

	if (!f2fs_is_valid_blkaddr(fio->sbi, fio->new_blkaddr,
			__is_meta_io(fio) ? META_GENERIC : DATA_GENERIC))
		return -EFSCORRUPTED;

	trace_f2fs_submit_page_bio(page, fio);
	f2fs_trace_ios(fio, 0);

	if (bio && (*fio->last_block + 1 != fio->new_blkaddr ||
			!__same_bdev(fio->sbi, fio->new_blkaddr, bio))) {
		__submit_bio(fio->sbi, bio, fio->type);
		bio = NULL;
	}
alloc_new:
	if (!bio) {
		bio = __bio_alloc(fio->sbi, fio->new_blkaddr, fio->io_wbc,
				BIO_MAX_PAGES, false, fio->type, fio->temp);
		bio_set_op_attrs(bio, fio->op, fio->op_flags);
	}

	if (bio_add_page(bio, page, PAGE_SIZE, 0) < PAGE_SIZE) {
		__submit_bio(fio->sbi, bio, fio->type);
		bio = NULL;
		goto alloc_new;
	}

	if (fio->io_wbc)
		wbc_account_io(fio->io_wbc, page, PAGE_SIZE);

	inc_page_count(fio->sbi, WB_DATA_TYPE(page));

	*fio->last_block = fio->new_blkaddr;
	*fio->bio = bio;

	return 0;
}

void f2fs_submit_page_mbio(struct f2fs_sb_info *sbi, struct page *page,
			block_t blk_addr, struct f2fs_io_info *fio)
{
	enum page_type btype = PAGE_TYPE_OF_BIO(fio->type);
	struct f2fs_bio_info *io;
	bool is_read = is_read_io(fio->rw);

	io = is_read ? &sbi->read_io : &sbi->write_io[btype];

	verify_block_addr(sbi, blk_addr);

	down_write(&io->io_rwsem);

	if (!is_read)
		inc_page_count(sbi, F2FS_WRITEBACK);

	if (io->bio && (io->last_block_in_bio != blk_addr - 1 ||
						io->fio.rw != fio->rw))
		__submit_merged_bio(io);
alloc_new:
	if (io->bio == NULL) {
		int bio_blocks = MAX_BIO_BLOCKS(sbi);

		io->bio = __bio_alloc(sbi, blk_addr, bio_blocks, is_read);
		io->fio = *fio;
	}

	if (bio_add_page(io->bio, page, PAGE_CACHE_SIZE, 0) <
							PAGE_CACHE_SIZE) {
		__submit_merged_bio(io);
		goto alloc_new;
	}

	io->last_block_in_bio = blk_addr;

	up_write(&io->io_rwsem);
	trace_f2fs_submit_page_mbio(page, fio->rw, fio->type, blk_addr);
}

/*
 * Lock ordering for the change of data block address:
 * ->data_page
 *  ->node_page
 *    update block addresses in the node page
 */
static void __set_data_blkaddr(struct dnode_of_data *dn, block_t new_addr)
{
	struct f2fs_node *rn;
	__le32 *addr_array;
	struct page *node_page = dn->node_page;
	unsigned int ofs_in_node = dn->ofs_in_node;

	f2fs_wait_on_page_writeback(node_page, NODE);

	rn = F2FS_NODE(node_page);

	/* Get physical address of data block */
	addr_array = blkaddr_in_node(rn);
	addr_array[ofs_in_node] = cpu_to_le32(new_addr);
	set_page_dirty(node_page);
}

int reserve_new_block(struct dnode_of_data *dn)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(dn->inode);

	if (unlikely(is_inode_flag_set(F2FS_I(dn->inode), FI_NO_ALLOC)))
		return -EPERM;
	if (unlikely(!inc_valid_block_count(sbi, dn->inode, 1)))
		return -ENOSPC;

	trace_f2fs_reserve_new_block(dn->inode, dn->nid, dn->ofs_in_node);

	__set_data_blkaddr(dn, NEW_ADDR);
	dn->data_blkaddr = NEW_ADDR;
	mark_inode_dirty(dn->inode);
	sync_inode_page(dn);
	return 0;
}

int f2fs_reserve_block(struct dnode_of_data *dn, pgoff_t index)
{
	bool need_put = dn->inode_page ? false : true;
	int err;

	/* if inode_page exists, index should be zero */
	f2fs_bug_on(F2FS_I_SB(dn->inode), !need_put && index);

	err = get_dnode_of_data(dn, index, ALLOC_NODE);
	if (err)
		return err;

	if (dn->data_blkaddr == NULL_ADDR)
		err = reserve_new_block(dn);
	if (err || need_put)
		f2fs_put_dnode(dn);
	return err;
}

static int check_extent_cache(struct inode *inode, pgoff_t pgofs,
					struct buffer_head *bh_result)
{
	struct f2fs_inode_info *fi = F2FS_I(inode);
	pgoff_t start_fofs, end_fofs;
	block_t start_blkaddr;

	if (is_inode_flag_set(fi, FI_NO_EXTENT))
		return 0;

	read_lock(&fi->ext.ext_lock);
	if (fi->ext.len == 0) {
		read_unlock(&fi->ext.ext_lock);
		return 0;
	}

	stat_inc_total_hit(inode->i_sb);

	start_fofs = fi->ext.fofs;
	end_fofs = fi->ext.fofs + fi->ext.len - 1;
	start_blkaddr = fi->ext.blk_addr;

	if (pgofs >= start_fofs && pgofs <= end_fofs) {
		unsigned int blkbits = inode->i_sb->s_blocksize_bits;
		size_t count;

		clear_buffer_new(bh_result);
		map_bh(bh_result, inode->i_sb,
				start_blkaddr + pgofs - start_fofs);
		count = end_fofs - pgofs + 1;
		if (count < (UINT_MAX >> blkbits))
			bh_result->b_size = (count << blkbits);
		else
			bh_result->b_size = UINT_MAX;

		stat_inc_read_hit(inode->i_sb);
		read_unlock(&fi->ext.ext_lock);
		return 1;
	}
	read_unlock(&fi->ext.ext_lock);
	return 0;
}

void update_extent_cache(block_t blk_addr, struct dnode_of_data *dn)
{
	struct f2fs_inode_info *fi = F2FS_I(dn->inode);
	pgoff_t fofs, start_fofs, end_fofs;
	block_t start_blkaddr, end_blkaddr;
	int need_update = true;

	f2fs_bug_on(F2FS_I_SB(dn->inode), blk_addr == NEW_ADDR);
	fofs = start_bidx_of_node(ofs_of_node(dn->node_page), fi) +
							dn->ofs_in_node;

	if (f2fs_lookup_extent_cache(inode, index, &ei)) {
		dn.data_blkaddr = ei.blk + index - ei.fofs;
		if (!f2fs_is_valid_blkaddr(F2FS_I_SB(inode), dn.data_blkaddr,
						DATA_GENERIC_ENHANCE_READ)) {
			err = -EFSCORRUPTED;
			goto put_err;
		}
		goto end_update;
	}

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	err = f2fs_get_dnode_of_data(&dn, index, LOOKUP_NODE);
	if (err)
		goto put_err;
	f2fs_put_dnode(&dn);

	if (unlikely(dn.data_blkaddr == NULL_ADDR)) {
		err = -ENOENT;
		goto put_err;
	}
	if (dn.data_blkaddr != NEW_ADDR &&
			!f2fs_is_valid_blkaddr(F2FS_I_SB(inode),
						dn.data_blkaddr,
						DATA_GENERIC_ENHANCE)) {
		err = -EFSCORRUPTED;
		goto put_err;
	}
got_it:
	if (PageUptodate(page)) {
		unlock_page(page);
		return page;
	}

	/* Back merge */
	if (fofs == end_fofs + 1 && blk_addr == end_blkaddr + 1) {
		fi->ext.len++;
		goto end_update;
	}

	/* Split the existing extent */
	if (fi->ext.len > 1 &&
		fofs >= start_fofs && fofs <= end_fofs) {
		if ((end_fofs - fofs) < (fi->ext.len >> 1)) {
			fi->ext.len = fofs - start_fofs;
		} else {
			fi->ext.fofs = fofs + 1;
			fi->ext.blk_addr = start_blkaddr +
					fofs - start_fofs + 1;
			fi->ext.len -= fofs - start_fofs + 1;
		}
	} else {
		need_update = false;
	}

	/* Finally, if the extent is very fragmented, let's drop the cache. */
	if (fi->ext.len < F2FS_MIN_EXTENT_LEN) {
		fi->ext.len = 0;
		set_inode_flag(fi, FI_NO_EXTENT);
		need_update = true;
	}
end_update:
	write_unlock(&fi->ext.ext_lock);
	if (need_update)
		sync_inode_page(dn);
	return;
}

struct page *find_data_page(struct inode *inode, pgoff_t index, bool sync)
{
	struct address_space *mapping = inode->i_mapping;
	struct dnode_of_data dn;
	struct page *page;
	int err;

	page = find_get_page(mapping, index);
	if (page && PageUptodate(page))
		return page;
	f2fs_put_page(page, 0);

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	err = get_dnode_of_data(&dn, index, LOOKUP_NODE);
	if (err)
		return ERR_PTR(err);
	f2fs_put_dnode(&dn);

	if (dn.data_blkaddr == NULL_ADDR)
		return ERR_PTR(-ENOENT);

	/* By fallocate(), there is no cached page, but with NEW_ADDR */
	if (unlikely(dn.data_blkaddr == NEW_ADDR))
		return ERR_PTR(-EINVAL);

	page = grab_cache_page(mapping, index);
	if (!page)
		return ERR_PTR(-ENOMEM);

	if (PageUptodate(page)) {
		unlock_page(page);
		return page;
	}

	err = f2fs_submit_page_bio(F2FS_I_SB(inode), page, dn.data_blkaddr,
					sync ? READ_SYNC : READA);
	if (err)
		return ERR_PTR(err);

	if (sync) {
		wait_on_page_locked(page);
		if (unlikely(!PageUptodate(page))) {
			f2fs_put_page(page, 0);
			return ERR_PTR(-EIO);
		}
	}
	return page;
}

/*
 * If it tries to access a hole, return an error.
 * Because, the callers, functions in dir.c and GC, should be able to know
 * whether this page exists or not.
 */
struct page *get_lock_data_page(struct inode *inode, pgoff_t index)
{
	struct address_space *mapping = inode->i_mapping;
	struct dnode_of_data dn;
	struct page *page;
	int err;

repeat:
	page = grab_cache_page(mapping, index);
	if (!page)
		return ERR_PTR(-ENOMEM);

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	err = get_dnode_of_data(&dn, index, LOOKUP_NODE);
	if (err) {
		f2fs_put_page(page, 1);
		return ERR_PTR(err);
	}
	f2fs_put_dnode(&dn);

	if (unlikely(dn.data_blkaddr == NULL_ADDR)) {
		f2fs_put_page(page, 1);
		return ERR_PTR(-ENOENT);
	}

	if (PageUptodate(page))
		return page;

	/*
	 * A new dentry page is allocated but not able to be written, since its
	 * new inode page couldn't be allocated due to -ENOSPC.
	 * In such the case, its blkaddr can be remained as NEW_ADDR.
	 * see, f2fs_add_link -> get_new_data_page -> init_inode_metadata.
	 */
	if (dn.data_blkaddr == NEW_ADDR) {
		zero_user_segment(page, 0, PAGE_CACHE_SIZE);
		SetPageUptodate(page);
		return page;
	}

	err = f2fs_submit_page_bio(F2FS_I_SB(inode), page,
					dn.data_blkaddr, READ_SYNC);
	if (err)
		return ERR_PTR(err);

	lock_page(page);
	if (unlikely(!PageUptodate(page))) {
		f2fs_put_page(page, 1);
		return ERR_PTR(-EIO);
	}
	if (unlikely(page->mapping != mapping)) {
		f2fs_put_page(page, 1);
		goto repeat;
	}
	return page;
}

/*
 * Caller ensures that this data page is never allocated.
 * A new zero-filled data page is allocated in the page cache.
 *
 * Also, caller should grab and release a rwsem by calling f2fs_lock_op() and
 * f2fs_unlock_op().
 * Note that, ipage is set only by make_empty_dir.
 */
struct page *get_new_data_page(struct inode *inode,
		struct page *ipage, pgoff_t index, bool new_i_size)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page;
	struct dnode_of_data dn;
	int err;

	set_new_dnode(&dn, inode, ipage, NULL, 0);
	err = f2fs_reserve_block(&dn, index);
	if (err)
		return ERR_PTR(err);
repeat:
	page = grab_cache_page(mapping, index);
	if (!page) {
		err = -ENOMEM;
		goto put_err;
	}

	if (PageUptodate(page))
		return page;

	if (dn.data_blkaddr == NEW_ADDR) {
		zero_user_segment(page, 0, PAGE_CACHE_SIZE);
		SetPageUptodate(page);
	} else {
		err = f2fs_submit_page_bio(F2FS_I_SB(inode), page,
						dn.data_blkaddr, READ_SYNC);
		if (err)
			goto put_err;

		lock_page(page);
		if (unlikely(!PageUptodate(page))) {
			f2fs_put_page(page, 1);
			err = -EIO;
			goto put_err;
		}
		if (unlikely(page->mapping != mapping)) {
			f2fs_put_page(page, 1);
			goto repeat;
		}
	}

	if (new_i_size &&
		i_size_read(inode) < ((index + 1) << PAGE_CACHE_SHIFT)) {
		i_size_write(inode, ((index + 1) << PAGE_CACHE_SHIFT));
		/* Only the directory inode sets new_i_size */
		set_inode_flag(F2FS_I(inode), FI_UPDATE_DIR);
	}
	return page;

put_err:
	f2fs_put_dnode(&dn);
	return ERR_PTR(err);
}

static int __allocate_data_block(struct dnode_of_data *dn)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(dn->inode);
	struct f2fs_inode_info *fi = F2FS_I(dn->inode);
	struct f2fs_summary sum;
	block_t new_blkaddr;
	struct node_info ni;
	pgoff_t fofs;
	int type;

	if (unlikely(is_inode_flag_set(F2FS_I(dn->inode), FI_NO_ALLOC)))
		return -EPERM;
	if (unlikely(!inc_valid_block_count(sbi, dn->inode, 1)))
		return -ENOSPC;

	__set_data_blkaddr(dn, NEW_ADDR);
	dn->data_blkaddr = NEW_ADDR;

	get_node_info(sbi, dn->nid, &ni);
	set_summary(&sum, dn->nid, dn->ofs_in_node, ni.version);

	type = CURSEG_WARM_DATA;

	allocate_data_block(sbi, NULL, NULL_ADDR, &new_blkaddr, &sum, type);

	/* direct IO doesn't use extent cache to maximize the performance */
	set_inode_flag(F2FS_I(dn->inode), FI_NO_EXTENT);
	update_extent_cache(new_blkaddr, dn);
	clear_inode_flag(F2FS_I(dn->inode), FI_NO_EXTENT);

	/* update i_size */
	fofs = start_bidx_of_node(ofs_of_node(dn->node_page), fi) +
							dn->ofs_in_node;
	if (i_size_read(dn->inode) < ((fofs + 1) << PAGE_CACHE_SHIFT))
		i_size_write(dn->inode, ((fofs + 1) << PAGE_CACHE_SHIFT));

	dn->data_blkaddr = new_blkaddr;
	return 0;
}

/*
 * get_data_block() now supported readahead/bmap/rw direct_IO with mapped bh.
 * If original data blocks are allocated, then give them to blockdev.
 * Otherwise,
 *     a. preallocate requested block addresses
 *     b. do not use extent cache for better performance
 *     c. give the block addresses to blockdev
 */
static int __get_data_block(struct inode *inode, sector_t iblock,
			struct buffer_head *bh_result, int create, bool fiemap)
{
	unsigned int blkbits = inode->i_sb->s_blocksize_bits;
	unsigned maxblocks = bh_result->b_size >> blkbits;
	struct dnode_of_data dn;
	int mode = create ? ALLOC_NODE : LOOKUP_NODE_RA;
	pgoff_t pgofs, end_offset;
	int err = 0, ofs = 1;
	bool allocated = false;

	/* Get the page offset from the block offset(iblock) */
	pgofs =	(pgoff_t)(iblock >> (PAGE_CACHE_SHIFT - blkbits));

	if (check_extent_cache(inode, pgofs, bh_result))
		goto out;

	if (create) {
		f2fs_balance_fs(F2FS_I_SB(inode));
		f2fs_lock_op(F2FS_I_SB(inode));
	}

	/* When reading holes, we need its node page */
	set_new_dnode(&dn, inode, NULL, NULL, 0);
	err = get_dnode_of_data(&dn, pgofs, mode);
	if (err) {
		if (err == -ENOENT)
			err = 0;
		goto unlock_out;
	}
	if (dn.data_blkaddr == NEW_ADDR && !fiemap)
		goto put_out;

	start_pgofs = pgofs;
	prealloc = 0;
	last_ofs_in_node = ofs_in_node = dn.ofs_in_node;
	end_offset = ADDRS_PER_PAGE(dn.node_page, inode);

next_block:
	blkaddr = datablock_addr(dn.inode, dn.node_page, dn.ofs_in_node);

	if (__is_valid_data_blkaddr(blkaddr) &&
		!f2fs_is_valid_blkaddr(sbi, blkaddr, DATA_GENERIC_ENHANCE)) {
		err = -EFSCORRUPTED;
		goto sync_out;
	}

	if (!__is_valid_data_blkaddr(blkaddr)) {
		if (create) {
			if (unlikely(f2fs_cp_error(sbi))) {
				err = -EIO;
				goto sync_out;
			}
			if (flag == F2FS_GET_BLOCK_PRE_AIO) {
				if (blkaddr == NULL_ADDR) {
					prealloc++;
					last_ofs_in_node = dn.ofs_in_node;
				}
			} else {
				WARN_ON(flag != F2FS_GET_BLOCK_PRE_DIO &&
					flag != F2FS_GET_BLOCK_DIO);
				err = __allocate_data_block(&dn,
							map->m_seg_type);
				if (!err)
					set_inode_flag(inode, FI_APPEND_WRITE);
			}
			if (err)
				goto sync_out;
			map->m_flags |= F2FS_MAP_NEW;
			blkaddr = dn.data_blkaddr;
		} else {
			if (flag == F2FS_GET_BLOCK_BMAP) {
				map->m_pblk = 0;
				goto sync_out;
			}
			if (flag == F2FS_GET_BLOCK_PRECACHE)
				goto sync_out;
			if (flag == F2FS_GET_BLOCK_FIEMAP &&
						blkaddr == NULL_ADDR) {
				if (map->m_next_pgofs)
					*map->m_next_pgofs = pgofs + 1;
				goto sync_out;
			}
			if (flag != F2FS_GET_BLOCK_FIEMAP) {
				/* for defragment case */
				if (map->m_next_pgofs)
					*map->m_next_pgofs = pgofs + 1;
				goto sync_out;
			}
		}
	}

	if (flag == F2FS_GET_BLOCK_PRE_AIO)
		goto skip;

	if (map->m_len == 0) {
		/* preallocated unwritten block should be mapped for fiemap. */
		if (blkaddr == NEW_ADDR)
			map->m_flags |= F2FS_MAP_UNWRITTEN;
		map->m_flags |= F2FS_MAP_MAPPED;

		map->m_pblk = blkaddr;
		map->m_len = 1;
	} else if ((map->m_pblk != NEW_ADDR &&
			blkaddr == (map->m_pblk + ofs)) ||
			(map->m_pblk == NEW_ADDR && blkaddr == NEW_ADDR) ||
			flag == F2FS_GET_BLOCK_PRE_DIO) {
		ofs++;
		map->m_len++;
	} else {
		goto put_out;
	}

	end_offset = ADDRS_PER_PAGE(dn.node_page, F2FS_I(inode));
	bh_result->b_size = (((size_t)1) << blkbits);
	dn.ofs_in_node++;
	pgofs++;

get_next:
	if (dn.ofs_in_node >= end_offset) {
		if (allocated)
			sync_inode_page(&dn);
		allocated = false;
		f2fs_put_dnode(&dn);

		set_new_dnode(&dn, inode, NULL, NULL, 0);
		err = get_dnode_of_data(&dn, pgofs, mode);
		if (err) {
			if (err == -ENOENT)
				err = 0;
			goto unlock_out;
		}
		if (dn.data_blkaddr == NEW_ADDR && !fiemap)
			goto put_out;

		end_offset = ADDRS_PER_PAGE(dn.node_page, F2FS_I(inode));
	}

	if (maxblocks > (bh_result->b_size >> blkbits)) {
		block_t blkaddr = datablock_addr(dn.node_page, dn.ofs_in_node);
		if (blkaddr == NULL_ADDR && create) {
			err = __allocate_data_block(&dn);
			if (err)
				goto sync_out;
			allocated = true;
			blkaddr = dn.data_blkaddr;
		}
		/* Give more consecutive addresses for the readahead */
		if (blkaddr == (bh_result->b_blocknr + ofs)) {
			ofs++;
			dn.ofs_in_node++;
			pgofs++;
			bh_result->b_size += (((size_t)1) << blkbits);
			goto get_next;
		}
	}
sync_out:
	if (allocated)
		sync_inode_page(&dn);
put_out:
	f2fs_put_dnode(&dn);
unlock_out:
	if (create)
		f2fs_unlock_op(F2FS_I_SB(inode));
out:
	trace_f2fs_get_data_block(inode, iblock, bh_result, err);
	return err;
}

static int get_data_block(struct inode *inode, sector_t iblock,
			struct buffer_head *bh_result, int create)
{
	return __get_data_block(inode, iblock, bh_result, create, false);
}

static int get_data_block_fiemap(struct inode *inode, sector_t iblock,
			struct buffer_head *bh_result, int create)
{
	return __get_data_block(inode, iblock, bh_result, create, true);
}

int f2fs_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
		u64 start, u64 len)
{
	struct buffer_head map_bh;
	sector_t start_blk, last_blk;
	pgoff_t next_pgofs;
	u64 logical = 0, phys = 0, size = 0;
	u32 flags = 0;
	int ret = 0;

	if (fieinfo->fi_flags & FIEMAP_FLAG_CACHE) {
		ret = f2fs_precache_extents(inode);
		if (ret)
			return ret;
	}

	ret = fiemap_check_flags(fieinfo, FIEMAP_FLAG_SYNC | FIEMAP_FLAG_XATTR);
	if (ret)
		return ret;

	inode_lock(inode);

	if (fieinfo->fi_flags & FIEMAP_FLAG_XATTR) {
		ret = f2fs_xattr_fiemap(inode, fieinfo);
		goto out;
	}

	if (f2fs_has_inline_data(inode)) {
		ret = f2fs_inline_data_fiemap(inode, fieinfo, start, len);
		if (ret != -EAGAIN)
			goto out;
	}

	if (logical_to_blk(inode, len) == 0)
		len = blk_to_logical(inode, 1);

	start_blk = logical_to_blk(inode, start);
	last_blk = logical_to_blk(inode, start + len - 1);

next:
	memset(&map_bh, 0, sizeof(struct buffer_head));
	map_bh.b_size = len;

	ret = get_data_block(inode, start_blk, &map_bh, 0,
					F2FS_GET_BLOCK_FIEMAP, &next_pgofs);
	if (ret)
		goto out;

	/* HOLE */
	if (!buffer_mapped(&map_bh)) {
		start_blk = next_pgofs;

		if (blk_to_logical(inode, start_blk) < blk_to_logical(inode,
					F2FS_I_SB(inode)->max_file_blocks))
			goto prep_next;

		flags |= FIEMAP_EXTENT_LAST;
	}

	if (size) {
		if (f2fs_encrypted_inode(inode))
			flags |= FIEMAP_EXTENT_DATA_ENCRYPTED;

		ret = fiemap_fill_next_extent(fieinfo, logical,
				phys, size, flags);
	}

	if (start_blk > last_blk || ret)
		goto out;

	logical = blk_to_logical(inode, start_blk);
	phys = blk_to_logical(inode, map_bh.b_blocknr);
	size = map_bh.b_size;
	flags = 0;
	if (buffer_unwritten(&map_bh))
		flags = FIEMAP_EXTENT_UNWRITTEN;

	start_blk += logical_to_blk(inode, size);

prep_next:
	cond_resched();
	if (fatal_signal_pending(current))
		ret = -EINTR;
	else
		goto next;
out:
	if (ret == 1)
		ret = 0;

	inode_unlock(inode);
	return ret;
}

static int f2fs_read_single_page(struct inode *inode, struct page *page,
					unsigned nr_pages,
					struct f2fs_map_blocks *map,
					struct bio **bio_ret,
					sector_t *last_block_in_bio,
					bool is_readahead)
{
	struct bio *bio = *bio_ret;
	const unsigned blkbits = inode->i_blkbits;
	const unsigned blocksize = 1 << blkbits;
	sector_t block_in_file;
	sector_t last_block;
	sector_t last_block_in_file;
	sector_t block_nr;
	int ret = 0;

	block_in_file = (sector_t)page_index(page);
	last_block = block_in_file + nr_pages;
	last_block_in_file = (i_size_read(inode) + blocksize - 1) >>
							blkbits;
	if (last_block > last_block_in_file)
		last_block = last_block_in_file;

	/* just zeroing out page which is beyond EOF */
	if (block_in_file >= last_block)
		goto zero_out;
	/*
	 * Map blocks using the previous result first.
	 */
	if ((map->m_flags & F2FS_MAP_MAPPED) &&
			block_in_file > map->m_lblk &&
			block_in_file < (map->m_lblk + map->m_len))
		goto got_it;

	/*
	 * Then do more f2fs_map_blocks() calls until we are
	 * done with this page.
	 */
	map->m_lblk = block_in_file;
	map->m_len = last_block - block_in_file;

	ret = f2fs_map_blocks(inode, map, 0, F2FS_GET_BLOCK_DEFAULT);
	if (ret)
		goto out;
got_it:
	if ((map->m_flags & F2FS_MAP_MAPPED)) {
		block_nr = map->m_pblk + block_in_file - map->m_lblk;
		SetPageMappedToDisk(page);

		if (!PageUptodate(page) && (!PageSwapCache(page) &&
					!cleancache_get_page(page))) {
			SetPageUptodate(page);
			goto confused;
		}

		if (!f2fs_is_valid_blkaddr(F2FS_I_SB(inode), block_nr,
						DATA_GENERIC_ENHANCE_READ)) {
			ret = -EFSCORRUPTED;
			goto out;
		}
	} else {
zero_out:
		zero_user_segment(page, 0, PAGE_SIZE);
		if (!PageUptodate(page))
			SetPageUptodate(page);
		unlock_page(page);
		goto out;
	}

	/*
	 * This page will go to BIO.  Do we need to send this
	 * BIO off first?
	 */
	if (bio && (*last_block_in_bio != block_nr - 1 ||
		!__same_bdev(F2FS_I_SB(inode), block_nr, bio))) {
submit_and_realloc:
		__submit_bio(F2FS_I_SB(inode), bio, DATA);
		bio = NULL;
	}
	if (bio == NULL) {
		bio = f2fs_grab_read_bio(inode, block_nr, nr_pages,
				is_readahead ? REQ_RAHEAD : 0);
		if (IS_ERR(bio)) {
			ret = PTR_ERR(bio);
			bio = NULL;
			goto out;
		}
	}

	/*
	 * If the page is under writeback, we need to wait for
	 * its completion to see the correct decrypted data.
	 */
	f2fs_wait_on_block_writeback(inode, block_nr);

	if (bio_add_page(bio, page, blocksize, 0) < blocksize)
		goto submit_and_realloc;

	inc_page_count(F2FS_I_SB(inode), F2FS_RD_DATA);
	ClearPageError(page);
	*last_block_in_bio = block_nr;
	goto out;
confused:
	if (bio) {
		__submit_bio(F2FS_I_SB(inode), bio, DATA);
		bio = NULL;
	}
	unlock_page(page);
out:
	*bio_ret = bio;
	return ret;
}

/*
 * This function was originally taken from fs/mpage.c, and customized for f2fs.
 * Major change was from block_size == page_size in f2fs by default.
 *
 * Note that the aops->readpages() function is ONLY used for read-ahead. If
 * this function ever deviates from doing just read-ahead, it should either
 * use ->readpage() or do the necessary surgery to decouple ->readpages()
 * from read-ahead.
 */
static int f2fs_mpage_readpages(struct address_space *mapping,
			struct list_head *pages, struct page *page,
			unsigned nr_pages, bool is_readahead)
{
	struct bio *bio = NULL;
	sector_t last_block_in_bio = 0;
	struct inode *inode = mapping->host;
	struct f2fs_map_blocks map;
	int ret = 0;

	map.m_pblk = 0;
	map.m_lblk = 0;
	map.m_len = 0;
	map.m_flags = 0;
	map.m_next_pgofs = NULL;
	map.m_next_extent = NULL;
	map.m_seg_type = NO_CHECK_TYPE;

	for (; nr_pages; nr_pages--) {
		if (pages) {
			page = list_last_entry(pages, struct page, lru);

			prefetchw(&page->flags);
			list_del(&page->lru);
			if (add_to_page_cache_lru(page, mapping,
						  page_index(page), GFP_KERNEL))
				goto next_page;
		}

		ret = f2fs_read_single_page(inode, page, nr_pages, &map, &bio,
					&last_block_in_bio, is_readahead);
		if (ret) {
			SetPageError(page);
			zero_user_segment(page, 0, PAGE_SIZE);
			unlock_page(page);
		}
next_page:
		if (pages)
			put_page(page);
	}
	BUG_ON(pages && !list_empty(pages));
	if (bio)
		__submit_bio(F2FS_I_SB(inode), bio, DATA);
	return pages ? 0 : ret;
}

static int f2fs_read_data_page(struct file *file, struct page *page)
{
	struct inode *inode = page_file_mapping(page)->host;
	int ret = -EAGAIN;

	trace_f2fs_readpage(page, DATA);

	/* If the file has inline data, try to read it directly */
	if (f2fs_has_inline_data(inode))
		ret = f2fs_read_inline_data(inode, page);
	if (ret == -EAGAIN)
		ret = f2fs_mpage_readpages(page_file_mapping(page),
						NULL, page, 1, false);
	return ret;
}

static int f2fs_read_data_pages(struct file *file,
			struct address_space *mapping,
			struct list_head *pages, unsigned nr_pages)
{
	struct inode *inode = file->f_mapping->host;

	/* If the file has inline data, skip readpages */
	if (f2fs_has_inline_data(inode))
		return 0;

	return mpage_readpages(mapping, pages, nr_pages, get_data_block);
}

int do_write_data_page(struct page *page, struct f2fs_io_info *fio)
{
	struct inode *inode = page->mapping->host;
	block_t old_blkaddr, new_blkaddr;
	struct dnode_of_data dn;
	int err = 0;

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	if (need_inplace_update(fio) &&
			f2fs_lookup_extent_cache(inode, page->index, &ei)) {
		fio->old_blkaddr = ei.blk + page->index - ei.fofs;

		if (!f2fs_is_valid_blkaddr(fio->sbi, fio->old_blkaddr,
						DATA_GENERIC_ENHANCE))
			return -EFSCORRUPTED;

		ipu_force = true;
		fio->need_lock = LOCK_DONE;
		goto got_it;
	}

	/* Deadlock due to between page->lock and f2fs_lock_op */
	if (fio->need_lock == LOCK_REQ && !f2fs_trylock_op(fio->sbi))
		return -EAGAIN;

	err = f2fs_get_dnode_of_data(&dn, page->index, LOOKUP_NODE);
	if (err)
		return err;

	old_blkaddr = dn.data_blkaddr;

	/* This page is already truncated */
	if (old_blkaddr == NULL_ADDR)
		goto out_writepage;
	}
got_it:
	if (__is_valid_data_blkaddr(fio->old_blkaddr) &&
		!f2fs_is_valid_blkaddr(fio->sbi, fio->old_blkaddr,
						DATA_GENERIC_ENHANCE)) {
		err = -EFSCORRUPTED;
		goto out_writepage;
	}
	/*
	 * If current allocation needs SSR,
	 * it had better in-place writes for updated data.
	 */
	if (unlikely(old_blkaddr != NEW_ADDR &&
			!is_cold_data(page) &&
			need_inplace_update(inode))) {
		rewrite_data_page(page, old_blkaddr, fio);
		set_inode_flag(F2FS_I(inode), FI_UPDATE_WRITE);
	} else {
		write_data_page(page, &dn, &new_blkaddr, fio);
		update_extent_cache(new_blkaddr, &dn);
		set_inode_flag(F2FS_I(inode), FI_APPEND_WRITE);
	}
out_writepage:
	f2fs_put_dnode(&dn);
	return err;
}

static int f2fs_write_data_page(struct page *page,
					struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	loff_t i_size = i_size_read(inode);
	const pgoff_t end_index = ((unsigned long long) i_size)
							>> PAGE_CACHE_SHIFT;
	unsigned offset = 0;
	bool need_balance_fs = false;
	int err = 0;
	struct f2fs_io_info fio = {
		.type = DATA,
		.rw = (wbc->sync_mode == WB_SYNC_ALL) ? WRITE_SYNC : WRITE,
	};

	trace_f2fs_writepage(page, DATA);

	if (page->index < end_index)
		goto write;

	/*
	 * If the offset is out-of-range of file size,
	 * this page does not have to be written to disk.
	 */
	offset = i_size & (PAGE_CACHE_SIZE - 1);
	if ((page->index >= end_index + 1) || !offset)
		goto out;

	zero_user_segment(page, offset, PAGE_CACHE_SIZE);
write:
	if (unlikely(sbi->por_doing))
		goto redirty_out;

	/* Dentry blocks are controlled by checkpoint */
	if (S_ISDIR(inode->i_mode)) {
		if (unlikely(f2fs_cp_error(sbi)))
			goto redirty_out;
		err = do_write_data_page(page, &fio);
		goto done;
	}

	/* we should bypass data pages to proceed the kworkder jobs */
	if (unlikely(f2fs_cp_error(sbi))) {
		SetPageError(page);
		unlock_page(page);
		goto out;
	}

	if (!wbc->for_reclaim)
		need_balance_fs = true;
	else if (has_not_enough_free_secs(sbi, 0))
		goto redirty_out;

	f2fs_lock_op(sbi);
	if (f2fs_has_inline_data(inode) || f2fs_may_inline(inode))
		err = f2fs_write_inline_data(inode, page, offset);
	else
		err = do_write_data_page(page, &fio);
	f2fs_unlock_op(sbi);
done:
	if (err && err != -ENOENT)
		goto redirty_out;

	clear_cold_data(page);
out:
	inode_dec_dirty_pages(inode);
	unlock_page(page);
	if (need_balance_fs)
		f2fs_balance_fs(sbi);
	if (wbc->for_reclaim)
		f2fs_submit_merged_bio(sbi, DATA, WRITE);
	return 0;

redirty_out:
	redirty_page_for_writepage(wbc, page);
	return AOP_WRITEPAGE_ACTIVATE;
}

static int __f2fs_writepage(struct page *page, struct writeback_control *wbc,
			void *data)
{
	struct address_space *mapping = data;
	int ret = mapping->a_ops->writepage(page, wbc);
	mapping_set_error(mapping, ret);
	return ret;
}

static int f2fs_write_data_pages(struct address_space *mapping,
			    struct writeback_control *wbc)
{
	struct inode *inode = mapping->host;
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	bool locked = false;
	int ret;
	long diff;

	trace_f2fs_writepages(mapping->host, wbc, DATA);

	/* deal with chardevs and other special file */
	if (!mapping->a_ops->writepage)
		return 0;

	if (S_ISDIR(inode->i_mode) && wbc->sync_mode == WB_SYNC_NONE &&
			get_dirty_pages(inode) < nr_pages_to_skip(sbi, DATA) &&
			available_free_memory(sbi, DIRTY_DENTS))
		goto skip_write;

	diff = nr_pages_to_write(sbi, DATA, wbc);

	if (!S_ISDIR(inode->i_mode)) {
		mutex_lock(&sbi->writepages);
		locked = true;
	}
	ret = write_cache_pages(mapping, wbc, __f2fs_writepage, mapping);
	if (locked)
		mutex_unlock(&sbi->writepages);

	f2fs_submit_merged_bio(sbi, DATA, WRITE);

	remove_dirty_dir_inode(inode);

	wbc->nr_to_write = max((long)0, wbc->nr_to_write - diff);
	return ret;

skip_write:
	wbc->pages_skipped += get_dirty_pages(inode);
	return 0;
}

static void f2fs_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;

	if (to > inode->i_size) {
		truncate_pagecache(inode, inode->i_size);
		truncate_blocks(inode, inode->i_size, true);
	}
}

static int f2fs_write_begin(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, unsigned flags,
		struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct page *page;
	pgoff_t index = ((unsigned long long) pos) >> PAGE_CACHE_SHIFT;
	struct dnode_of_data dn;
	int err = 0;

	trace_f2fs_write_begin(inode, pos, len, flags);

	f2fs_balance_fs(sbi);
repeat:
	err = f2fs_convert_inline_data(inode, pos + len, NULL);
	if (err)
		goto fail;

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page) {
		err = -ENOMEM;
		goto fail;
	}

	/* to avoid latency during memory pressure */
	unlock_page(page);

	*pagep = page;

	if (f2fs_has_inline_data(inode) && (pos + len) <= MAX_INLINE_DATA)
		goto inline_data;

	f2fs_lock_op(sbi);
	set_new_dnode(&dn, inode, NULL, NULL, 0);
	err = f2fs_reserve_block(&dn, index);
	f2fs_unlock_op(sbi);
	if (err) {
		f2fs_put_page(page, 0);
		goto fail;
	}
inline_data:
	lock_page(page);
	if (unlikely(page->mapping != mapping)) {
		f2fs_put_page(page, 1);
		goto repeat;
	}

	f2fs_wait_on_page_writeback(page, DATA);

	if ((len == PAGE_CACHE_SIZE) || PageUptodate(page))
		return 0;

	if ((pos & PAGE_CACHE_MASK) >= i_size_read(inode)) {
		unsigned start = pos & (PAGE_CACHE_SIZE - 1);
		unsigned end = start + len;

		/* Reading beyond i_size is simple: memset to zero */
		zero_user_segments(page, 0, start, end, PAGE_CACHE_SIZE);
		goto out;
	}

	if (blkaddr == NEW_ADDR) {
		zero_user_segment(page, 0, PAGE_SIZE);
		SetPageUptodate(page);
	} else {
		if (!f2fs_is_valid_blkaddr(sbi, blkaddr,
				DATA_GENERIC_ENHANCE_READ)) {
			err = -EFSCORRUPTED;
			goto fail;
		}
	} else if (dn.data_blkaddr == NEW_ADDR) {
		zero_user_segment(page, 0, PAGE_CACHE_SIZE);
	} else {
		err = f2fs_submit_page_bio(sbi, page, dn.data_blkaddr,
					   READ_SYNC);
		if (err)
			goto fail;

		lock_page(page);
		if (unlikely(!PageUptodate(page))) {
			f2fs_put_page(page, 1);
			err = -EIO;
			goto fail;
		}
		if (unlikely(page->mapping != mapping)) {
			f2fs_put_page(page, 1);
			goto repeat;
		}
	}
out:
	SetPageUptodate(page);
	clear_cold_data(page);
	return 0;
fail:
	f2fs_write_failed(mapping, pos + len);
	return err;
}

static int f2fs_write_end(struct file *file,
			struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata)
{
	struct inode *inode = page->mapping->host;

	trace_f2fs_write_end(inode, pos, len, copied);

	if (f2fs_is_atomic_file(inode) || f2fs_is_volatile_file(inode))
		register_inmem_page(inode, page);
	else
		set_page_dirty(page);

	if (pos + copied > i_size_read(inode)) {
		i_size_write(inode, pos + copied);
		mark_inode_dirty(inode);
		update_inode_page(inode);
	}

	f2fs_put_page(page, 1);
	return copied;
}

static int check_direct_IO(struct inode *inode, int rw,
		struct iov_iter *iter, loff_t offset)
{
	unsigned blocksize_mask = inode->i_sb->s_blocksize - 1;

	if (rw == READ)
		return 0;

	if (offset & blocksize_mask)
		return -EINVAL;

	if (iov_iter_alignment(iter) & blocksize_mask)
		return -EINVAL;

	return 0;
}

static ssize_t f2fs_direct_IO(int rw, struct kiocb *iocb,
		struct iov_iter *iter, loff_t offset)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	size_t count = iov_iter_count(iter);
	int err;

	/* Let buffer I/O handle the inline data case. */
	if (f2fs_has_inline_data(inode))
		return 0;

	if (check_direct_IO(inode, rw, iter, offset))
		return 0;

	trace_f2fs_direct_IO_enter(inode, offset, count, rw);

	err = blockdev_direct_IO(rw, iocb, inode, iter, offset, get_data_block);
	if (err < 0 && (rw & WRITE))
		f2fs_write_failed(mapping, offset + count);

	trace_f2fs_direct_IO_exit(inode, offset, count, rw, err);

	return err;
}

static void f2fs_invalidate_data_page(struct page *page, unsigned int offset,
				      unsigned int length)
{
	struct inode *inode = page->mapping->host;

	if (offset % PAGE_CACHE_SIZE || length != PAGE_CACHE_SIZE)
		return;

	if (PageDirty(page))
		inode_dec_dirty_pages(inode);
	ClearPagePrivate(page);
}

static int f2fs_release_data_page(struct page *page, gfp_t wait)
{
	ClearPagePrivate(page);
	return 1;
}

static int f2fs_set_data_page_dirty(struct page *page)
{
	struct inode *inode = page_file_mapping(page)->host;

	trace_f2fs_set_page_dirty(page, DATA);

	if (!PageUptodate(page))
		SetPageUptodate(page);
	if (PageSwapCache(page))
		return __set_page_dirty_nobuffers(page);

	if (f2fs_is_atomic_file(inode) && !f2fs_is_commit_atomic_write(inode)) {
		if (!IS_ATOMIC_WRITTEN_PAGE(page)) {
			f2fs_register_inmem_page(inode, page);
			return 1;
		}
		/*
		 * Previously, this page has been registered, we just
		 * return here.
		 */
		return 0;
	}

	if (!PageDirty(page)) {
		__set_page_dirty_nobuffers(page);
		update_dirty_page(inode, page);
		return 1;
	}
	return 0;
}

static sector_t f2fs_bmap(struct address_space *mapping, sector_t block)
{
	struct inode *inode = mapping->host;

	if (f2fs_has_inline_data(inode))
		return 0;

	return generic_block_bmap(mapping, block, get_data_block);
}

#ifdef CONFIG_SWAP
/* Copied from generic_swapfile_activate() to check any holes */
static int check_swap_activate(struct file *swap_file, unsigned int max)
{
	struct address_space *mapping = swap_file->f_mapping;
	struct inode *inode = mapping->host;
	unsigned blocks_per_page;
	unsigned long page_no;
	unsigned blkbits;
	sector_t probe_block;
	sector_t last_block;
	sector_t lowest_block = -1;
	sector_t highest_block = 0;

	blkbits = inode->i_blkbits;
	blocks_per_page = PAGE_SIZE >> blkbits;

	/*
	 * Map all the blocks into the extent list.  This code doesn't try
	 * to be very smart.
	 */
	probe_block = 0;
	page_no = 0;
	last_block = i_size_read(inode) >> blkbits;
	while ((probe_block + blocks_per_page) <= last_block && page_no < max) {
		unsigned block_in_page;
		sector_t first_block;

		cond_resched();

		first_block = bmap(inode, probe_block);
		if (first_block == 0)
			goto bad_bmap;

		/*
		 * It must be PAGE_SIZE aligned on-disk
		 */
		if (first_block & (blocks_per_page - 1)) {
			probe_block++;
			goto reprobe;
		}

		for (block_in_page = 1; block_in_page < blocks_per_page;
					block_in_page++) {
			sector_t block;

			block = bmap(inode, probe_block + block_in_page);
			if (block == 0)
				goto bad_bmap;
			if (block != first_block + block_in_page) {
				/* Discontiguity */
				probe_block++;
				goto reprobe;
			}
		}

		first_block >>= (PAGE_SHIFT - blkbits);
		if (page_no) {	/* exclude the header page */
			if (first_block < lowest_block)
				lowest_block = first_block;
			if (first_block > highest_block)
				highest_block = first_block;
		}

		page_no++;
		probe_block += blocks_per_page;
reprobe:
		continue;
	}
	return 0;

bad_bmap:
	pr_err("swapon: swapfile has holes\n");
	return -EINVAL;
}

static int f2fs_swap_activate(struct swap_info_struct *sis, struct file *file,
				sector_t *span)
{
	struct inode *inode = file_inode(file);
	int ret;

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	if (f2fs_readonly(F2FS_I_SB(inode)->sb))
		return -EROFS;

	ret = f2fs_convert_inline_inode(inode);
	if (ret)
		return ret;

	ret = check_swap_activate(file, sis->max);
	if (ret)
		return ret;

	set_inode_flag(inode, FI_PIN_FILE);
	f2fs_precache_extents(inode);
	f2fs_update_time(F2FS_I_SB(inode), REQ_TIME);
	return 0;
}

static void f2fs_swap_deactivate(struct file *file)
{
	struct inode *inode = file_inode(file);

	clear_inode_flag(inode, FI_PIN_FILE);
}
#else
static int f2fs_swap_activate(struct swap_info_struct *sis, struct file *file,
				sector_t *span)
{
	return -EOPNOTSUPP;
}

static void f2fs_swap_deactivate(struct file *file)
{
}
#endif

const struct address_space_operations f2fs_dblock_aops = {
	.readpage	= f2fs_read_data_page,
	.readpages	= f2fs_read_data_pages,
	.writepage	= f2fs_write_data_page,
	.writepages	= f2fs_write_data_pages,
	.write_begin	= f2fs_write_begin,
	.write_end	= f2fs_write_end,
	.set_page_dirty	= f2fs_set_data_page_dirty,
	.invalidatepage	= f2fs_invalidate_data_page,
	.releasepage	= f2fs_release_data_page,
	.direct_IO	= f2fs_direct_IO,
	.bmap		= f2fs_bmap,
	.swap_activate  = f2fs_swap_activate,
	.swap_deactivate = f2fs_swap_deactivate,
#ifdef CONFIG_MIGRATION
	.migratepage    = f2fs_migrate_page,
#endif
};
