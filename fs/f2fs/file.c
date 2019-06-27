/*
 * fs/f2fs/file.c
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
#include <linux/stat.h>
#include <linux/buffer_head.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/falloc.h>
#include <linux/types.h>
#include <linux/compat.h>
#include <linux/uaccess.h>
#include <linux/mount.h>
#include <linux/pagevec.h>

#include "f2fs.h"
#include "node.h"
#include "segment.h"
#include "xattr.h"
#include "acl.h"
#include <trace/events/f2fs.h>

static int f2fs_vm_page_mkwrite(struct vm_area_struct *vma,
						struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	struct inode *inode = file_inode(vma->vm_file);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct dnode_of_data dn;
	int err;

	f2fs_balance_fs(sbi);

	sb_start_pagefault(inode->i_sb);

	/* force to convert with normal data indices */
	err = f2fs_convert_inline_data(inode, MAX_INLINE_DATA + 1, page);
	if (err)
		goto out;

	/* block allocation */
	f2fs_lock_op(sbi);
	set_new_dnode(&dn, inode, NULL, NULL, 0);
	err = f2fs_reserve_block(&dn, page->index);
	f2fs_unlock_op(sbi);
	if (err)
		goto out;

	file_update_time(vma->vm_file);
	lock_page(page);
	if (unlikely(page->mapping != inode->i_mapping ||
			page_offset(page) > i_size_read(inode) ||
			!PageUptodate(page))) {
		unlock_page(page);
		err = -EFAULT;
		goto out;
	}

	/*
	 * check to see if the page is mapped already (no holes)
	 */
	if (PageMappedToDisk(page))
		goto mapped;

	/* page is wholly or partially inside EOF */
	if (((page->index + 1) << PAGE_CACHE_SHIFT) > i_size_read(inode)) {
		unsigned offset;
		offset = i_size_read(inode) & ~PAGE_CACHE_MASK;
		zero_user_segment(page, offset, PAGE_CACHE_SIZE);
	}
	set_page_dirty(page);
	SetPageUptodate(page);

	trace_f2fs_vm_page_mkwrite(page, DATA);
mapped:
	/* fill the page */
	f2fs_wait_on_page_writeback(page, DATA);
out:
	sb_end_pagefault(inode->i_sb);
	return block_page_mkwrite_return(err);
}

static const struct vm_operations_struct f2fs_file_vm_ops = {
	.fault		= filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite	= f2fs_vm_page_mkwrite,
	.remap_pages	= generic_file_remap_pages,
};

static int get_parent_ino(struct inode *inode, nid_t *pino)
{
	struct dentry *dentry;

	inode = igrab(inode);
	dentry = d_find_any_alias(inode);
	iput(inode);
	if (!dentry)
		return 0;

	if (update_dent_inode(inode, &dentry->d_name)) {
		dput(dentry);
		return 0;
	}

	*pino = parent_ino(dentry);
	dput(dentry);
	return 1;
}

static inline bool need_do_checkpoint(struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	bool need_cp = false;

	if (!S_ISREG(inode->i_mode) || inode->i_nlink != 1)
		need_cp = true;
	else if (file_wrong_pino(inode))
		need_cp = true;
	else if (!space_for_roll_forward(sbi))
		need_cp = true;
	else if (!is_checkpointed_node(sbi, F2FS_I(inode)->i_pino))
		need_cp = true;
	else if (F2FS_I(inode)->xattr_ver == cur_cp_version(F2FS_CKPT(sbi)))
		need_cp = true;

	return need_cp;
}

int f2fs_sync_file(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file->f_mapping->host;
	struct f2fs_inode_info *fi = F2FS_I(inode);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	nid_t ino = inode->i_ino;
	int ret = 0;
	bool need_cp = false;
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_ALL,
		.nr_to_write = LONG_MAX,
		.for_reclaim = 0,
	};

	if (unlikely(f2fs_readonly(inode->i_sb)))
		return 0;

	trace_f2fs_sync_file_enter(inode);

	if (S_ISDIR(inode->i_mode))
		goto go_write;

	/* if fdatasync is triggered, let's do in-place-update */
	if (get_dirty_pages(inode) <= SM_I(sbi)->min_fsync_blocks)
		set_inode_flag(fi, FI_NEED_IPU);
	ret = filemap_write_and_wait_range(inode->i_mapping, start, end);
	clear_inode_flag(fi, FI_NEED_IPU);

	if (ret) {
		trace_f2fs_sync_file_exit(inode, need_cp, datasync, ret);
		return ret;
	}

	/*
	 * if there is no written data, don't waste time to write recovery info.
	 */
	if (!is_inode_flag_set(fi, FI_APPEND_WRITE) &&
			!exist_written_data(sbi, ino, APPEND_INO)) {
		struct page *i = find_get_page(NODE_MAPPING(sbi), ino);

		/* But we need to avoid that there are some inode updates */
		if ((i && PageDirty(i)) || need_inode_block_update(sbi, ino)) {
			f2fs_put_page(i, 0);
			goto go_write;
		}
		f2fs_put_page(i, 0);

		if (is_inode_flag_set(fi, FI_UPDATE_WRITE) ||
				exist_written_data(sbi, ino, UPDATE_INO))
			goto flush_out;
		goto out;
	}
go_write:
	/* guarantee free sections for fsync */
	f2fs_balance_fs(sbi);

	/*
	 * Both of fdatasync() and fsync() are able to be recovered from
	 * sudden-power-off.
	 */
	down_read(&fi->i_sem);
	need_cp = need_do_checkpoint(inode);
	up_read(&fi->i_sem);

	if (need_cp) {
		nid_t pino;

		/* all the dirty node pages should be flushed for POR */
		ret = f2fs_sync_fs(inode->i_sb, 1);

		down_write(&fi->i_sem);
		F2FS_I(inode)->xattr_ver = 0;
		if (file_wrong_pino(inode) && inode->i_nlink == 1 &&
					get_parent_ino(inode, &pino)) {
			F2FS_I(inode)->i_pino = pino;
			file_got_pino(inode);
			up_write(&fi->i_sem);
			mark_inode_dirty_sync(inode);
			ret = f2fs_write_inode(inode, NULL);
			if (ret)
				goto out;
		} else {
			up_write(&fi->i_sem);
		}
	} else {
sync_nodes:
		sync_node_pages(sbi, ino, &wbc);

		if (need_inode_block_update(sbi, ino)) {
			mark_inode_dirty_sync(inode);
			ret = f2fs_write_inode(inode, NULL);
			if (ret)
				goto out;
			goto sync_nodes;
		}

		ret = wait_on_node_pages_writeback(sbi, ino);
		if (ret)
			goto out;

		/* once recovery info is written, don't need to tack this */
		remove_dirty_inode(sbi, ino, APPEND_INO);
		clear_inode_flag(fi, FI_APPEND_WRITE);
flush_out:
		remove_dirty_inode(sbi, ino, UPDATE_INO);
		clear_inode_flag(fi, FI_UPDATE_WRITE);
		ret = f2fs_issue_flush(F2FS_I_SB(inode));
	}
out:
	trace_f2fs_sync_file_exit(inode, need_cp, datasync, ret);
	return ret;
}

static pgoff_t __get_first_dirty_index(struct address_space *mapping,
						pgoff_t pgofs, int whence)
{
	struct pagevec pvec;
	int nr_pages;

	if (whence != SEEK_DATA)
		return 0;

	/* find first dirty page index */
	pagevec_init(&pvec, 0);
	nr_pages = pagevec_lookup_tag(&pvec, mapping, &pgofs,
					PAGECACHE_TAG_DIRTY, 1);
	pgofs = nr_pages ? pvec.pages[0]->index : LONG_MAX;
	pagevec_release(&pvec);
	return pgofs;
}

static bool __found_offset(block_t blkaddr, pgoff_t dirty, pgoff_t pgofs,
							int whence)
{
	switch (whence) {
	case SEEK_DATA:
		if ((blkaddr == NEW_ADDR && dirty == pgofs) ||
			(blkaddr != NEW_ADDR && blkaddr != NULL_ADDR))
			return true;
		break;
	case SEEK_HOLE:
		if (blkaddr == NULL_ADDR)
			return true;
		break;
	}
	return false;
}

static loff_t f2fs_seek_block(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;
	loff_t maxbytes = inode->i_sb->s_maxbytes;
	struct dnode_of_data dn;
	pgoff_t pgofs, end_offset, dirty;
	loff_t data_ofs = offset;
	loff_t isize;
	int err = 0;

	mutex_lock(&inode->i_mutex);

	isize = i_size_read(inode);
	if (offset >= isize)
		goto fail;

	/* handle inline data case */
	if (f2fs_has_inline_data(inode)) {
		if (whence == SEEK_HOLE)
			data_ofs = isize;
		goto found;
	}

	pgofs = (pgoff_t)(offset >> PAGE_CACHE_SHIFT);

	dirty = __get_first_dirty_index(inode->i_mapping, pgofs, whence);

	for (; data_ofs < isize; data_ofs = pgofs << PAGE_CACHE_SHIFT) {
		set_new_dnode(&dn, inode, NULL, NULL, 0);
		err = get_dnode_of_data(&dn, pgofs, LOOKUP_NODE_RA);
		if (err && err != -ENOENT) {
			goto fail;
		} else if (err == -ENOENT) {
			/* direct node does not exists */
			if (whence == SEEK_DATA) {
				pgofs = PGOFS_OF_NEXT_DNODE(pgofs,
							F2FS_I(inode));
				continue;
			} else {
				goto found;
			}
		}

		end_offset = ADDRS_PER_PAGE(dn.node_page, F2FS_I(inode));

		/* find data/hole in dnode block */
		for (; dn.ofs_in_node < end_offset;
				dn.ofs_in_node++, pgofs++,
				data_ofs = pgofs << PAGE_CACHE_SHIFT) {
			block_t blkaddr;
			blkaddr = datablock_addr(dn.node_page, dn.ofs_in_node);

			if (__found_offset(blkaddr, dirty, pgofs, whence)) {
				f2fs_put_dnode(&dn);
				goto found;
			}
		}
		f2fs_put_dnode(&dn);
	}

	if (whence == SEEK_DATA)
		goto fail;
found:
	if (whence == SEEK_HOLE && data_ofs > isize)
		data_ofs = isize;
	mutex_unlock(&inode->i_mutex);
	return vfs_setpos(file, data_ofs, maxbytes);
fail:
	mutex_unlock(&inode->i_mutex);
	return -ENXIO;
}

static loff_t f2fs_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;
	loff_t maxbytes = inode->i_sb->s_maxbytes;

	switch (whence) {
	case SEEK_SET:
	case SEEK_CUR:
	case SEEK_END:
		return generic_file_llseek_size(file, offset, whence,
						maxbytes, i_size_read(inode));
	case SEEK_DATA:
	case SEEK_HOLE:
		if (offset < 0)
			return -ENXIO;
		return f2fs_seek_block(file, offset, whence);
	}

	return -EINVAL;
}

static int f2fs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	file_accessed(file);
	vma->vm_ops = &f2fs_file_vm_ops;
	return 0;
}

int truncate_data_blocks_range(struct dnode_of_data *dn, int count)
{
	int nr_free = 0, ofs = dn->ofs_in_node;
	struct f2fs_sb_info *sbi = F2FS_I_SB(dn->inode);
	struct f2fs_node *raw_node;
	__le32 *addr;

	raw_node = F2FS_NODE(dn->node_page);
	addr = blkaddr_in_node(raw_node) + ofs;

	for (; count > 0; count--, addr++, dn->ofs_in_node++) {
		block_t blkaddr = le32_to_cpu(*addr);
		if (blkaddr == NULL_ADDR)
			continue;

		update_extent_cache(NULL_ADDR, dn);
		invalidate_blocks(sbi, blkaddr);
		nr_free++;
	}
	if (nr_free) {
		dec_valid_block_count(sbi, dn->inode, nr_free);
		set_page_dirty(dn->node_page);
		sync_inode_page(dn);
	}
	dn->ofs_in_node = ofs;

	trace_f2fs_truncate_data_blocks_range(dn->inode, dn->nid,
					 dn->ofs_in_node, nr_free);
	return nr_free;
}

void truncate_data_blocks(struct dnode_of_data *dn)
{
	truncate_data_blocks_range(dn, ADDRS_PER_BLOCK);
}

static void truncate_partial_data_page(struct inode *inode, u64 from)
{
	unsigned offset = from & (PAGE_CACHE_SIZE - 1);
	struct page *page;

	if (f2fs_has_inline_data(inode))
		return truncate_inline_data(inode, from);

	if (!offset)
		return;

	page = find_data_page(inode, from >> PAGE_CACHE_SHIFT, false);
	if (IS_ERR(page))
		return;

	lock_page(page);
	if (unlikely(!PageUptodate(page) ||
			page->mapping != inode->i_mapping))
		goto out;

	f2fs_wait_on_page_writeback(page, DATA);
	zero_user(page, offset, PAGE_CACHE_SIZE - offset);
	set_page_dirty(page);

out:
	f2fs_put_page(page, 1);
}

int truncate_blocks(struct inode *inode, u64 from, bool lock)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	unsigned int blocksize = inode->i_sb->s_blocksize;
	struct dnode_of_data dn;
	pgoff_t free_from;
	int count = 0, err = 0;

	trace_f2fs_truncate_blocks_enter(inode, from);

	if (f2fs_has_inline_data(inode))
		goto done;

	free_from = (pgoff_t)
			((from + blocksize - 1) >> (sbi->log_blocksize));

	if (lock)
		f2fs_lock_op(sbi);

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	err = get_dnode_of_data(&dn, free_from, LOOKUP_NODE);
	if (err) {
		if (err == -ENOENT)
			goto free_next;
		if (lock)
			f2fs_unlock_op(sbi);
		trace_f2fs_truncate_blocks_exit(inode, err);
		return err;
	}

	count = ADDRS_PER_PAGE(dn.node_page, F2FS_I(inode));

	count -= dn.ofs_in_node;
	f2fs_bug_on(sbi, count < 0);

	if (dn.ofs_in_node || IS_INODE(dn.node_page)) {
		truncate_data_blocks_range(&dn, count);
		free_from += count;
	}

	f2fs_put_dnode(&dn);
free_next:
	err = truncate_inode_blocks(inode, free_from);
	if (lock)
		f2fs_unlock_op(sbi);
done:
	/* lastly zero out the first data page */
	truncate_partial_data_page(inode, from);

	trace_f2fs_truncate_blocks_exit(inode, err);
	return err;
}

void f2fs_truncate(struct inode *inode)
{
	if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
				S_ISLNK(inode->i_mode)))
		return;

	trace_f2fs_truncate(inode);

	if (!truncate_blocks(inode, i_size_read(inode), true)) {
		inode->i_mtime = inode->i_ctime = CURRENT_TIME;
		mark_inode_dirty(inode);
	}
}

int f2fs_getattr(struct vfsmount *mnt,
			 struct dentry *dentry, struct kstat *stat)
{
	struct inode *inode = d_inode(dentry);
#if 0
	struct f2fs_inode_info *fi = F2FS_I(inode);
	struct f2fs_inode *ri;
	unsigned int flags;

	if (f2fs_has_extra_attr(inode) &&
			f2fs_sb_has_inode_crtime(F2FS_I_SB(inode)) &&
			F2FS_FITS_IN_INODE(ri, fi->i_extra_isize, i_crtime)) {
		stat->result_mask |= STATX_BTIME;
		stat->btime.tv_sec = fi->i_crtime.tv_sec;
		stat->btime.tv_nsec = fi->i_crtime.tv_nsec;
	}

	flags = fi->i_flags;
	if (flags & F2FS_APPEND_FL)
		stat->attributes |= STATX_ATTR_APPEND;
	if (flags & F2FS_COMPR_FL)
		stat->attributes |= STATX_ATTR_COMPRESSED;
	if (IS_ENCRYPTED(inode))
		stat->attributes |= STATX_ATTR_ENCRYPTED;
	if (flags & F2FS_IMMUTABLE_FL)
		stat->attributes |= STATX_ATTR_IMMUTABLE;
	if (flags & F2FS_NODUMP_FL)
		stat->attributes |= STATX_ATTR_NODUMP;

	stat->attributes_mask |= (STATX_ATTR_APPEND |
				  STATX_ATTR_ENCRYPTED |
				  STATX_ATTR_IMMUTABLE |
				  STATX_ATTR_NODUMP);
#endif
	generic_fillattr(inode, stat);
	stat->blocks <<= 3;
	return 0;
}

#ifdef CONFIG_F2FS_FS_POSIX_ACL
static void __setattr_copy(struct inode *inode, const struct iattr *attr)
{
	struct f2fs_inode_info *fi = F2FS_I(inode);
	unsigned int ia_valid = attr->ia_valid;

	if (ia_valid & ATTR_UID)
		inode->i_uid = attr->ia_uid;
	if (ia_valid & ATTR_GID)
		inode->i_gid = attr->ia_gid;
	if (ia_valid & ATTR_ATIME)
		inode->i_atime = timespec_trunc(attr->ia_atime,
						inode->i_sb->s_time_gran);
	if (ia_valid & ATTR_MTIME)
		inode->i_mtime = timespec_trunc(attr->ia_mtime,
						inode->i_sb->s_time_gran);
	if (ia_valid & ATTR_CTIME)
		inode->i_ctime = timespec_trunc(attr->ia_ctime,
						inode->i_sb->s_time_gran);
	if (ia_valid & ATTR_MODE) {
		umode_t mode = attr->ia_mode;

		if (!in_group_p(inode->i_gid) && !capable(CAP_FSETID))
			mode &= ~S_ISGID;
		set_acl_inode(fi, mode);
	}
}
#else
#define __setattr_copy setattr_copy
#endif

int f2fs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	struct f2fs_inode_info *fi = F2FS_I(inode);
	int err;

	err = inode_change_ok(inode, attr);
	if (err)
		return err;

	if (attr->ia_valid & ATTR_SIZE) {
		err = f2fs_convert_inline_data(inode, attr->ia_size, NULL);
		if (err)
			return err;

		if (attr->ia_size != i_size_read(inode)) {
			truncate_setsize(inode, attr->ia_size);
			f2fs_truncate(inode);
			f2fs_balance_fs(F2FS_I_SB(inode));
		} else {
			/*
			 * giving a chance to truncate blocks past EOF which
			 * are fallocated with FALLOC_FL_KEEP_SIZE.
			 */
			f2fs_truncate(inode);
		}
	}

	__setattr_copy(inode, attr);

	if (attr->ia_valid & ATTR_MODE) {
		err = posix_acl_chmod(inode, get_inode_mode(inode));
		if (err || is_inode_flag_set(fi, FI_ACL_MODE)) {
			inode->i_mode = fi->i_acl_mode;
			clear_inode_flag(fi, FI_ACL_MODE);
		}
	}

	mark_inode_dirty(inode);
	return err;
}

const struct inode_operations f2fs_file_inode_operations = {
	.getattr	= f2fs_getattr,
	.setattr	= f2fs_setattr,
	.get_acl	= f2fs_get_acl,
	.set_acl	= f2fs_set_acl,
#ifdef CONFIG_F2FS_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= f2fs_listxattr,
	.removexattr	= generic_removexattr,
#endif
	.fiemap		= f2fs_fiemap,
};

static void fill_zero(struct inode *inode, pgoff_t index,
					loff_t start, loff_t len)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct page *page;

	if (!len)
		return;

	f2fs_balance_fs(sbi);

	f2fs_lock_op(sbi);
	page = get_new_data_page(inode, NULL, index, false);
	f2fs_unlock_op(sbi);

	if (!IS_ERR(page)) {
		f2fs_wait_on_page_writeback(page, DATA);
		zero_user(page, start, len);
		set_page_dirty(page);
		f2fs_put_page(page, 1);
	}
}

int truncate_hole(struct inode *inode, pgoff_t pg_start, pgoff_t pg_end)
{
	pgoff_t index;
	int err;

	for (index = pg_start; index < pg_end; index++) {
		struct dnode_of_data dn;

		set_new_dnode(&dn, inode, NULL, NULL, 0);
		err = get_dnode_of_data(&dn, index, LOOKUP_NODE);
		if (err) {
			if (err == -ENOENT)
				continue;
			return err;
		}

		if (dn.data_blkaddr != NULL_ADDR)
			truncate_data_blocks_range(&dn, 1);
		f2fs_put_dnode(&dn);
	}
	return 0;
}

static int punch_hole(struct inode *inode, loff_t offset, loff_t len)
{
	pgoff_t pg_start, pg_end;
	loff_t off_start, off_end;
	int ret = 0;

	if (!S_ISREG(inode->i_mode))
		return -EOPNOTSUPP;

	/* skip punching hole beyond i_size */
	if (offset >= inode->i_size)
		return ret;

	ret = f2fs_convert_inline_data(inode, MAX_INLINE_DATA + 1, NULL);
	if (ret)
		return ret;

	pg_start = ((unsigned long long) offset) >> PAGE_CACHE_SHIFT;
	pg_end = ((unsigned long long) offset + len) >> PAGE_CACHE_SHIFT;

	off_start = offset & (PAGE_CACHE_SIZE - 1);
	off_end = (offset + len) & (PAGE_CACHE_SIZE - 1);

	if (pg_start == pg_end) {
		fill_zero(inode, pg_start, off_start,
						off_end - off_start);
	} else {
		if (off_start)
			fill_zero(inode, pg_start++, off_start,
					PAGE_CACHE_SIZE - off_start);
		if (off_end)
			fill_zero(inode, pg_end, 0, off_end);

		if (pg_start < pg_end) {
			struct address_space *mapping = inode->i_mapping;
			loff_t blk_start, blk_end;
			struct f2fs_sb_info *sbi = F2FS_I_SB(inode);

			f2fs_balance_fs(sbi);

			blk_start = pg_start << PAGE_CACHE_SHIFT;
			blk_end = pg_end << PAGE_CACHE_SHIFT;
			truncate_inode_pages_range(mapping, blk_start,
					blk_end - 1);

			f2fs_lock_op(sbi);
			ret = truncate_hole(inode, pg_start, pg_end);
			f2fs_unlock_op(sbi);
		}
	}

	return ret;
}

static int expand_inode_data(struct inode *inode, loff_t offset,
					loff_t len, int mode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	pgoff_t index, pg_start, pg_end;
	loff_t new_size = i_size_read(inode);
	loff_t off_start, off_end;
	int ret = 0;

	f2fs_balance_fs(sbi);

	ret = inode_newsize_ok(inode, (len + offset));
	if (ret)
		return ret;

		if (__is_valid_data_blkaddr(*blkaddr) &&
			!f2fs_is_valid_blkaddr(sbi, *blkaddr,
					DATA_GENERIC_ENHANCE)) {
			f2fs_put_dnode(&dn);
			return -EFSCORRUPTED;
		}

	pg_start = ((unsigned long long) offset) >> PAGE_CACHE_SHIFT;
	pg_end = ((unsigned long long) offset + len) >> PAGE_CACHE_SHIFT;

	off_start = offset & (PAGE_CACHE_SIZE - 1);
	off_end = (offset + len) & (PAGE_CACHE_SIZE - 1);

	f2fs_lock_op(sbi);

	for (index = pg_start; index <= pg_end; index++) {
		struct dnode_of_data dn;

		if (index == pg_end && !off_end)
			goto noalloc;

		set_new_dnode(&dn, inode, NULL, NULL, 0);
		ret = f2fs_reserve_block(&dn, index);
		if (ret)
			break;
noalloc:
		if (pg_start == pg_end)
			new_size = offset + len;
		else if (index == pg_start && off_start)
			new_size = (index + 1) << PAGE_CACHE_SHIFT;
		else if (index == pg_end)
			new_size = (index << PAGE_CACHE_SHIFT) + off_end;
		else
			new_size += PAGE_CACHE_SIZE;
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) &&
		i_size_read(inode) < new_size) {
		i_size_write(inode, new_size);
		mark_inode_dirty(inode);
		update_inode_page(inode);
	}
	f2fs_unlock_op(sbi);

	return ret;
}

static long f2fs_fallocate(struct file *file, int mode,
				loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(file);
	long ret;

	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE))
		return -EOPNOTSUPP;

	mutex_lock(&inode->i_mutex);

	if (mode & FALLOC_FL_PUNCH_HOLE)
		ret = punch_hole(inode, offset, len);
	else
		ret = expand_inode_data(inode, offset, len, mode);

			ret = f2fs_get_node_info(sbi, dn.nid, &ni);
			if (ret) {
				f2fs_put_dnode(&dn);
				return ret;
			}

			ilen = min((pgoff_t)
				ADDRS_PER_PAGE(dn.node_page, dst_inode) -
						dn.ofs_in_node, len - i);
			do {
				dn.data_blkaddr = datablock_addr(dn.inode,
						dn.node_page, dn.ofs_in_node);
				f2fs_truncate_data_blocks_range(&dn, 1);

				if (do_replace[i]) {
					f2fs_i_blocks_write(src_inode,
							1, false, false);
					f2fs_i_blocks_write(dst_inode,
							1, true, false);
					f2fs_replace_block(sbi, &dn, dn.data_blkaddr,
					blkaddr[i], ni.version, true, false);

					do_replace[i] = 0;
				}
				dn.ofs_in_node++;
				i++;
				new_size = (dst + i) << PAGE_SHIFT;
				if (dst_inode->i_size < new_size)
					f2fs_i_size_write(dst_inode, new_size);
			} while (--ilen && (do_replace[i] || blkaddr[i] == NULL_ADDR));

			f2fs_put_dnode(&dn);
		} else {
			struct page *psrc, *pdst;

			psrc = f2fs_get_lock_data_page(src_inode,
							src + i, true);
			if (IS_ERR(psrc))
				return PTR_ERR(psrc);
			pdst = f2fs_get_new_data_page(dst_inode, NULL, dst + i,
								true);
			if (IS_ERR(pdst)) {
				f2fs_put_page(psrc, 1);
				return PTR_ERR(pdst);
			}
			f2fs_copy_page(psrc, pdst);
			set_page_dirty(pdst);
			f2fs_put_page(pdst, 1);
			f2fs_put_page(psrc, 1);

			ret = f2fs_truncate_hole(src_inode,
						src + i, src + i + 1);
			if (ret)
				return ret;
			i++;
		}
	}
	return 0;
}

static int __exchange_data_block(struct inode *src_inode,
			struct inode *dst_inode, pgoff_t src, pgoff_t dst,
			pgoff_t len, bool full)
{
	block_t *src_blkaddr;
	int *do_replace;
	pgoff_t olen;
	int ret;

	while (len) {
		olen = min((pgoff_t)4 * ADDRS_PER_BLOCK(src_inode), len);

		src_blkaddr = f2fs_kvzalloc(F2FS_I_SB(src_inode),
					array_size(olen, sizeof(block_t)),
					GFP_KERNEL);
		if (!src_blkaddr)
			return -ENOMEM;

		do_replace = f2fs_kvzalloc(F2FS_I_SB(src_inode),
					array_size(olen, sizeof(int)),
					GFP_KERNEL);
		if (!do_replace) {
			kvfree(src_blkaddr);
			return -ENOMEM;
		}

		ret = __read_out_blkaddrs(src_inode, src_blkaddr,
					do_replace, src, olen);
		if (ret)
			goto roll_back;

		ret = __clone_blkaddrs(src_inode, dst_inode, src_blkaddr,
					do_replace, src, dst, olen, full);
		if (ret)
			goto roll_back;

		src += olen;
		dst += olen;
		len -= olen;

		kvfree(src_blkaddr);
		kvfree(do_replace);
	}
	return 0;

roll_back:
	__roll_back_blkaddrs(src_inode, src_blkaddr, do_replace, src, olen);
	kvfree(src_blkaddr);
	kvfree(do_replace);
	return ret;
}

static int f2fs_do_collapse(struct inode *inode, loff_t offset, loff_t len)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	pgoff_t nrpages = DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE);
	pgoff_t start = offset >> PAGE_SHIFT;
	pgoff_t end = (offset + len) >> PAGE_SHIFT;
	int ret;

	f2fs_balance_fs(sbi, true);

	/* avoid gc operation during block exchange */
	down_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
	down_write(&F2FS_I(inode)->i_mmap_sem);

	f2fs_lock_op(sbi);
	f2fs_drop_extent_tree(inode);
	truncate_pagecache(inode, offset);
	ret = __exchange_data_block(inode, inode, end, start, nrpages - end, true);
	f2fs_unlock_op(sbi);

	up_write(&F2FS_I(inode)->i_mmap_sem);
	up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
	return ret;
}

static int f2fs_collapse_range(struct inode *inode, loff_t offset, loff_t len)
{
	loff_t new_size;
	int ret;

	if (offset + len >= i_size_read(inode))
		return -EINVAL;

	/* collapse range should be aligned to block size of f2fs. */
	if (offset & (F2FS_BLKSIZE - 1) || len & (F2FS_BLKSIZE - 1))
		return -EINVAL;

	ret = f2fs_convert_inline_inode(inode);
	if (ret)
		return ret;

	/* write out all dirty pages from offset */
	ret = filemap_write_and_wait_range(inode->i_mapping, offset, LLONG_MAX);
	if (ret)
		return ret;

	ret = f2fs_do_collapse(inode, offset, len);
	if (ret)
		return ret;

	/* write out all moved pages, if possible */
	down_write(&F2FS_I(inode)->i_mmap_sem);
	filemap_write_and_wait_range(inode->i_mapping, offset, LLONG_MAX);
	truncate_pagecache(inode, offset);

	new_size = i_size_read(inode) - len;
	truncate_pagecache(inode, new_size);

	ret = f2fs_truncate_blocks(inode, new_size, true);
	up_write(&F2FS_I(inode)->i_mmap_sem);
	if (!ret)
		f2fs_i_size_write(inode, new_size);
	return ret;
}

static int f2fs_do_zero_range(struct dnode_of_data *dn, pgoff_t start,
								pgoff_t end)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(dn->inode);
	pgoff_t index = start;
	unsigned int ofs_in_node = dn->ofs_in_node;
	blkcnt_t count = 0;
	int ret;

	for (; index < end; index++, dn->ofs_in_node++) {
		if (datablock_addr(dn->inode, dn->node_page,
					dn->ofs_in_node) == NULL_ADDR)
			count++;
	}

	dn->ofs_in_node = ofs_in_node;
	ret = f2fs_reserve_new_blocks(dn, count);
	if (ret)
		return ret;

	dn->ofs_in_node = ofs_in_node;
	for (index = start; index < end; index++, dn->ofs_in_node++) {
		dn->data_blkaddr = datablock_addr(dn->inode,
					dn->node_page, dn->ofs_in_node);
		/*
		 * f2fs_reserve_new_blocks will not guarantee entire block
		 * allocation.
		 */
		if (dn->data_blkaddr == NULL_ADDR) {
			ret = -ENOSPC;
			break;
		}
		if (dn->data_blkaddr != NEW_ADDR) {
			f2fs_invalidate_blocks(sbi, dn->data_blkaddr);
			dn->data_blkaddr = NEW_ADDR;
			f2fs_set_data_blkaddr(dn);
		}
	}

	f2fs_update_extent_cache_range(dn, start, 0, index - start);

	return ret;
}

static int f2fs_zero_range(struct inode *inode, loff_t offset, loff_t len,
								int mode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct address_space *mapping = inode->i_mapping;
	pgoff_t index, pg_start, pg_end;
	loff_t new_size = i_size_read(inode);
	loff_t off_start, off_end;
	int ret = 0;

	ret = inode_newsize_ok(inode, (len + offset));
	if (ret)
		return ret;

	ret = f2fs_convert_inline_inode(inode);
	if (ret)
		return ret;

	ret = filemap_write_and_wait_range(mapping, offset, offset + len - 1);
	if (ret)
		return ret;

	pg_start = ((unsigned long long) offset) >> PAGE_SHIFT;
	pg_end = ((unsigned long long) offset + len) >> PAGE_SHIFT;

	off_start = offset & (PAGE_SIZE - 1);
	off_end = (offset + len) & (PAGE_SIZE - 1);

	if (pg_start == pg_end) {
		ret = fill_zero(inode, pg_start, off_start,
						off_end - off_start);
		if (ret)
			return ret;

		new_size = max_t(loff_t, new_size, offset + len);
	} else {
		if (off_start) {
			ret = fill_zero(inode, pg_start++, off_start,
						PAGE_SIZE - off_start);
			if (ret)
				return ret;

			new_size = max_t(loff_t, new_size,
					(loff_t)pg_start << PAGE_SHIFT);
		}

		for (index = pg_start; index < pg_end;) {
			struct dnode_of_data dn;
			unsigned int end_offset;
			pgoff_t end;

			down_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
			down_write(&F2FS_I(inode)->i_mmap_sem);

			truncate_pagecache_range(inode,
				(loff_t)index << PAGE_SHIFT,
				((loff_t)pg_end << PAGE_SHIFT) - 1);

			f2fs_lock_op(sbi);

			set_new_dnode(&dn, inode, NULL, NULL, 0);
			ret = f2fs_get_dnode_of_data(&dn, index, ALLOC_NODE);
			if (ret) {
				f2fs_unlock_op(sbi);
				up_write(&F2FS_I(inode)->i_mmap_sem);
				up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
				goto out;
			}

			end_offset = ADDRS_PER_PAGE(dn.node_page, inode);
			end = min(pg_end, end_offset - dn.ofs_in_node + index);

			ret = f2fs_do_zero_range(&dn, index, end);
			f2fs_put_dnode(&dn);

			f2fs_unlock_op(sbi);
			up_write(&F2FS_I(inode)->i_mmap_sem);
			up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);

			f2fs_balance_fs(sbi, dn.node_changed);

			if (ret)
				goto out;

			index = end;
			new_size = max_t(loff_t, new_size,
					(loff_t)index << PAGE_SHIFT);
		}

		if (off_end) {
			ret = fill_zero(inode, pg_end, 0, off_end);
			if (ret)
				goto out;

			new_size = max_t(loff_t, new_size, offset + len);
		}
	}

out:
	if (new_size > i_size_read(inode)) {
		if (mode & FALLOC_FL_KEEP_SIZE)
			file_set_keep_isize(inode);
		else
			f2fs_i_size_write(inode, new_size);
	}
	return ret;
}

static int f2fs_insert_range(struct inode *inode, loff_t offset, loff_t len)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	pgoff_t nr, pg_start, pg_end, delta, idx;
	loff_t new_size;
	int ret = 0;

	new_size = i_size_read(inode) + len;
	ret = inode_newsize_ok(inode, new_size);
	if (ret)
		return ret;

	if (offset >= i_size_read(inode))
		return -EINVAL;

	/* insert range should be aligned to block size of f2fs. */
	if (offset & (F2FS_BLKSIZE - 1) || len & (F2FS_BLKSIZE - 1))
		return -EINVAL;

	ret = f2fs_convert_inline_inode(inode);
	if (ret)
		return ret;

	f2fs_balance_fs(sbi, true);

	down_write(&F2FS_I(inode)->i_mmap_sem);
	ret = f2fs_truncate_blocks(inode, i_size_read(inode), true);
	up_write(&F2FS_I(inode)->i_mmap_sem);
	if (ret)
		return ret;

	/* write out all dirty pages from offset */
	ret = filemap_write_and_wait_range(inode->i_mapping, offset, LLONG_MAX);
	if (ret)
		return ret;

	pg_start = offset >> PAGE_SHIFT;
	pg_end = (offset + len) >> PAGE_SHIFT;
	delta = pg_end - pg_start;
	idx = DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE);

	/* avoid gc operation during block exchange */
	down_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
	down_write(&F2FS_I(inode)->i_mmap_sem);
	truncate_pagecache(inode, offset);

	while (!ret && idx > pg_start) {
		nr = idx - pg_start;
		if (nr > delta)
			nr = delta;
		idx -= nr;

		f2fs_lock_op(sbi);
		f2fs_drop_extent_tree(inode);

		ret = __exchange_data_block(inode, inode, idx,
					idx + delta, nr, false);
		f2fs_unlock_op(sbi);
	}
	up_write(&F2FS_I(inode)->i_mmap_sem);
	up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);

	/* write out all moved pages, if possible */
	down_write(&F2FS_I(inode)->i_mmap_sem);
	filemap_write_and_wait_range(inode->i_mapping, offset, LLONG_MAX);
	truncate_pagecache(inode, offset);
	up_write(&F2FS_I(inode)->i_mmap_sem);

	if (!ret)
		f2fs_i_size_write(inode, new_size);
	return ret;
}

static int expand_inode_data(struct inode *inode, loff_t offset,
					loff_t len, int mode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_map_blocks map = { .m_next_pgofs = NULL,
			.m_next_extent = NULL, .m_seg_type = NO_CHECK_TYPE };
	pgoff_t pg_end;
	loff_t new_size = i_size_read(inode);
	loff_t off_end;
	int err;

	err = inode_newsize_ok(inode, (len + offset));
	if (err)
		return err;

	err = f2fs_convert_inline_inode(inode);
	if (err)
		return err;

	f2fs_balance_fs(sbi, true);

	pg_end = ((unsigned long long)offset + len) >> PAGE_SHIFT;
	off_end = (offset + len) & (PAGE_SIZE - 1);

	map.m_lblk = ((unsigned long long)offset) >> PAGE_SHIFT;
	map.m_len = pg_end - map.m_lblk;
	if (off_end)
		map.m_len++;

	if (f2fs_is_pinned_file(inode))
		map.m_seg_type = CURSEG_COLD_DATA;

	err = f2fs_map_blocks(inode, &map, 1, (f2fs_is_pinned_file(inode) ?
						F2FS_GET_BLOCK_PRE_DIO :
						F2FS_GET_BLOCK_PRE_AIO));
	if (err) {
		pgoff_t last_off;

		if (!map.m_len)
			return err;

		last_off = map.m_lblk + map.m_len - 1;

		/* update new size to the failed position */
		new_size = (last_off == pg_end) ? offset + len :
					(loff_t)(last_off + 1) << PAGE_SHIFT;
	} else {
		new_size = ((loff_t)pg_end << PAGE_SHIFT) + off_end;
	}

	if (new_size > i_size_read(inode)) {
		if (mode & FALLOC_FL_KEEP_SIZE)
			file_set_keep_isize(inode);
		else
			f2fs_i_size_write(inode, new_size);
	}

	return err;
}

#ifndef FALLOC_FL_COLLAPSE_RANGE
#define FALLOC_FL_COLLAPSE_RANGE	0X08
#endif
#ifndef FALLOC_FL_ZERO_RANGE
#define FALLOC_FL_ZERO_RANGE		0X10
#endif
#ifndef FALLOC_FL_INSERT_RANGE
#define FALLOC_FL_INSERT_RANGE		0X20
#endif

static long f2fs_fallocate(struct file *file, int mode,
				loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(file);
	long ret = 0;

	if (unlikely(f2fs_cp_error(F2FS_I_SB(inode))))
		return -EIO;

	/* f2fs only support ->fallocate for regular file */
	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	if (f2fs_encrypted_inode(inode) &&
		(mode & (FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE)))
		return -EOPNOTSUPP;

	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE |
			FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_ZERO_RANGE |
			FALLOC_FL_INSERT_RANGE))
		return -EOPNOTSUPP;

	inode_lock(inode);

	if (mode & FALLOC_FL_PUNCH_HOLE) {
		if (offset >= inode->i_size)
			goto out;

		ret = punch_hole(inode, offset, len);
	} else if (mode & FALLOC_FL_COLLAPSE_RANGE) {
		ret = f2fs_collapse_range(inode, offset, len);
	} else if (mode & FALLOC_FL_ZERO_RANGE) {
		ret = f2fs_zero_range(inode, offset, len, mode);
	} else if (mode & FALLOC_FL_INSERT_RANGE) {
		ret = f2fs_insert_range(inode, offset, len);
	} else {
		ret = expand_inode_data(inode, offset, len, mode);
	}

	if (!ret) {
		inode->i_mtime = inode->i_ctime = current_time(inode);
		f2fs_mark_inode_dirty_sync(inode, false);
		f2fs_update_time(F2FS_I_SB(inode), REQ_TIME);
	}

out:
	inode_unlock(inode);

	trace_f2fs_fallocate(inode, mode, offset, len, ret);
	return ret;
}

static int f2fs_release_file(struct inode *inode, struct file *filp)
{
	/*
	 * f2fs_relase_file is called at every close calls. So we should
	 * not drop any inmemory pages by close called by other process.
	 */
	if (!(filp->f_mode & FMODE_WRITE) ||
			atomic_read(&inode->i_writecount) != 1)
		return 0;

	/* some remained atomic pages should discarded */
	if (f2fs_is_atomic_file(inode))
		f2fs_drop_inmem_pages(inode);
	if (f2fs_is_volatile_file(inode)) {
		set_inode_flag(inode, FI_DROP_CACHE);
		filemap_fdatawrite(inode->i_mapping);
		clear_inode_flag(inode, FI_DROP_CACHE);
		clear_inode_flag(inode, FI_VOLATILE_FILE);
		stat_dec_volatile_write(inode);
	}
	return 0;
}

static int f2fs_file_flush(struct file *file, fl_owner_t id)
{
	struct inode *inode = file_inode(file);

	/*
	 * If the process doing a transaction is crashed, we should do
	 * roll-back. Otherwise, other reader/write can see corrupted database
	 * until all the writers close its file. Since this should be done
	 * before dropping file lock, it needs to do in ->flush.
	 */
	if (f2fs_is_atomic_file(inode) &&
			F2FS_I(inode)->inmem_task == current)
		f2fs_drop_inmem_pages(inode);
	return 0;
}

static int f2fs_setflags_common(struct inode *inode, u32 iflags, u32 mask)
{
	struct f2fs_inode_info *fi = F2FS_I(inode);
	u32 oldflags;

	/* Is it quota file? Do not allow user to mess with it */
	if (IS_NOQUOTA(inode))
		return -EPERM;

	oldflags = fi->i_flags;

	if ((iflags ^ oldflags) & (F2FS_APPEND_FL | F2FS_IMMUTABLE_FL))
		if (!capable(CAP_LINUX_IMMUTABLE))
			return -EPERM;

	fi->i_flags = iflags | (oldflags & ~mask);

	if (fi->i_flags & F2FS_PROJINHERIT_FL)
		set_inode_flag(inode, FI_PROJ_INHERIT);
	else
		clear_inode_flag(inode, FI_PROJ_INHERIT);

	inode->i_ctime = current_time(inode);
	f2fs_set_inode_flags(inode);
	f2fs_mark_inode_dirty_sync(inode, true);
	return 0;
}

/* FS_IOC_GETFLAGS and FS_IOC_SETFLAGS support */

/*
 * To make a new on-disk f2fs i_flag gettable via FS_IOC_GETFLAGS, add an entry
 * for it to f2fs_fsflags_map[], and add its FS_*_FL equivalent to
 * F2FS_GETTABLE_FS_FL.  To also make it settable via FS_IOC_SETFLAGS, also add
 * its FS_*_FL equivalent to F2FS_SETTABLE_FS_FL.
 */

static const struct {
	u32 iflag;
	u32 fsflag;
} f2fs_fsflags_map[] = {
	{ F2FS_SYNC_FL,		FS_SYNC_FL },
	{ F2FS_IMMUTABLE_FL,	FS_IMMUTABLE_FL },
	{ F2FS_APPEND_FL,	FS_APPEND_FL },
	{ F2FS_NODUMP_FL,	FS_NODUMP_FL },
	{ F2FS_NOATIME_FL,	FS_NOATIME_FL },
	{ F2FS_INDEX_FL,	FS_INDEX_FL },
	{ F2FS_DIRSYNC_FL,	FS_DIRSYNC_FL },
	{ F2FS_PROJINHERIT_FL,	FS_PROJINHERIT_FL },
};

#define F2FS_GETTABLE_FS_FL (		\
		FS_SYNC_FL |		\
		FS_IMMUTABLE_FL |	\
		FS_APPEND_FL |		\
		FS_NODUMP_FL |		\
		FS_NOATIME_FL |		\
		FS_INDEX_FL |		\
		FS_DIRSYNC_FL |		\
		FS_PROJINHERIT_FL |	\
		FS_ENCRYPT_FL |		\
		FS_INLINE_DATA_FL |	\
		FS_NOCOW_FL)

#define F2FS_SETTABLE_FS_FL (		\
		FS_SYNC_FL |		\
		FS_IMMUTABLE_FL |	\
		FS_APPEND_FL |		\
		FS_NODUMP_FL |		\
		FS_NOATIME_FL |		\
		FS_DIRSYNC_FL |		\
		FS_PROJINHERIT_FL)

/* Convert f2fs on-disk i_flags to FS_IOC_{GET,SET}FLAGS flags */
static inline u32 f2fs_iflags_to_fsflags(u32 iflags)
{
	u32 fsflags = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(f2fs_fsflags_map); i++)
		if (iflags & f2fs_fsflags_map[i].iflag)
			fsflags |= f2fs_fsflags_map[i].fsflag;

	return fsflags;
}

/* Convert FS_IOC_{GET,SET}FLAGS flags to f2fs on-disk i_flags */
static inline u32 f2fs_fsflags_to_iflags(u32 fsflags)
{
	u32 iflags = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(f2fs_fsflags_map); i++)
		if (fsflags & f2fs_fsflags_map[i].fsflag)
			iflags |= f2fs_fsflags_map[i].iflag;

	return iflags;
}

static int f2fs_ioc_getflags(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_inode_info *fi = F2FS_I(inode);
	u32 fsflags = f2fs_iflags_to_fsflags(fi->i_flags);

	if (IS_ENCRYPTED(inode))
		fsflags |= FS_ENCRYPT_FL;
	if (f2fs_has_inline_data(inode) || f2fs_has_inline_dentry(inode))
		fsflags |= FS_INLINE_DATA_FL;
	if (is_inode_flag_set(inode, FI_PIN_FILE))
		fsflags |= FS_NOCOW_FL;

	fsflags &= F2FS_GETTABLE_FS_FL;

	return put_user(fsflags, (int __user *)arg);
}

static int f2fs_ioc_setflags(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	u32 fsflags;
	u32 iflags;
	int ret;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	if (get_user(fsflags, (int __user *)arg))
		return -EFAULT;

	if (fsflags & ~F2FS_GETTABLE_FS_FL)
		return -EOPNOTSUPP;
	fsflags &= F2FS_SETTABLE_FS_FL;

	iflags = f2fs_fsflags_to_iflags(fsflags);
	if (f2fs_mask_flags(inode->i_mode, iflags) != iflags)
		return -EOPNOTSUPP;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	inode_lock(inode);

	ret = f2fs_setflags_common(inode, iflags,
			f2fs_fsflags_to_iflags(F2FS_SETTABLE_FS_FL));
	inode_unlock(inode);
	mnt_drop_write_file(filp);
	return ret;
}

static int f2fs_ioc_getversion(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);

	return put_user(inode->i_generation, (int __user *)arg);
}

static int f2fs_ioc_start_atomic_write(struct file *filp)
{
	struct inode *inode = file_inode(filp);
	int ret;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	inode_lock(inode);

	if (f2fs_is_atomic_file(inode)) {
		if (is_inode_flag_set(inode, FI_ATOMIC_REVOKE_REQUEST))
			ret = -EINVAL;
		goto out;
	}

	ret = f2fs_convert_inline_inode(inode);
	if (ret)
		goto out;

	down_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);

	/*
	 * Should wait end_io to count F2FS_WB_CP_DATA correctly by
	 * f2fs_is_atomic_file.
	 */
	if (get_dirty_pages(inode))
		f2fs_warn(F2FS_I_SB(inode), "Unexpected flush for atomic writes: ino=%lu, npages=%u",
			  inode->i_ino, get_dirty_pages(inode));
	ret = filemap_write_and_wait_range(inode->i_mapping, 0, LLONG_MAX);
	if (ret) {
		up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
		goto out;
	}

	set_inode_flag(inode, FI_ATOMIC_FILE);
	clear_inode_flag(inode, FI_ATOMIC_REVOKE_REQUEST);
	up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);

	f2fs_update_time(F2FS_I_SB(inode), REQ_TIME);
	F2FS_I(inode)->inmem_task = current;
	stat_inc_atomic_write(inode);
	stat_update_max_atomic_write(inode);
out:
	inode_unlock(inode);
	mnt_drop_write_file(filp);
	return ret;
}

static int f2fs_ioc_commit_atomic_write(struct file *filp)
{
	struct inode *inode = file_inode(filp);
	int ret;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	f2fs_balance_fs(F2FS_I_SB(inode), true);

	inode_lock(inode);

	if (f2fs_is_volatile_file(inode)) {
		ret = -EINVAL;
		goto err_out;
	}

	if (f2fs_is_atomic_file(inode)) {
		ret = f2fs_commit_inmem_pages(inode);
		if (ret)
			goto err_out;

		ret = f2fs_do_sync_file(filp, 0, LLONG_MAX, 0, true);
		if (!ret) {
			clear_inode_flag(inode, FI_ATOMIC_FILE);
			F2FS_I(inode)->i_gc_failures[GC_FAILURE_ATOMIC] = 0;
			stat_dec_atomic_write(inode);
		}
	} else {
		ret = f2fs_do_sync_file(filp, 0, LLONG_MAX, 1, false);
	}
err_out:
	if (is_inode_flag_set(inode, FI_ATOMIC_REVOKE_REQUEST)) {
		clear_inode_flag(inode, FI_ATOMIC_REVOKE_REQUEST);
		ret = -EINVAL;
	}
	inode_unlock(inode);
	mnt_drop_write_file(filp);
	return ret;
}

static int f2fs_ioc_start_volatile_write(struct file *filp)
{
	struct inode *inode = file_inode(filp);
	int ret;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	inode_lock(inode);

	if (f2fs_is_volatile_file(inode))
		goto out;

	ret = f2fs_convert_inline_inode(inode);
	if (ret)
		goto out;

	stat_inc_volatile_write(inode);
	stat_update_max_volatile_write(inode);

	set_inode_flag(inode, FI_VOLATILE_FILE);
	f2fs_update_time(F2FS_I_SB(inode), REQ_TIME);
out:
	inode_unlock(inode);
	mnt_drop_write_file(filp);
	return ret;
}

static int f2fs_ioc_release_volatile_write(struct file *filp)
{
	struct inode *inode = file_inode(filp);
	int ret;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	inode_lock(inode);

	if (!f2fs_is_volatile_file(inode))
		goto out;

	if (!f2fs_is_first_block_written(inode)) {
		ret = truncate_partial_data_page(inode, 0, true);
		goto out;
	}

	ret = punch_hole(inode, 0, F2FS_BLKSIZE);
out:
	inode_unlock(inode);
	mnt_drop_write_file(filp);
	return ret;
}

static int f2fs_ioc_abort_volatile_write(struct file *filp)
{
	struct inode *inode = file_inode(filp);
	int ret;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	inode_lock(inode);

	if (f2fs_is_atomic_file(inode))
		f2fs_drop_inmem_pages(inode);
	if (f2fs_is_volatile_file(inode)) {
		clear_inode_flag(inode, FI_VOLATILE_FILE);
		stat_dec_volatile_write(inode);
		ret = f2fs_do_sync_file(filp, 0, LLONG_MAX, 0, true);
	}

	clear_inode_flag(inode, FI_ATOMIC_REVOKE_REQUEST);

	inode_unlock(inode);

	mnt_drop_write_file(filp);
	f2fs_update_time(F2FS_I_SB(inode), REQ_TIME);
	return ret;
}

static int f2fs_ioc_shutdown(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct super_block *sb = sbi->sb;
	__u32 in;
	int ret = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (get_user(in, (__u32 __user *)arg))
		return -EFAULT;

	if (in != F2FS_GOING_DOWN_FULLSYNC) {
		ret = mnt_want_write_file(filp);
		if (ret)
			return ret;
	}

	switch (in) {
	case F2FS_GOING_DOWN_FULLSYNC:
		sb = freeze_bdev(sb->s_bdev);
		if (IS_ERR(sb)) {
			ret = PTR_ERR(sb);
			goto out;
		}
		if (sb) {
			f2fs_stop_checkpoint(sbi, false);
			set_sbi_flag(sbi, SBI_IS_SHUTDOWN);
			thaw_bdev(sb->s_bdev, sb);
		}
		break;
	case F2FS_GOING_DOWN_METASYNC:
		/* do checkpoint only */
		ret = f2fs_sync_fs(sb, 1);
		if (ret)
			goto out;
		f2fs_stop_checkpoint(sbi, false);
		set_sbi_flag(sbi, SBI_IS_SHUTDOWN);
		break;
	case F2FS_GOING_DOWN_NOSYNC:
		f2fs_stop_checkpoint(sbi, false);
		set_sbi_flag(sbi, SBI_IS_SHUTDOWN);
		break;
	case F2FS_GOING_DOWN_METAFLUSH:
		f2fs_sync_meta_pages(sbi, META, LONG_MAX, FS_META_IO);
		f2fs_stop_checkpoint(sbi, false);
		set_sbi_flag(sbi, SBI_IS_SHUTDOWN);
		break;
	case F2FS_GOING_DOWN_NEED_FSCK:
		set_sbi_flag(sbi, SBI_NEED_FSCK);
		set_sbi_flag(sbi, SBI_CP_DISABLED_QUICK);
		set_sbi_flag(sbi, SBI_IS_DIRTY);
		/* do checkpoint only */
		ret = f2fs_sync_fs(sb, 1);
		goto out;
	default:
		ret = -EINVAL;
		goto out;
	}

	f2fs_stop_gc_thread(sbi);
	f2fs_stop_discard_thread(sbi);

	f2fs_drop_discard_cmd(sbi);
	clear_opt(sbi, DISCARD);

	f2fs_update_time(sbi, REQ_TIME);
out:
	if (in != F2FS_GOING_DOWN_FULLSYNC)
		mnt_drop_write_file(filp);

	trace_f2fs_shutdown(sbi, in, ret);

	return ret;
}

static int f2fs_ioc_fitrim(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	struct request_queue *q = bdev_get_queue(sb->s_bdev);
	struct fstrim_range range;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!f2fs_hw_support_discard(F2FS_SB(sb)))
		return -EOPNOTSUPP;

	if (copy_from_user(&range, (struct fstrim_range __user *)arg,
				sizeof(range)))
		return -EFAULT;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	range.minlen = max((unsigned int)range.minlen,
				q->limits.discard_granularity);
	ret = f2fs_trim_fs(F2FS_SB(sb), &range);
	mnt_drop_write_file(filp);
	if (ret < 0)
		return ret;

	if (copy_to_user((struct fstrim_range __user *)arg, &range,
				sizeof(range)))
		return -EFAULT;
	f2fs_update_time(F2FS_I_SB(inode), REQ_TIME);
	return 0;
}

static bool uuid_is_nonzero(__u8 u[16])
{
	int i;

	for (i = 0; i < 16; i++)
		if (u[i])
			return true;
	return false;
}

static int f2fs_ioc_set_encryption_policy(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);

	if (!f2fs_sb_has_encrypt(F2FS_I_SB(inode)))
		return -EOPNOTSUPP;

	f2fs_update_time(F2FS_I_SB(inode), REQ_TIME);

	return fscrypt_ioctl_set_policy(filp, (const void __user *)arg);
}

static int f2fs_ioc_get_encryption_policy(struct file *filp, unsigned long arg)
{
	if (!f2fs_sb_has_encrypt(F2FS_I_SB(file_inode(filp))))
		return -EOPNOTSUPP;
	return fscrypt_ioctl_get_policy(filp, (void __user *)arg);
}

static int f2fs_ioc_get_encryption_pwsalt(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	int err;

	if (!f2fs_sb_has_encrypt(sbi))
		return -EOPNOTSUPP;

	err = mnt_want_write_file(filp);
	if (err)
		return err;

	down_write(&sbi->sb_lock);

	if (uuid_is_nonzero(sbi->raw_super->encrypt_pw_salt))
		goto got_it;

	/* update superblock with uuid */
	generate_random_uuid(sbi->raw_super->encrypt_pw_salt);

	err = f2fs_commit_super(sbi, false);
	if (err) {
		/* undo new data */
		memset(sbi->raw_super->encrypt_pw_salt, 0, 16);
		goto out_err;
	}
got_it:
	if (copy_to_user((__u8 __user *)arg, sbi->raw_super->encrypt_pw_salt,
									16))
		err = -EFAULT;
out_err:
	up_write(&sbi->sb_lock);
	mnt_drop_write_file(filp);
	return err;
}

static int f2fs_ioc_gc(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	__u32 sync;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (get_user(sync, (__u32 __user *)arg))
		return -EFAULT;

	if (f2fs_readonly(sbi->sb))
		return -EROFS;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	if (!sync) {
		if (!mutex_trylock(&sbi->gc_mutex)) {
			ret = -EBUSY;
			goto out;
		}
	} else {
		mutex_lock(&sbi->gc_mutex);
	}

	ret = f2fs_gc(sbi, sync, true, NULL_SEGNO);
out:
	mnt_drop_write_file(filp);
	return ret;
}

static int f2fs_ioc_gc_range(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_gc_range range;
	u64 end;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(&range, (struct f2fs_gc_range __user *)arg,
							sizeof(range)))
		return -EFAULT;

	if (f2fs_readonly(sbi->sb))
		return -EROFS;

	end = range.start + range.len;
	if (range.start < MAIN_BLKADDR(sbi) || end >= MAX_BLKADDR(sbi)) {
		return -EINVAL;
	}

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

do_more:
	if (!range.sync) {
		if (!mutex_trylock(&sbi->gc_mutex)) {
			ret = -EBUSY;
			goto out;
		}
	} else {
		mutex_lock(&sbi->gc_mutex);
	}

	ret = f2fs_gc(sbi, range.sync, true, GET_SEGNO(sbi, range.start));
	range.start += BLKS_PER_SEC(sbi);
	if (range.start <= end)
		goto do_more;
out:
	mnt_drop_write_file(filp);
	return ret;
}

static int f2fs_ioc_write_checkpoint(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (f2fs_readonly(sbi->sb))
		return -EROFS;

	if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED))) {
		f2fs_info(sbi, "Skipping Checkpoint. Checkpoints currently disabled.");
		return -EINVAL;
	}

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	ret = f2fs_sync_fs(sbi->sb, 1);

	mnt_drop_write_file(filp);
	return ret;
}

static int f2fs_defragment_range(struct f2fs_sb_info *sbi,
					struct file *filp,
					struct f2fs_defragment *range)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_map_blocks map = { .m_next_extent = NULL,
					.m_seg_type = NO_CHECK_TYPE };
	struct extent_info ei = {0, 0, 0};
	pgoff_t pg_start, pg_end, next_pgofs;
	unsigned int blk_per_seg = sbi->blocks_per_seg;
	unsigned int total = 0, sec_num;
	block_t blk_end = 0;
	bool fragmented = false;
	int err;

	/* if in-place-update policy is enabled, don't waste time here */
	if (f2fs_should_update_inplace(inode, NULL))
		return -EINVAL;

	pg_start = range->start >> PAGE_SHIFT;
	pg_end = (range->start + range->len) >> PAGE_SHIFT;

	f2fs_balance_fs(sbi, true);

	inode_lock(inode);

	/* writeback all dirty pages in the range */
	err = filemap_write_and_wait_range(inode->i_mapping, range->start,
						range->start + range->len - 1);
	if (err)
		goto out;

	/*
	 * lookup mapping info in extent cache, skip defragmenting if physical
	 * block addresses are continuous.
	 */
	if (f2fs_lookup_extent_cache(inode, pg_start, &ei)) {
		if (ei.fofs + ei.len >= pg_end)
			goto out;
	}

	map.m_lblk = pg_start;
	map.m_next_pgofs = &next_pgofs;

	/*
	 * lookup mapping info in dnode page cache, skip defragmenting if all
	 * physical block addresses are continuous even if there are hole(s)
	 * in logical blocks.
	 */
	while (map.m_lblk < pg_end) {
		map.m_len = pg_end - map.m_lblk;
		err = f2fs_map_blocks(inode, &map, 0, F2FS_GET_BLOCK_DEFAULT);
		if (err)
			goto out;

		if (!(map.m_flags & F2FS_MAP_FLAGS)) {
			map.m_lblk = next_pgofs;
			continue;
		}

		if (blk_end && blk_end != map.m_pblk)
			fragmented = true;

		/* record total count of block that we're going to move */
		total += map.m_len;

		blk_end = map.m_pblk + map.m_len;

		map.m_lblk += map.m_len;
	}

	if (!fragmented)
		goto out;

	sec_num = DIV_ROUND_UP(total, BLKS_PER_SEC(sbi));

	/*
	 * make sure there are enough free section for LFS allocation, this can
	 * avoid defragment running in SSR mode when free section are allocated
	 * intensively
	 */
	if (has_not_enough_free_secs(sbi, 0, sec_num)) {
		err = -EAGAIN;
		goto out;
	}

	mutex_unlock(&inode->i_mutex);

	trace_f2fs_fallocate(inode, mode, offset, len, ret);
	return ret;
}

#define F2FS_REG_FLMASK		(~(FS_DIRSYNC_FL | FS_TOPDIR_FL))
#define F2FS_OTHER_FLMASK	(FS_NODUMP_FL | FS_NOATIME_FL)

static inline __u32 f2fs_mask_flags(umode_t mode, __u32 flags)
{
	if (S_ISDIR(mode))
		return flags;
	else if (S_ISREG(mode))
		return flags & F2FS_REG_FLMASK;
	else
		return flags & F2FS_OTHER_FLMASK;
}

static int f2fs_ioc_getflags(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_inode_info *fi = F2FS_I(inode);
	unsigned int flags = fi->i_flags & FS_FL_USER_VISIBLE;
	return put_user(flags, (int __user *)arg);
}

static int f2fs_ioc_setflags(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_inode_info *fi = F2FS_I(inode);
	unsigned int flags = fi->i_flags & FS_FL_USER_VISIBLE;
	unsigned int oldflags;
	int ret;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	if (!inode_owner_or_capable(inode)) {
		ret = -EACCES;
		goto out;
	}

	if (get_user(flags, (int __user *)arg)) {
		ret = -EFAULT;
		goto out;
	}

	flags = f2fs_mask_flags(inode->i_mode, flags);

	mutex_lock(&inode->i_mutex);

	oldflags = fi->i_flags;

	if ((flags ^ oldflags) & (FS_APPEND_FL | FS_IMMUTABLE_FL)) {
		if (!capable(CAP_LINUX_IMMUTABLE)) {
			mutex_unlock(&inode->i_mutex);
			ret = -EPERM;
			goto out;
		}
	}

	flags = flags & FS_FL_USER_MODIFIABLE;
	flags |= oldflags & ~FS_FL_USER_MODIFIABLE;
	fi->i_flags = flags;
	mutex_unlock(&inode->i_mutex);

	f2fs_set_inode_flags(inode);
	inode->i_ctime = CURRENT_TIME;
	mark_inode_dirty(inode);
out:
	mnt_drop_write_file(filp);
	return ret;
}

static int f2fs_ioc_start_atomic_write(struct file *filp)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	f2fs_balance_fs(sbi);

	set_inode_flag(F2FS_I(inode), FI_ATOMIC_FILE);

	return f2fs_convert_inline_data(inode, MAX_INLINE_DATA + 1, NULL);
}

static int f2fs_ioc_commit_atomic_write(struct file *filp)
{
	struct inode *inode = file_inode(filp);
	int ret;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	if (!f2fs_is_multi_device(sbi) || sbi->s_ndevs - 1 <= range.dev_num ||
			__is_large_section(sbi)) {
		f2fs_warn(sbi, "Can't flush %u in %d for segs_per_sec %u != 1",
			  range.dev_num, sbi->s_ndevs, sbi->segs_per_sec);
		return -EINVAL;
	}

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	if (f2fs_is_atomic_file(inode))
		commit_inmem_pages(inode, false);

	ret = f2fs_sync_file(filp, 0, LONG_MAX, 0);
	mnt_drop_write_file(filp);
	return ret;
}

static int f2fs_ioc_start_volatile_write(struct file *filp)
{
	struct inode *inode = file_inode(filp);

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	/* Use i_gc_failures for normal file as a risk signal. */
	if (inc)
		f2fs_i_gc_failures_write(inode,
				fi->i_gc_failures[GC_FAILURE_PIN] + 1);

	if (fi->i_gc_failures[GC_FAILURE_PIN] > sbi->gc_pin_file_threshold) {
		f2fs_warn(sbi, "%s: Enable GC = ino %lx after %x GC trials",
			  __func__, inode->i_ino,
			  fi->i_gc_failures[GC_FAILURE_PIN]);
		clear_inode_flag(inode, FI_PIN_FILE);
		return -EAGAIN;
	}
	return 0;
}

static int f2fs_ioc_fitrim(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	struct request_queue *q = bdev_get_queue(sb->s_bdev);
	struct fstrim_range range;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!blk_queue_discard(q))
		return -EOPNOTSUPP;

	if (copy_from_user(&range, (struct fstrim_range __user *)arg,
				sizeof(range)))
		return -EFAULT;

	range.minlen = max((unsigned int)range.minlen,
				q->limits.discard_granularity);
	ret = f2fs_trim_fs(F2FS_SB(sb), &range);
	if (ret < 0)
		return ret;

	if (copy_to_user((struct fstrim_range __user *)arg, &range,
				sizeof(range)))
		return -EFAULT;
	return 0;
}

static int f2fs_ioc_resize_fs(struct file *filp, unsigned long arg)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(file_inode(filp));
	__u64 block_count;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (f2fs_readonly(sbi->sb))
		return -EROFS;

	if (copy_from_user(&block_count, (void __user *)arg,
			   sizeof(block_count)))
		return -EFAULT;

	ret = f2fs_resize_fs(sbi, block_count);

	return ret;
}

long f2fs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case F2FS_IOC_GETFLAGS:
		return f2fs_ioc_getflags(filp, arg);
	case F2FS_IOC_SETFLAGS:
		return f2fs_ioc_setflags(filp, arg);
	case F2FS_IOC_START_ATOMIC_WRITE:
		return f2fs_ioc_start_atomic_write(filp);
	case F2FS_IOC_COMMIT_ATOMIC_WRITE:
		return f2fs_ioc_commit_atomic_write(filp);
	case F2FS_IOC_START_VOLATILE_WRITE:
		return f2fs_ioc_start_volatile_write(filp);
	case FITRIM:
		return f2fs_ioc_fitrim(filp, arg);
	case F2FS_IOC_SET_ENCRYPTION_POLICY:
		return f2fs_ioc_set_encryption_policy(filp, arg);
	case F2FS_IOC_GET_ENCRYPTION_POLICY:
		return f2fs_ioc_get_encryption_policy(filp, arg);
	case F2FS_IOC_GET_ENCRYPTION_PWSALT:
		return f2fs_ioc_get_encryption_pwsalt(filp, arg);
	case F2FS_IOC_GARBAGE_COLLECT:
		return f2fs_ioc_gc(filp, arg);
	case F2FS_IOC_GARBAGE_COLLECT_RANGE:
		return f2fs_ioc_gc_range(filp, arg);
	case F2FS_IOC_WRITE_CHECKPOINT:
		return f2fs_ioc_write_checkpoint(filp, arg);
	case F2FS_IOC_DEFRAGMENT:
		return f2fs_ioc_defragment(filp, arg);
	case F2FS_IOC_MOVE_RANGE:
		return f2fs_ioc_move_range(filp, arg);
	case F2FS_IOC_FLUSH_DEVICE:
		return f2fs_ioc_flush_device(filp, arg);
	case F2FS_IOC_GET_FEATURES:
		return f2fs_ioc_get_features(filp, arg);
	case F2FS_IOC_GET_PIN_FILE:
		return f2fs_ioc_get_pin_file(filp, arg);
	case F2FS_IOC_SET_PIN_FILE:
		return f2fs_ioc_set_pin_file(filp, arg);
	case F2FS_IOC_PRECACHE_EXTENTS:
		return f2fs_ioc_precache_extents(filp, arg);
	case F2FS_IOC_RESIZE_FS:
		return f2fs_ioc_resize_fs(filp, arg);
	default:
		return -ENOTTY;
	}
}

#ifdef CONFIG_COMPAT
long f2fs_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case F2FS_IOC32_GETFLAGS:
		cmd = F2FS_IOC_GETFLAGS;
		break;
	case F2FS_IOC32_SETFLAGS:
		cmd = F2FS_IOC_SETFLAGS;
		break;
	case F2FS_IOC32_GETVERSION:
		cmd = F2FS_IOC_GETVERSION;
		break;
	case F2FS_IOC_START_ATOMIC_WRITE:
	case F2FS_IOC_COMMIT_ATOMIC_WRITE:
	case F2FS_IOC_START_VOLATILE_WRITE:
	case F2FS_IOC_RELEASE_VOLATILE_WRITE:
	case F2FS_IOC_ABORT_VOLATILE_WRITE:
	case F2FS_IOC_SHUTDOWN:
	case F2FS_IOC_SET_ENCRYPTION_POLICY:
	case F2FS_IOC_GET_ENCRYPTION_PWSALT:
	case F2FS_IOC_GET_ENCRYPTION_POLICY:
	case F2FS_IOC_GARBAGE_COLLECT:
	case F2FS_IOC_GARBAGE_COLLECT_RANGE:
	case F2FS_IOC_WRITE_CHECKPOINT:
	case F2FS_IOC_DEFRAGMENT:
	case F2FS_IOC_MOVE_RANGE:
	case F2FS_IOC_FLUSH_DEVICE:
	case F2FS_IOC_GET_FEATURES:
	case F2FS_IOC_GET_PIN_FILE:
	case F2FS_IOC_SET_PIN_FILE:
	case F2FS_IOC_PRECACHE_EXTENTS:
	case F2FS_IOC_RESIZE_FS:
		break;
	default:
		return -ENOIOCTLCMD;
	}
	return f2fs_ioctl(file, cmd, (unsigned long) compat_ptr(arg));
}
#endif

const struct file_operations f2fs_file_operations = {
	.llseek		= f2fs_llseek,
	.read		= new_sync_read,
	.write		= new_sync_write,
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.open		= generic_file_open,
	.mmap		= f2fs_file_mmap,
	.fsync		= f2fs_sync_file,
	.fallocate	= f2fs_fallocate,
	.unlocked_ioctl	= f2fs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= f2fs_compat_ioctl,
#endif
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
};
