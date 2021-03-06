/*
 * fs/f2fs/gc.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/backing-dev.h>
#include <linux/init.h>
#include <linux/f2fs_fs.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/freezer.h>
#include <linux/blkdev.h>

#include "f2fs.h"
#include "node.h"
#include "segment.h"
#include "gc.h"
#include <trace/events/f2fs.h>

static struct kmem_cache *winode_slab;

static int gc_thread_func(void *data)
{
	struct f2fs_sb_info *sbi = data;
	struct f2fs_gc_kthread *gc_th = sbi->gc_thread;
	wait_queue_head_t *wq = &sbi->gc_thread->gc_wait_queue_head;
	long wait_ms;

	wait_ms = gc_th->min_sleep_time;

	do {
		if (try_to_freeze())
			continue;
		else
			wait_event_interruptible_timeout(*wq,
						kthread_should_stop(),
						msecs_to_jiffies(wait_ms));
		if (kthread_should_stop())
			break;

		if (sbi->sb->s_writers.frozen >= SB_FREEZE_WRITE) {
			wait_ms = increase_sleep_time(gc_th, wait_ms);
			continue;
		}

		/*
		 * [GC triggering condition]
		 * 0. GC is not conducted currently.
		 * 1. There are enough dirty segments.
		 * 2. IO subsystem is idle by checking the # of writeback pages.
		 * 3. IO subsystem is idle by checking the # of requests in
		 *    bdev's request list.
		 *
		 * Note) We have to avoid triggering GCs frequently.
		 * Because it is possible that some segments can be
		 * invalidated soon after by user update or deletion.
		 * So, I'd like to wait some time to collect dirty segments.
		 */
		if (!mutex_trylock(&sbi->gc_mutex))
			continue;

		if (!is_idle(sbi)) {
			wait_ms = increase_sleep_time(gc_th, wait_ms);
			mutex_unlock(&sbi->gc_mutex);
			continue;
		}

		if (has_enough_invalid_blocks(sbi))
			wait_ms = decrease_sleep_time(gc_th, wait_ms);
		else
			wait_ms = increase_sleep_time(gc_th, wait_ms);

		stat_inc_bggc_count(sbi);

		/* if return value is not zero, no victim was selected */
		if (f2fs_gc(sbi))
			wait_ms = gc_th->no_gc_sleep_time;

		/* balancing f2fs's metadata periodically */
		f2fs_balance_fs_bg(sbi);

	} while (!kthread_should_stop());
	return 0;
}

int start_gc_thread(struct f2fs_sb_info *sbi)
{
	struct f2fs_gc_kthread *gc_th;
	dev_t dev = sbi->sb->s_bdev->bd_dev;
	int err = 0;

	if (!test_opt(sbi, BG_GC))
		goto out;
	gc_th = kmalloc(sizeof(struct f2fs_gc_kthread), GFP_KERNEL);
	if (!gc_th) {
		err = -ENOMEM;
		goto out;
	}

	gc_th->min_sleep_time = DEF_GC_THREAD_MIN_SLEEP_TIME;
	gc_th->max_sleep_time = DEF_GC_THREAD_MAX_SLEEP_TIME;
	gc_th->no_gc_sleep_time = DEF_GC_THREAD_NOGC_SLEEP_TIME;

	gc_th->gc_idle = 0;

	sbi->gc_thread = gc_th;
	init_waitqueue_head(&sbi->gc_thread->gc_wait_queue_head);
	sbi->gc_thread->f2fs_gc_task = kthread_run(gc_thread_func, sbi,
			"f2fs_gc-%u:%u", MAJOR(dev), MINOR(dev));
	if (IS_ERR(gc_th->f2fs_gc_task)) {
		err = PTR_ERR(gc_th->f2fs_gc_task);
		kfree(gc_th);
		sbi->gc_thread = NULL;
	}
out:
	return err;
}

void stop_gc_thread(struct f2fs_sb_info *sbi)
{
	struct f2fs_gc_kthread *gc_th = sbi->gc_thread;
	if (!gc_th)
		return;
	kthread_stop(gc_th->f2fs_gc_task);
	kfree(gc_th);
	sbi->gc_thread = NULL;
}

static int select_gc_type(struct f2fs_gc_kthread *gc_th, int gc_type)
{
	int gc_mode = (gc_type == BG_GC) ? GC_CB : GC_GREEDY;

	if (gc_th && gc_th->gc_idle) {
		if (gc_th->gc_idle == 1)
			gc_mode = GC_CB;
		else if (gc_th->gc_idle == 2)
			gc_mode = GC_GREEDY;
	}
	return gc_mode;
}

static void select_policy(struct f2fs_sb_info *sbi, int gc_type,
			int type, struct victim_sel_policy *p)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);

	if (p->alloc_mode == SSR) {
		p->gc_mode = GC_GREEDY;
		p->dirty_segmap = dirty_i->dirty_segmap[type];
		p->max_search = dirty_i->nr_dirty[type];
		p->ofs_unit = 1;
	} else {
		p->gc_mode = select_gc_type(sbi->gc_thread, gc_type);
		p->dirty_segmap = dirty_i->dirty_segmap[DIRTY];
		p->max_search = dirty_i->nr_dirty[DIRTY];
		p->ofs_unit = sbi->segs_per_sec;
	}

	if (p->max_search > sbi->max_victim_search)
		p->max_search = sbi->max_victim_search;

	p->offset = sbi->last_victim[p->gc_mode];
}

static unsigned int get_max_cost(struct f2fs_sb_info *sbi,
				struct victim_sel_policy *p)
{
	/* SSR allocates in a segment unit */
	if (p->alloc_mode == SSR)
		return 1 << sbi->log_blocks_per_seg;
	if (p->gc_mode == GC_GREEDY)
		return (1 << sbi->log_blocks_per_seg) * p->ofs_unit;
	else if (p->gc_mode == GC_CB)
		return UINT_MAX;
	else /* No other gc_mode */
		return 0;
}

static unsigned int check_bg_victims(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	unsigned int secno;

	/*
	 * If the gc_type is FG_GC, we can select victim segments
	 * selected by background GC before.
	 * Those segments guarantee they have small valid blocks.
	 */
	for_each_set_bit(secno, dirty_i->victim_secmap, MAIN_SECS(sbi)) {
		if (sec_usage_check(sbi, secno))
			continue;
		clear_bit(secno, dirty_i->victim_secmap);
		return secno * sbi->segs_per_sec;
	}
	return NULL_SEGNO;
}

static unsigned int get_cb_cost(struct f2fs_sb_info *sbi, unsigned int segno)
{
	struct sit_info *sit_i = SIT_I(sbi);
	unsigned int secno = GET_SECNO(sbi, segno);
	unsigned int start = secno * sbi->segs_per_sec;
	unsigned long long mtime = 0;
	unsigned int vblocks;
	unsigned char age = 0;
	unsigned char u;
	unsigned int i;

	for (i = 0; i < sbi->segs_per_sec; i++)
		mtime += get_seg_entry(sbi, start + i)->mtime;
	vblocks = get_valid_blocks(sbi, segno, sbi->segs_per_sec);

	mtime = div_u64(mtime, sbi->segs_per_sec);
	vblocks = div_u64(vblocks, sbi->segs_per_sec);

	u = (vblocks * 100) >> sbi->log_blocks_per_seg;

	/* Handle if the system time has changed by the user */
	if (mtime < sit_i->min_mtime)
		sit_i->min_mtime = mtime;
	if (mtime > sit_i->max_mtime)
		sit_i->max_mtime = mtime;
	if (sit_i->max_mtime != sit_i->min_mtime)
		age = 100 - div64_u64(100 * (mtime - sit_i->min_mtime),
				sit_i->max_mtime - sit_i->min_mtime);

	return UINT_MAX - ((100 * (100 - u) * age) / (100 + u));
}

static inline unsigned int get_gc_cost(struct f2fs_sb_info *sbi,
			unsigned int segno, struct victim_sel_policy *p)
{
	if (p->alloc_mode == SSR)
		return get_seg_entry(sbi, segno)->ckpt_valid_blocks;

	/* alloc_mode == LFS */
	if (p->gc_mode == GC_GREEDY)
		return get_valid_blocks(sbi, segno, sbi->segs_per_sec);
	else
		return get_cb_cost(sbi, segno);
}

/*
 * This function is called from two paths.
 * One is garbage collection and the other is SSR segment selection.
 * When it is called during GC, it just gets a victim segment
 * and it does not remove it from dirty seglist.
 * When it is called from SSR segment selection, it finds a segment
 * which has minimum valid blocks and removes it from dirty seglist.
 */
static int get_victim_by_default(struct f2fs_sb_info *sbi,
		unsigned int *result, int gc_type, int type, char alloc_mode)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	struct victim_sel_policy p;
	unsigned int secno, last_victim;
	unsigned int last_segment;
	unsigned int nsearched = 0;

	mutex_lock(&dirty_i->seglist_lock);
	last_segment = MAIN_SECS(sbi) * sbi->segs_per_sec;

	p.alloc_mode = alloc_mode;
	select_policy(sbi, gc_type, type, &p);

	p.min_segno = NULL_SEGNO;
	p.min_cost = max_cost = get_max_cost(sbi, &p);

	if (p.alloc_mode == LFS && gc_type == FG_GC) {
		p.min_segno = check_bg_victims(sbi);
		if (p.min_segno != NULL_SEGNO)
			goto got_it;
	}

	while (1) {
		unsigned long cost;
		unsigned int segno;

		segno = find_next_bit(p.dirty_segmap, MAIN_SEGS(sbi), p.offset);
		if (segno >= MAIN_SEGS(sbi)) {
			if (sbi->last_victim[p.gc_mode]) {
				sbi->last_victim[p.gc_mode] = 0;
				p.offset = 0;
				continue;
			}
			break;
		}

		p.offset = segno + p.ofs_unit;
		if (p.ofs_unit > 1)
			p.offset -= segno % p.ofs_unit;

		secno = GET_SECNO(sbi, segno);

		if (sec_usage_check(sbi, secno))
			goto next;
		/* Don't touch checkpointed data */
		if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED) &&
					get_ckpt_valid_blocks(sbi, segno) &&
					p.alloc_mode != SSR))
			goto next;
		if (gc_type == BG_GC && test_bit(secno, dirty_i->victim_secmap))
			continue;

		cost = get_gc_cost(sbi, segno, &p);

		if (p.min_cost > cost) {
			p.min_segno = segno;
			p.min_cost = cost;
		} else if (unlikely(cost == max_cost)) {
			continue;
		}
next:
		if (nsearched >= p.max_search) {
			if (!sm->last_victim[p.gc_mode] && segno <= last_victim)
				sm->last_victim[p.gc_mode] = last_victim + 1;
			else
				sm->last_victim[p.gc_mode] = segno + 1;
			sm->last_victim[p.gc_mode] %=
				(MAIN_SECS(sbi) * sbi->segs_per_sec);
			break;
		}
	}
	if (p.min_segno != NULL_SEGNO) {
got_it:
		if (p.alloc_mode == LFS) {
			secno = GET_SECNO(sbi, p.min_segno);
			if (gc_type == FG_GC)
				sbi->cur_victim_sec = secno;
			else
				set_bit(secno, dirty_i->victim_secmap);
		}
		*result = (p.min_segno / p.ofs_unit) * p.ofs_unit;

		trace_f2fs_get_victim(sbi->sb, type, gc_type, &p,
				sbi->cur_victim_sec,
				prefree_segments(sbi), free_segments(sbi));
	}
	mutex_unlock(&dirty_i->seglist_lock);

	return (p.min_segno == NULL_SEGNO) ? 0 : 1;
}

static const struct victim_selection default_v_ops = {
	.get_victim = get_victim_by_default,
};

static struct inode *find_gc_inode(nid_t ino, struct list_head *ilist)
{
	struct inode_entry *ie;

	list_for_each_entry(ie, ilist, list)
		if (ie->inode->i_ino == ino)
			return ie->inode;
	return NULL;
}

static void add_gc_inode(struct inode *inode, struct list_head *ilist)
{
	struct inode_entry *new_ie;

	if (inode == find_gc_inode(inode->i_ino, ilist)) {
		iput(inode);
		return;
	}

	new_ie = f2fs_kmem_cache_alloc(winode_slab, GFP_NOFS);
	new_ie->inode = inode;
	list_add_tail(&new_ie->list, ilist);
}

static void put_gc_inode(struct list_head *ilist)
{
	struct inode_entry *ie, *next_ie;
	list_for_each_entry_safe(ie, next_ie, ilist, list) {
		iput(ie->inode);
		list_del(&ie->list);
		kmem_cache_free(winode_slab, ie);
	}
}

static int check_valid_map(struct f2fs_sb_info *sbi,
				unsigned int segno, int offset)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct seg_entry *sentry;
	int ret;

	mutex_lock(&sit_i->sentry_lock);
	sentry = get_seg_entry(sbi, segno);
	ret = f2fs_test_bit(offset, sentry->cur_valid_map);
	mutex_unlock(&sit_i->sentry_lock);
	return ret;
}

/*
 * This function compares node address got in summary with that in NAT.
 * On validity, copy that node with cold status, otherwise (invalid node)
 * ignore that.
 */
static void gc_node_segment(struct f2fs_sb_info *sbi,
		struct f2fs_summary *sum, unsigned int segno, int gc_type)
{
	bool initial = true;
	struct f2fs_summary *entry;
	int off;

next_step:
	entry = sum;

	for (off = 0; off < sbi->blocks_per_seg; off++, entry++) {
		nid_t nid = le32_to_cpu(entry->nid);
		struct page *node_page;

		/* stop BG_GC if there is not enough free sections. */
		if (gc_type == BG_GC && has_not_enough_free_secs(sbi, 0))
			return;

		if (check_valid_map(sbi, segno, off) == 0)
			continue;

		if (initial) {
			ra_node_page(sbi, nid);
			continue;
		}
		node_page = get_node_page(sbi, nid);
		if (IS_ERR(node_page))
			continue;

		/* block may become invalid during get_node_page */
		if (check_valid_map(sbi, segno, off) == 0) {
			f2fs_put_page(node_page, 1);
			continue;
		}

		/* set page dirty and write it */
		if (gc_type == FG_GC) {
			f2fs_wait_on_page_writeback(node_page, NODE);
			set_page_dirty(node_page);
		} else {
			if (!PageWriteback(node_page))
				set_page_dirty(node_page);
		}
		f2fs_put_page(node_page, 1);
		stat_inc_node_blk_count(sbi, 1);
	}

	if (initial) {
		initial = false;
		goto next_step;
	}

	if (gc_type == FG_GC) {
		struct writeback_control wbc = {
			.sync_mode = WB_SYNC_ALL,
			.nr_to_write = LONG_MAX,
			.for_reclaim = 0,
		};
		sync_node_pages(sbi, 0, &wbc);

		/*
		 * In the case of FG_GC, it'd be better to reclaim this victim
		 * completely.
		 */
		if (get_valid_blocks(sbi, segno, 1) != 0)
			goto next_step;
	}
}

/*
 * Calculate start block index indicating the given node offset.
 * Be careful, caller should give this node offset only indicating direct node
 * blocks. If any node offsets, which point the other types of node blocks such
 * as indirect or double indirect node blocks, are given, it must be a caller's
 * bug.
 */
block_t start_bidx_of_node(unsigned int node_ofs, struct f2fs_inode_info *fi)
{
	unsigned int indirect_blks = 2 * NIDS_PER_BLOCK + 4;
	unsigned int bidx;

	if (node_ofs == 0)
		return 0;

	if (node_ofs <= 2) {
		bidx = node_ofs - 1;
	} else if (node_ofs <= indirect_blks) {
		int dec = (node_ofs - 4) / (NIDS_PER_BLOCK + 1);
		bidx = node_ofs - 2 - dec;
	} else {
		int dec = (node_ofs - indirect_blks - 3) / (NIDS_PER_BLOCK + 1);
		bidx = node_ofs - 5 - dec;
	}
	return bidx * ADDRS_PER_BLOCK + ADDRS_PER_INODE(fi);
}

static int check_dnode(struct f2fs_sb_info *sbi, struct f2fs_summary *sum,
		struct node_info *dni, block_t blkaddr, unsigned int *nofs)
{
	struct page *node_page;
	nid_t nid;
	unsigned int ofs_in_node;
	block_t source_blkaddr;

	nid = le32_to_cpu(sum->nid);
	ofs_in_node = le16_to_cpu(sum->ofs_in_node);

	node_page = get_node_page(sbi, nid);
	if (IS_ERR(node_page))
		return 0;

	get_node_info(sbi, nid, dni);

	if (sum->version != dni->version) {
		f2fs_warn(sbi, "%s: valid data with mismatched node version.",
			  __func__);
		set_sbi_flag(sbi, SBI_NEED_FSCK);
	}

	*nofs = ofs_of_node(node_page);
	source_blkaddr = datablock_addr(node_page, ofs_in_node);
	f2fs_put_page(node_page, 1);

	if (source_blkaddr != blkaddr)
		return false;
	return true;
}

static int ra_data_block(struct inode *inode, pgoff_t index)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct address_space *mapping = inode->i_mapping;
	struct dnode_of_data dn;
	struct page *page;
	struct extent_info ei = {0, 0, 0};
	struct f2fs_io_info fio = {
		.sbi = sbi,
		.ino = inode->i_ino,
		.type = DATA,
		.temp = COLD,
		.op = REQ_OP_READ,
		.op_flags = 0,
		.encrypted_page = NULL,
		.in_list = false,
		.retry = false,
	};
	int err;

	page = f2fs_grab_cache_page(mapping, index, true);
	if (!page)
		return -ENOMEM;

	if (f2fs_lookup_extent_cache(inode, index, &ei)) {
		dn.data_blkaddr = ei.blk + index - ei.fofs;
		if (unlikely(!f2fs_is_valid_blkaddr(sbi, dn.data_blkaddr,
						DATA_GENERIC_ENHANCE_READ))) {
			err = -EFSCORRUPTED;
			goto put_page;
		}
		goto got_it;
	}

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	err = f2fs_get_dnode_of_data(&dn, index, LOOKUP_NODE);
	if (err)
		goto put_page;
	f2fs_put_dnode(&dn);

	if (!__is_valid_data_blkaddr(dn.data_blkaddr)) {
		err = -ENOENT;
		goto put_page;
	}
	if (unlikely(!f2fs_is_valid_blkaddr(sbi, dn.data_blkaddr,
						DATA_GENERIC_ENHANCE))) {
		err = -EFSCORRUPTED;
		goto put_page;
	}
got_it:
	/* read page */
	fio.page = page;
	fio.new_blkaddr = fio.old_blkaddr = dn.data_blkaddr;

	/*
	 * don't cache encrypted data into meta inode until previous dirty
	 * data were writebacked to avoid racing between GC and flush.
	 */
	f2fs_wait_on_page_writeback(page, DATA, true, true);

	f2fs_wait_on_block_writeback(inode, dn.data_blkaddr);

	fio.encrypted_page = f2fs_pagecache_get_page(META_MAPPING(sbi),
					dn.data_blkaddr,
					FGP_LOCK | FGP_CREAT, GFP_NOFS);
	if (!fio.encrypted_page) {
		err = -ENOMEM;
		goto put_page;
	}

	err = f2fs_submit_page_bio(&fio);
	if (err)
		goto put_encrypted_page;
	f2fs_put_page(fio.encrypted_page, 0);
	f2fs_put_page(page, 1);
	return 0;
put_encrypted_page:
	f2fs_put_page(fio.encrypted_page, 1);
put_page:
	f2fs_put_page(page, 1);
	return err;
}

static void move_data_page(struct inode *inode, struct page *page, int gc_type)
{
	struct f2fs_io_info fio = {
		.type = DATA,
		.rw = WRITE_SYNC,
	};
	struct dnode_of_data dn;
	struct f2fs_summary sum;
	struct node_info ni;
	struct page *page, *mpage;
	block_t newaddr;
	int err = 0;
	bool lfs_mode = test_opt(fio.sbi, LFS);

	/* do not read out */
	page = f2fs_grab_cache_page(inode->i_mapping, bidx, false);
	if (!page)
		return -ENOMEM;

	if (!check_valid_map(F2FS_I_SB(inode), segno, off)) {
		err = -ENOENT;
		goto out;
	}

	if (f2fs_is_atomic_file(inode)) {
		F2FS_I(inode)->i_gc_failures[GC_FAILURE_ATOMIC]++;
		F2FS_I_SB(inode)->skipped_atomic_files[gc_type]++;
		err = -EAGAIN;
		goto out;
	}

	if (f2fs_is_pinned_file(inode)) {
		f2fs_pin_file_control(inode, true);
		err = -EAGAIN;
		goto out;
	}

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	err = f2fs_get_dnode_of_data(&dn, bidx, LOOKUP_NODE);
	if (err)
		goto out;

	if (unlikely(dn.data_blkaddr == NULL_ADDR)) {
		ClearPageUptodate(page);
		err = -ENOENT;
		goto put_out;
	}

	/*
	 * don't cache encrypted data into meta inode until previous dirty
	 * data were writebacked to avoid racing between GC and flush.
	 */
	f2fs_wait_on_page_writeback(page, DATA, true, true);

	f2fs_wait_on_block_writeback(inode, dn.data_blkaddr);

	err = f2fs_get_node_info(fio.sbi, dn.nid, &ni);
	if (err)
		goto put_out;

	set_summary(&sum, dn.nid, dn.ofs_in_node, ni.version);

	/* read page */
	fio.page = page;
	fio.new_blkaddr = fio.old_blkaddr = dn.data_blkaddr;

	if (lfs_mode)
		down_write(&fio.sbi->io_order_lock);

	mpage = f2fs_grab_cache_page(META_MAPPING(fio.sbi),
					fio.old_blkaddr, false);
	if (!mpage)
		goto up_out;

	fio.encrypted_page = mpage;

	/* read source block in mpage */
	if (!PageUptodate(mpage)) {
		err = f2fs_submit_page_bio(&fio);
		if (err) {
			f2fs_put_page(mpage, 1);
			goto up_out;
		}
		lock_page(mpage);
		if (unlikely(mpage->mapping != META_MAPPING(fio.sbi) ||
						!PageUptodate(mpage))) {
			err = -EIO;
			f2fs_put_page(mpage, 1);
			goto up_out;
		}
	}

	f2fs_allocate_data_block(fio.sbi, NULL, fio.old_blkaddr, &newaddr,
					&sum, CURSEG_COLD_DATA, NULL, false);

	fio.encrypted_page = f2fs_pagecache_get_page(META_MAPPING(fio.sbi),
				newaddr, FGP_LOCK | FGP_CREAT, GFP_NOFS);
	if (!fio.encrypted_page) {
		err = -ENOMEM;
		f2fs_put_page(mpage, 1);
		goto recover_block;
	}

	/* write target block */
	f2fs_wait_on_page_writeback(fio.encrypted_page, DATA, true, true);
	memcpy(page_address(fio.encrypted_page),
				page_address(mpage), PAGE_SIZE);
	f2fs_put_page(mpage, 1);
	invalidate_mapping_pages(META_MAPPING(fio.sbi),
				fio.old_blkaddr, fio.old_blkaddr);

	set_page_dirty(fio.encrypted_page);
	if (clear_page_dirty_for_io(fio.encrypted_page))
		dec_page_count(fio.sbi, F2FS_DIRTY_META);

	set_page_writeback(fio.encrypted_page);
	ClearPageError(page);

	/* allocate block address */
	f2fs_wait_on_page_writeback(dn.node_page, NODE, true, true);

	fio.op = REQ_OP_WRITE;
	fio.op_flags = REQ_SYNC;
	fio.new_blkaddr = newaddr;
	f2fs_submit_page_write(&fio);
	if (fio.retry) {
		err = -EAGAIN;
		if (PageWriteback(fio.encrypted_page))
			end_page_writeback(fio.encrypted_page);
		goto put_page_out;
	}

	f2fs_update_iostat(fio.sbi, FS_GC_DATA_IO, F2FS_BLKSIZE);

	f2fs_update_data_blkaddr(&dn, newaddr);
	set_inode_flag(inode, FI_APPEND_WRITE);
	if (page->index == 0)
		set_inode_flag(inode, FI_FIRST_BLOCK_WRITTEN);
put_page_out:
	f2fs_put_page(fio.encrypted_page, 1);
recover_block:
	if (err)
		f2fs_do_replace_block(fio.sbi, &sum, newaddr, fio.old_blkaddr,
								true, true);
up_out:
	if (lfs_mode)
		up_write(&fio.sbi->io_order_lock);
put_out:
	f2fs_put_dnode(&dn);
out:
	f2fs_put_page(page, 1);
	return err;
}

static int move_data_page(struct inode *inode, block_t bidx, int gc_type,
							unsigned int segno, int off)
{
	struct page *page;
	int err = 0;

	page = f2fs_get_lock_data_page(inode, bidx, true);
	if (IS_ERR(page))
		return PTR_ERR(page);

	if (!check_valid_map(F2FS_I_SB(inode), segno, off)) {
		err = -ENOENT;
		goto out;
	}

	if (f2fs_is_atomic_file(inode)) {
		F2FS_I(inode)->i_gc_failures[GC_FAILURE_ATOMIC]++;
		F2FS_I_SB(inode)->skipped_atomic_files[gc_type]++;
		err = -EAGAIN;
		goto out;
	}
	if (f2fs_is_pinned_file(inode)) {
		if (gc_type == FG_GC)
			f2fs_pin_file_control(inode, true);
		err = -EAGAIN;
		goto out;
	}

	if (gc_type == BG_GC) {
		if (PageWriteback(page))
			goto out;
		set_page_dirty(page);
		set_cold_data(page);
	} else {
		f2fs_wait_on_page_writeback(page, DATA);

		if (clear_page_dirty_for_io(page))
			inode_dec_dirty_pages(inode);
		set_cold_data(page);
		do_write_data_page(page, &fio);
		clear_cold_data(page);
	}
out:
	f2fs_put_page(page, 1);
}

/*
 * This function tries to get parent node of victim data block, and identifies
 * data block validity. If the block is valid, copy that with cold status and
 * modify parent node.
 * If the parent node is not valid or the data block address is different,
 * the victim data block is ignored.
 */
static void gc_data_segment(struct f2fs_sb_info *sbi, struct f2fs_summary *sum,
		struct list_head *ilist, unsigned int segno, int gc_type)
{
	struct super_block *sb = sbi->sb;
	struct f2fs_summary *entry;
	block_t start_addr;
	int off;
	int phase = 0;

	start_addr = START_BLOCK(sbi, segno);

next_step:
	entry = sum;

	for (off = 0; off < sbi->blocks_per_seg; off++, entry++) {
		struct page *data_page;
		struct inode *inode;
		struct node_info dni; /* dnode info for the data */
		unsigned int ofs_in_node, nofs;
		block_t start_bidx;

		/* stop BG_GC if there is not enough free sections. */
		if (gc_type == BG_GC && has_not_enough_free_secs(sbi, 0))
			return;

		if (check_valid_map(sbi, segno, off) == 0)
			continue;

		if (phase == 0) {
			ra_node_page(sbi, le32_to_cpu(entry->nid));
			continue;
		}

		/* Get an inode by ino with checking validity */
		if (check_dnode(sbi, entry, &dni, start_addr + off, &nofs) == 0)
			continue;

		if (phase == 1) {
			ra_node_page(sbi, dni.ino);
			continue;
		}

		ofs_in_node = le16_to_cpu(entry->ofs_in_node);

		if (phase == 2) {
			inode = f2fs_iget(sb, dni.ino);
			if (IS_ERR(inode) || is_bad_inode(inode))
				continue;

			start_bidx = start_bidx_of_node(nofs, F2FS_I(inode));

			data_page = find_data_page(inode,
					start_bidx + ofs_in_node, false);
			if (IS_ERR(data_page))
				goto next_iput;

			f2fs_put_page(data_page, 0);
			add_gc_inode(inode, ilist);
		} else {
			inode = find_gc_inode(dni.ino, ilist);
			if (inode) {
				start_bidx = start_bidx_of_node(nofs,
								F2FS_I(inode));
				data_page = get_lock_data_page(inode,
						start_bidx + ofs_in_node);
				if (IS_ERR(data_page))
					continue;
				move_data_page(inode, data_page, gc_type);
				stat_inc_data_blk_count(sbi, 1);
			}
		}
		continue;
next_iput:
		iput(inode);
	}

	if (++phase < 4)
		goto next_step;

	if (gc_type == FG_GC) {
		f2fs_submit_merged_bio(sbi, DATA, WRITE);

		/*
		 * In the case of FG_GC, it'd be better to reclaim this victim
		 * completely.
		 */
		if (get_valid_blocks(sbi, segno, 1) != 0) {
			phase = 2;
			goto next_step;
		}
	}
}

static int __get_victim(struct f2fs_sb_info *sbi, unsigned int *victim,
						int gc_type, int type)
{
	struct sit_info *sit_i = SIT_I(sbi);
	int ret;
	mutex_lock(&sit_i->sentry_lock);
	ret = DIRTY_I(sbi)->v_ops->get_victim(sbi, victim, gc_type, type, LFS);
	mutex_unlock(&sit_i->sentry_lock);
	return ret;
}

static void do_garbage_collect(struct f2fs_sb_info *sbi, unsigned int segno,
				struct list_head *ilist, int gc_type)
{
	struct page *sum_page;
	struct f2fs_summary_block *sum;
	struct blk_plug plug;

	/* read segment summary of victim */
	sum_page = get_sum_page(sbi, segno);

	blk_start_plug(&plug);

	for (segno = start_segno; segno < end_segno; segno++) {

		/* find segment summary of victim */
		sum_page = find_get_page(META_MAPPING(sbi),
					GET_SUM_BLOCK(sbi, segno));
		f2fs_put_page(sum_page, 0);

		if (get_valid_blocks(sbi, segno, false) == 0)
			goto freed;
		if (__is_large_section(sbi) &&
				migrated >= sbi->migration_granularity)
			goto skip;
		if (!PageUptodate(sum_page) || unlikely(f2fs_cp_error(sbi)))
			goto skip;

		sum = page_address(sum_page);
		if (type != GET_SUM_TYPE((&sum->footer))) {
			f2fs_err(sbi, "Inconsistent segment (%u) type [%d, %d] in SSA and SIT",
				 segno, type, GET_SUM_TYPE((&sum->footer)));
			set_sbi_flag(sbi, SBI_NEED_FSCK);
			f2fs_stop_checkpoint(sbi, false);
			goto skip;
		}

		/*
		 * this is to avoid deadlock:
		 * - lock_page(sum_page)         - f2fs_replace_block
		 *  - check_valid_map()            - down_write(sentry_lock)
		 *   - down_read(sentry_lock)     - change_curseg()
		 *                                  - lock_page(sum_page)
		 */
		if (type == SUM_TYPE_NODE)
			submitted += gc_node_segment(sbi, sum->entries, segno,
								gc_type);
		else
			submitted += gc_data_segment(sbi, sum->entries, gc_list,
							segno, gc_type);

		stat_inc_seg_count(sbi, type, gc_type);

	switch (GET_SUM_TYPE((&sum->footer))) {
	case SUM_TYPE_NODE:
		gc_node_segment(sbi, sum->entries, segno, gc_type);
		break;
	case SUM_TYPE_DATA:
		gc_data_segment(sbi, sum->entries, ilist, segno, gc_type);
		break;
	}
	blk_finish_plug(&plug);

	stat_inc_seg_count(sbi, GET_SUM_TYPE((&sum->footer)));
	stat_inc_call_count(sbi->stat_info);

	f2fs_put_page(sum_page, 1);
}

int f2fs_gc(struct f2fs_sb_info *sbi)
{
	struct list_head ilist;
	unsigned int segno, i;
	int gc_type = BG_GC;
	int nfree = 0;
	int ret = -1;
	struct cp_control cpc = {
		.reason = CP_SYNC,
	};

	INIT_LIST_HEAD(&ilist);
gc_more:
	if (unlikely(!(sbi->sb->s_flags & MS_ACTIVE)))
		goto stop;
	if (unlikely(f2fs_cp_error(sbi)))
		goto stop;

	if (gc_type == BG_GC && has_not_enough_free_secs(sbi, nfree)) {
		gc_type = FG_GC;
		write_checkpoint(sbi, &cpc);
	}

	if (!__get_victim(sbi, &segno, gc_type, NO_CHECK_TYPE))
		goto stop;
	ret = 0;

	/* readahead multi ssa blocks those have contiguous address */
	if (sbi->segs_per_sec > 1)
		ra_meta_pages(sbi, GET_SUM_BLOCK(sbi, segno), sbi->segs_per_sec,
								META_SSA);

	for (i = 0; i < sbi->segs_per_sec; i++)
		do_garbage_collect(sbi, segno + i, &ilist, gc_type);

	if (gc_type == FG_GC) {
		sbi->cur_victim_sec = NULL_SEGNO;
		nfree++;
		WARN_ON(get_valid_blocks(sbi, segno, sbi->segs_per_sec));
	}

	if (has_not_enough_free_secs(sbi, nfree))
		goto gc_more;

	if (gc_type == FG_GC)
		write_checkpoint(sbi, &cpc);
stop:
	mutex_unlock(&sbi->gc_mutex);

	put_gc_inode(&ilist);
	return ret;
}

void build_gc_manager(struct f2fs_sb_info *sbi)
{
	DIRTY_I(sbi)->v_ops = &default_v_ops;
}

int __init create_gc_caches(void)
{
	winode_slab = f2fs_kmem_cache_create("f2fs_gc_inodes",
			sizeof(struct inode_entry));
	if (!winode_slab)
		return -ENOMEM;
	return 0;
}

void destroy_gc_caches(void)
{
	kmem_cache_destroy(winode_slab);
}

static int free_segment_range(struct f2fs_sb_info *sbi, unsigned int start,
							unsigned int end)
{
	int type;
	unsigned int segno, next_inuse;
	int err = 0;

	/* Move out cursegs from the target range */
	for (type = CURSEG_HOT_DATA; type < NR_CURSEG_TYPE; type++)
		allocate_segment_for_resize(sbi, type, start, end);

	/* do GC to move out valid blocks in the range */
	for (segno = start; segno <= end; segno += sbi->segs_per_sec) {
		struct gc_inode_list gc_list = {
			.ilist = LIST_HEAD_INIT(gc_list.ilist),
			.iroot = RADIX_TREE_INIT(GFP_NOFS),
		};

		mutex_lock(&sbi->gc_mutex);
		do_garbage_collect(sbi, segno, &gc_list, FG_GC);
		mutex_unlock(&sbi->gc_mutex);
		put_gc_inode(&gc_list);

		if (get_valid_blocks(sbi, segno, true))
			return -EAGAIN;
	}

	err = f2fs_sync_fs(sbi->sb, 1);
	if (err)
		return err;

	next_inuse = find_next_inuse(FREE_I(sbi), end + 1, start);
	if (next_inuse <= end) {
		f2fs_err(sbi, "segno %u should be free but still inuse!",
			 next_inuse);
		f2fs_bug_on(sbi, 1);
	}
	return err;
}

static void update_sb_metadata(struct f2fs_sb_info *sbi, int secs)
{
	struct f2fs_super_block *raw_sb = F2FS_RAW_SUPER(sbi);
	int section_count = le32_to_cpu(raw_sb->section_count);
	int segment_count = le32_to_cpu(raw_sb->segment_count);
	int segment_count_main = le32_to_cpu(raw_sb->segment_count_main);
	long long block_count = le64_to_cpu(raw_sb->block_count);
	int segs = secs * sbi->segs_per_sec;

	raw_sb->section_count = cpu_to_le32(section_count + secs);
	raw_sb->segment_count = cpu_to_le32(segment_count + segs);
	raw_sb->segment_count_main = cpu_to_le32(segment_count_main + segs);
	raw_sb->block_count = cpu_to_le64(block_count +
					(long long)segs * sbi->blocks_per_seg);
}

static void update_fs_metadata(struct f2fs_sb_info *sbi, int secs)
{
	int segs = secs * sbi->segs_per_sec;
	long long user_block_count =
				le64_to_cpu(F2FS_CKPT(sbi)->user_block_count);

	SM_I(sbi)->segment_count = (int)SM_I(sbi)->segment_count + segs;
	MAIN_SEGS(sbi) = (int)MAIN_SEGS(sbi) + segs;
	FREE_I(sbi)->free_sections = (int)FREE_I(sbi)->free_sections + secs;
	FREE_I(sbi)->free_segments = (int)FREE_I(sbi)->free_segments + segs;
	F2FS_CKPT(sbi)->user_block_count = cpu_to_le64(user_block_count +
					(long long)segs * sbi->blocks_per_seg);
}

int f2fs_resize_fs(struct f2fs_sb_info *sbi, __u64 block_count)
{
	__u64 old_block_count, shrunk_blocks;
	unsigned int secs;
	int gc_mode, gc_type;
	int err = 0;
	__u32 rem;

	old_block_count = le64_to_cpu(F2FS_RAW_SUPER(sbi)->block_count);
	if (block_count > old_block_count)
		return -EINVAL;

	/* new fs size should align to section size */
	div_u64_rem(block_count, BLKS_PER_SEC(sbi), &rem);
	if (rem)
		return -EINVAL;

	if (block_count == old_block_count)
		return 0;

	if (is_sbi_flag_set(sbi, SBI_NEED_FSCK)) {
		f2fs_err(sbi, "Should run fsck to repair first.");
		return -EFSCORRUPTED;
	}

	if (test_opt(sbi, DISABLE_CHECKPOINT)) {
		f2fs_err(sbi, "Checkpoint should be enabled.");
		return -EINVAL;
	}

	freeze_bdev(sbi->sb->s_bdev);

	shrunk_blocks = old_block_count - block_count;
	secs = div_u64(shrunk_blocks, BLKS_PER_SEC(sbi));
	spin_lock(&sbi->stat_lock);
	if (shrunk_blocks + valid_user_blocks(sbi) +
		sbi->current_reserved_blocks + sbi->unusable_block_count +
		F2FS_OPTION(sbi).root_reserved_blocks > sbi->user_block_count)
		err = -ENOSPC;
	else
		sbi->user_block_count -= shrunk_blocks;
	spin_unlock(&sbi->stat_lock);
	if (err) {
		thaw_bdev(sbi->sb->s_bdev, sbi->sb);
		return err;
	}

	mutex_lock(&sbi->resize_mutex);
	set_sbi_flag(sbi, SBI_IS_RESIZEFS);

	mutex_lock(&DIRTY_I(sbi)->seglist_lock);

	MAIN_SECS(sbi) -= secs;

	for (gc_mode = 0; gc_mode < MAX_GC_POLICY; gc_mode++)
		if (SIT_I(sbi)->last_victim[gc_mode] >=
					MAIN_SECS(sbi) * sbi->segs_per_sec)
			SIT_I(sbi)->last_victim[gc_mode] = 0;

	for (gc_type = BG_GC; gc_type <= FG_GC; gc_type++)
		if (sbi->next_victim_seg[gc_type] >=
					MAIN_SECS(sbi) * sbi->segs_per_sec)
			sbi->next_victim_seg[gc_type] = NULL_SEGNO;

	mutex_unlock(&DIRTY_I(sbi)->seglist_lock);

	err = free_segment_range(sbi, MAIN_SECS(sbi) * sbi->segs_per_sec,
			MAIN_SEGS(sbi) - 1);
	if (err)
		goto out;

	update_sb_metadata(sbi, -secs);

	err = f2fs_commit_super(sbi, false);
	if (err) {
		update_sb_metadata(sbi, secs);
		goto out;
	}

	update_fs_metadata(sbi, -secs);
	clear_sbi_flag(sbi, SBI_IS_RESIZEFS);
	err = f2fs_sync_fs(sbi->sb, 1);
	if (err) {
		update_fs_metadata(sbi, secs);
		update_sb_metadata(sbi, secs);
		f2fs_commit_super(sbi, false);
	}
out:
	if (err) {
		set_sbi_flag(sbi, SBI_NEED_FSCK);
		f2fs_err(sbi, "resize_fs failed, should run fsck to repair!");

		MAIN_SECS(sbi) += secs;
		spin_lock(&sbi->stat_lock);
		sbi->user_block_count += shrunk_blocks;
		spin_unlock(&sbi->stat_lock);
	}
	clear_sbi_flag(sbi, SBI_IS_RESIZEFS);
	mutex_unlock(&sbi->resize_mutex);
	thaw_bdev(sbi->sb->s_bdev, sbi->sb);
	return err;
}

static int free_segment_range(struct f2fs_sb_info *sbi, unsigned int start,
							unsigned int end)
{
	int type;
	unsigned int segno, next_inuse;
	int err = 0;

	/* Move out cursegs from the target range */
	for (type = CURSEG_HOT_DATA; type < NR_CURSEG_TYPE; type++)
		allocate_segment_for_resize(sbi, type, start, end);

	/* do GC to move out valid blocks in the range */
	for (segno = start; segno <= end; segno += sbi->segs_per_sec) {
		struct gc_inode_list gc_list = {
			.ilist = LIST_HEAD_INIT(gc_list.ilist),
			.iroot = RADIX_TREE_INIT(GFP_NOFS),
		};

		mutex_lock(&sbi->gc_mutex);
		do_garbage_collect(sbi, segno, &gc_list, FG_GC);
		mutex_unlock(&sbi->gc_mutex);
		put_gc_inode(&gc_list);

		if (get_valid_blocks(sbi, segno, true))
			return -EAGAIN;
	}

	err = f2fs_sync_fs(sbi->sb, 1);
	if (err)
		return err;

	next_inuse = find_next_inuse(FREE_I(sbi), end + 1, start);
	if (next_inuse <= end) {
		f2fs_err(sbi, "segno %u should be free but still inuse!",
			 next_inuse);
		f2fs_bug_on(sbi, 1);
	}
	return err;
}

static void update_sb_metadata(struct f2fs_sb_info *sbi, int secs)
{
	struct f2fs_super_block *raw_sb = F2FS_RAW_SUPER(sbi);
	int section_count = le32_to_cpu(raw_sb->section_count);
	int segment_count = le32_to_cpu(raw_sb->segment_count);
	int segment_count_main = le32_to_cpu(raw_sb->segment_count_main);
	long long block_count = le64_to_cpu(raw_sb->block_count);
	int segs = secs * sbi->segs_per_sec;

	raw_sb->section_count = cpu_to_le32(section_count + secs);
	raw_sb->segment_count = cpu_to_le32(segment_count + segs);
	raw_sb->segment_count_main = cpu_to_le32(segment_count_main + segs);
	raw_sb->block_count = cpu_to_le64(block_count +
					(long long)segs * sbi->blocks_per_seg);
}

static void update_fs_metadata(struct f2fs_sb_info *sbi, int secs)
{
	int segs = secs * sbi->segs_per_sec;
	long long user_block_count =
				le64_to_cpu(F2FS_CKPT(sbi)->user_block_count);

	SM_I(sbi)->segment_count = (int)SM_I(sbi)->segment_count + segs;
	MAIN_SEGS(sbi) = (int)MAIN_SEGS(sbi) + segs;
	FREE_I(sbi)->free_sections = (int)FREE_I(sbi)->free_sections + secs;
	FREE_I(sbi)->free_segments = (int)FREE_I(sbi)->free_segments + segs;
	F2FS_CKPT(sbi)->user_block_count = cpu_to_le64(user_block_count +
					(long long)segs * sbi->blocks_per_seg);
}

int f2fs_resize_fs(struct f2fs_sb_info *sbi, __u64 block_count)
{
	__u64 old_block_count, shrunk_blocks;
	unsigned int secs;
	int gc_mode, gc_type;
	int err = 0;
	__u32 rem;

	old_block_count = le64_to_cpu(F2FS_RAW_SUPER(sbi)->block_count);
	if (block_count > old_block_count)
		return -EINVAL;

	/* new fs size should align to section size */
	div_u64_rem(block_count, BLKS_PER_SEC(sbi), &rem);
	if (rem)
		return -EINVAL;

	if (block_count == old_block_count)
		return 0;

	if (is_sbi_flag_set(sbi, SBI_NEED_FSCK)) {
		f2fs_err(sbi, "Should run fsck to repair first.");
		return -EFSCORRUPTED;
	}

	if (test_opt(sbi, DISABLE_CHECKPOINT)) {
		f2fs_err(sbi, "Checkpoint should be enabled.");
		return -EINVAL;
	}

	freeze_bdev(sbi->sb->s_bdev);

	shrunk_blocks = old_block_count - block_count;
	secs = div_u64(shrunk_blocks, BLKS_PER_SEC(sbi));
	spin_lock(&sbi->stat_lock);
	if (shrunk_blocks + valid_user_blocks(sbi) +
		sbi->current_reserved_blocks + sbi->unusable_block_count +
		F2FS_OPTION(sbi).root_reserved_blocks > sbi->user_block_count)
		err = -ENOSPC;
	else
		sbi->user_block_count -= shrunk_blocks;
	spin_unlock(&sbi->stat_lock);
	if (err) {
		thaw_bdev(sbi->sb->s_bdev, sbi->sb);
		return err;
	}

	mutex_lock(&sbi->resize_mutex);
	set_sbi_flag(sbi, SBI_IS_RESIZEFS);

	mutex_lock(&DIRTY_I(sbi)->seglist_lock);

	MAIN_SECS(sbi) -= secs;

	for (gc_mode = 0; gc_mode < MAX_GC_POLICY; gc_mode++)
		if (SIT_I(sbi)->last_victim[gc_mode] >=
					MAIN_SECS(sbi) * sbi->segs_per_sec)
			SIT_I(sbi)->last_victim[gc_mode] = 0;

	for (gc_type = BG_GC; gc_type <= FG_GC; gc_type++)
		if (sbi->next_victim_seg[gc_type] >=
					MAIN_SECS(sbi) * sbi->segs_per_sec)
			sbi->next_victim_seg[gc_type] = NULL_SEGNO;

	mutex_unlock(&DIRTY_I(sbi)->seglist_lock);

	err = free_segment_range(sbi, MAIN_SECS(sbi) * sbi->segs_per_sec,
			MAIN_SEGS(sbi) - 1);
	if (err)
		goto out;

	update_sb_metadata(sbi, -secs);

	err = f2fs_commit_super(sbi, false);
	if (err) {
		update_sb_metadata(sbi, secs);
		goto out;
	}

	update_fs_metadata(sbi, -secs);
	clear_sbi_flag(sbi, SBI_IS_RESIZEFS);
	err = f2fs_sync_fs(sbi->sb, 1);
	if (err) {
		update_fs_metadata(sbi, secs);
		update_sb_metadata(sbi, secs);
		f2fs_commit_super(sbi, false);
	}
out:
	if (err) {
		set_sbi_flag(sbi, SBI_NEED_FSCK);
		f2fs_err(sbi, "resize_fs failed, should run fsck to repair!");

		MAIN_SECS(sbi) += secs;
		spin_lock(&sbi->stat_lock);
		sbi->user_block_count += shrunk_blocks;
		spin_unlock(&sbi->stat_lock);
	}
	clear_sbi_flag(sbi, SBI_IS_RESIZEFS);
	mutex_unlock(&sbi->resize_mutex);
	thaw_bdev(sbi->sb->s_bdev, sbi->sb);
	return err;
}
