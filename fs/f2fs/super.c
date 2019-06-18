/*
 * fs/f2fs/super.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/statfs.h>
#include <linux/buffer_head.h>
#include <linux/backing-dev.h>
#include <linux/kthread.h>
#include <linux/parser.h>
#include <linux/mount.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include <linux/exportfs.h>
#include <linux/blkdev.h>
#include <linux/f2fs_fs.h>
#include <linux/sysfs.h>

#include "f2fs.h"
#include "node.h"
#include "segment.h"
#include "xattr.h"
#include "gc.h"

#define CREATE_TRACE_POINTS
#include <trace/events/f2fs.h>

static struct proc_dir_entry *f2fs_proc_root;
static struct kmem_cache *f2fs_inode_cachep;
static struct kset *f2fs_kset;

enum {
	Opt_gc_background,
	Opt_disable_roll_forward,
	Opt_discard,
	Opt_noheap,
	Opt_user_xattr,
	Opt_nouser_xattr,
	Opt_acl,
	Opt_noacl,
	Opt_active_logs,
	Opt_disable_ext_identify,
	Opt_inline_xattr,
	Opt_inline_data,
	Opt_flush_merge,
	Opt_nobarrier,
	Opt_err,
};

static match_table_t f2fs_tokens = {
	{Opt_gc_background, "background_gc=%s"},
	{Opt_disable_roll_forward, "disable_roll_forward"},
	{Opt_discard, "discard"},
	{Opt_noheap, "no_heap"},
	{Opt_user_xattr, "user_xattr"},
	{Opt_nouser_xattr, "nouser_xattr"},
	{Opt_acl, "acl"},
	{Opt_noacl, "noacl"},
	{Opt_active_logs, "active_logs=%u"},
	{Opt_disable_ext_identify, "disable_ext_identify"},
	{Opt_inline_xattr, "inline_xattr"},
	{Opt_inline_data, "inline_data"},
	{Opt_flush_merge, "flush_merge"},
	{Opt_nobarrier, "nobarrier"},
	{Opt_err, NULL},
};

void f2fs_printk(struct f2fs_sb_info *sbi, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;
	int level;

	va_start(args, fmt);

	level = printk_get_level(fmt);
	vaf.fmt = printk_skip_level(fmt);
	vaf.va = &args;
	printk("%c%cF2FS-fs (%s): %pV\n",
	       KERN_SOH_ASCII, level, sbi->sb->s_id, &vaf);

	va_end(args);
}

static unsigned char *__struct_ptr(struct f2fs_sb_info *sbi, int struct_type)
{
	block_t limit = min((sbi->user_block_count << 1) / 1000,
			sbi->user_block_count - sbi->reserved_blocks);

	/* limit is 0.2% */
	if (test_opt(sbi, RESERVE_ROOT) &&
			F2FS_OPTION(sbi).root_reserved_blocks > limit) {
		F2FS_OPTION(sbi).root_reserved_blocks = limit;
		f2fs_info(sbi, "Reduce reserved blocks for root = %u",
			  F2FS_OPTION(sbi).root_reserved_blocks);
	}
	if (!test_opt(sbi, RESERVE_ROOT) &&
		(!uid_eq(F2FS_OPTION(sbi).s_resuid,
				make_kuid(&init_user_ns, F2FS_DEF_RESUID)) ||
		!gid_eq(F2FS_OPTION(sbi).s_resgid,
				make_kgid(&init_user_ns, F2FS_DEF_RESGID))))
		f2fs_info(sbi, "Ignore s_resuid=%u, s_resgid=%u w/o reserve_root",
			  from_kuid_munged(&init_user_ns,
					   F2FS_OPTION(sbi).s_resuid),
			  from_kgid_munged(&init_user_ns,
					   F2FS_OPTION(sbi).s_resgid));
}

static ssize_t f2fs_sbi_show(struct f2fs_attr *a,
			struct f2fs_sb_info *sbi, char *buf)
{
	unsigned char *ptr = NULL;
	unsigned int *ui;

	ptr = __struct_ptr(sbi, a->struct_type);
	if (!ptr)
		return -EINVAL;

	ui = (unsigned int *)(ptr + a->offset);

	return snprintf(buf, PAGE_SIZE, "%u\n", *ui);
}

static ssize_t f2fs_sbi_store(struct f2fs_attr *a,
			struct f2fs_sb_info *sbi,
			const char *buf, size_t count)
{
	unsigned char *ptr;
	unsigned long t;
	unsigned int *ui;
	ssize_t ret;

	ptr = __struct_ptr(sbi, a->struct_type);
	if (!ptr)
		return -EINVAL;

	if (sb_any_quota_loaded(sb) && !F2FS_OPTION(sbi).s_qf_names[qtype]) {
		f2fs_err(sbi, "Cannot change journaled quota options when quota turned on");
		return -EINVAL;
	}
	if (f2fs_sb_has_quota_ino(sbi)) {
		f2fs_info(sbi, "QUOTA feature is enabled, so ignore qf_name");
		return 0;
	}

	qname = match_strdup(args);
	if (!qname) {
		f2fs_err(sbi, "Not enough memory for storing quotafile name");
		return -ENOMEM;
	}
	if (F2FS_OPTION(sbi).s_qf_names[qtype]) {
		if (strcmp(F2FS_OPTION(sbi).s_qf_names[qtype], qname) == 0)
			ret = 0;
		else
			f2fs_err(sbi, "%s quota file already specified",
				 QTYPE2NAME(qtype));
		goto errout;
	}
	if (strchr(qname, '/')) {
		f2fs_err(sbi, "quotafile must be on filesystem root");
		goto errout;
	}
	F2FS_OPTION(sbi).s_qf_names[qtype] = qname;
	set_opt(sbi, QUOTA);
	return 0;
errout:
	kvfree(qname);
	return ret;
}

static const struct sysfs_ops f2fs_attr_ops = {
	.show	= f2fs_attr_show,
	.store	= f2fs_attr_store,
};

static struct kobj_type f2fs_ktype = {
	.default_attrs	= f2fs_attrs,
	.sysfs_ops	= &f2fs_attr_ops,
	.release	= f2fs_sb_release,
};

	if (sb_any_quota_loaded(sb) && F2FS_OPTION(sbi).s_qf_names[qtype]) {
		f2fs_err(sbi, "Cannot change journaled quota options when quota turned on");
		return -EINVAL;
	}
	kvfree(F2FS_OPTION(sbi).s_qf_names[qtype]);
	F2FS_OPTION(sbi).s_qf_names[qtype] = NULL;
	return 0;
}

static void init_once(void *foo)
{
	/*
	 * We do the test below only for project quotas. 'usrquota' and
	 * 'grpquota' mount options are allowed even without quota feature
	 * to support legacy quotas in quota files.
	 */
	if (F2FS_MAXQUOTAS > 2 && test_opt(sbi, PRJQUOTA) &&
					!f2fs_sb_has_project_quota(sbi)) {
		f2fs_err(sbi, "Project quota feature not enabled. Cannot enable project quota enforcement.");
		return -1;
	}
	if (F2FS_OPTION(sbi).s_qf_names[USRQUOTA] ||
			F2FS_OPTION(sbi).s_qf_names[GRPQUOTA] ||
			(F2FS_MAXQUOTAS > 2 &&
				F2FS_OPTION(sbi).s_qf_names[PRJQUOTA])) {
		if (test_opt(sbi, USRQUOTA) &&
				F2FS_OPTION(sbi).s_qf_names[USRQUOTA])
			clear_opt(sbi, USRQUOTA);

		if (test_opt(sbi, GRPQUOTA) &&
				F2FS_OPTION(sbi).s_qf_names[GRPQUOTA])
			clear_opt(sbi, GRPQUOTA);

		if (F2FS_MAXQUOTAS > 2 && test_opt(sbi, PRJQUOTA) &&
				F2FS_OPTION(sbi).s_qf_names[PRJQUOTA])
			clear_opt(sbi, PRJQUOTA);

		if (test_opt(sbi, GRPQUOTA) || test_opt(sbi, USRQUOTA) ||
				test_opt(sbi, PRJQUOTA)) {
			f2fs_err(sbi, "old and new quota format mixing");
			return -1;
		}

		if (!F2FS_OPTION(sbi).s_jquota_fmt) {
			f2fs_err(sbi, "journaled quota format not specified");
			return -1;
		}
	}

	if (f2fs_sb_has_quota_ino(sbi) && F2FS_OPTION(sbi).s_jquota_fmt) {
		f2fs_info(sbi, "QUOTA feature is enabled, so ignore jquota_fmt");
		F2FS_OPTION(sbi).s_jquota_fmt = 0;
	}
	return 0;
}

static int parse_options(struct super_block *sb, char *options)
{
	struct f2fs_sb_info *sbi = F2FS_SB(sb);
	substring_t args[MAX_OPT_ARGS];
	char *p, *name;
	int arg = 0;

	if (!options)
		return 0;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;
		if (!*p)
			continue;
		/*
		 * Initialize args struct so we know whether arg was
		 * found; some options take optional arguments.
		 */
		args[0].to = args[0].from = NULL;
		token = match_token(p, f2fs_tokens, args);

		switch (token) {
		case Opt_gc_background:
			name = match_strdup(&args[0]);

			if (!name)
				return -ENOMEM;
			if (strlen(name) == 2 && !strncmp(name, "on", 2))
				set_opt(sbi, BG_GC);
			else if (strlen(name) == 3 && !strncmp(name, "off", 3))
				clear_opt(sbi, BG_GC);
			else {
				kfree(name);
				return -EINVAL;
			}
			kfree(name);
			break;
		case Opt_disable_roll_forward:
			set_opt(sbi, DISABLE_ROLL_FORWARD);
			break;
		case Opt_discard:
			set_opt(sbi, DISCARD);
			break;
		case Opt_nodiscard:
			if (f2fs_sb_has_blkzoned(sbi)) {
				f2fs_warn(sbi, "discard is required for zoned block devices");
				return -EINVAL;
			}
			clear_opt(sbi, DISCARD);
			break;
		case Opt_noheap:
			set_opt(sbi, NOHEAP);
			break;
#ifdef CONFIG_F2FS_FS_XATTR
		case Opt_user_xattr:
			set_opt(sbi, XATTR_USER);
			break;
		case Opt_nouser_xattr:
			clear_opt(sbi, XATTR_USER);
			break;
		case Opt_inline_xattr:
			set_opt(sbi, INLINE_XATTR);
			break;
#else
		case Opt_user_xattr:
			f2fs_info(sbi, "user_xattr options not supported");
			break;
		case Opt_nouser_xattr:
			f2fs_info(sbi, "nouser_xattr options not supported");
			break;
		case Opt_inline_xattr:
			f2fs_info(sbi, "inline_xattr options not supported");
			break;
		case Opt_noinline_xattr:
			f2fs_info(sbi, "noinline_xattr options not supported");
			break;
#endif
#ifdef CONFIG_F2FS_FS_POSIX_ACL
		case Opt_acl:
			set_opt(sbi, POSIX_ACL);
			break;
		case Opt_noacl:
			clear_opt(sbi, POSIX_ACL);
			break;
#else
		case Opt_acl:
			f2fs_info(sbi, "acl options not supported");
			break;
		case Opt_noacl:
			f2fs_info(sbi, "noacl options not supported");
			break;
#endif
		case Opt_active_logs:
			if (args->from && match_int(args, &arg))
				return -EINVAL;
			if (arg != 2 && arg != 4 && arg != NR_CURSEG_TYPE)
				return -EINVAL;
			sbi->active_logs = arg;
			break;
		case Opt_disable_ext_identify:
			set_opt(sbi, DISABLE_EXT_IDENTIFY);
			break;
		case Opt_inline_data:
			set_opt(sbi, INLINE_DATA);
			break;
		case Opt_flush_merge:
			set_opt(sbi, FLUSH_MERGE);
			break;
		case Opt_nobarrier:
			set_opt(sbi, NOBARRIER);
			break;
		case Opt_fastboot:
			set_opt(sbi, FASTBOOT);
			break;
		case Opt_extent_cache:
			set_opt(sbi, EXTENT_CACHE);
			break;
		case Opt_noextent_cache:
			clear_opt(sbi, EXTENT_CACHE);
			break;
		case Opt_noinline_data:
			clear_opt(sbi, INLINE_DATA);
			break;
		case Opt_data_flush:
			set_opt(sbi, DATA_FLUSH);
			break;
		case Opt_reserve_root:
			if (args->from && match_int(args, &arg))
				return -EINVAL;
			if (test_opt(sbi, RESERVE_ROOT)) {
				f2fs_info(sbi, "Preserve previous reserve_root=%u",
					  F2FS_OPTION(sbi).root_reserved_blocks);
			} else {
				F2FS_OPTION(sbi).root_reserved_blocks = arg;
				set_opt(sbi, RESERVE_ROOT);
			}
			break;
		case Opt_resuid:
			if (args->from && match_int(args, &arg))
				return -EINVAL;
			uid = make_kuid(current_user_ns(), arg);
			if (!uid_valid(uid)) {
				f2fs_err(sbi, "Invalid uid value %d", arg);
				return -EINVAL;
			}
			F2FS_OPTION(sbi).s_resuid = uid;
			break;
		case Opt_resgid:
			if (args->from && match_int(args, &arg))
				return -EINVAL;
			gid = make_kgid(current_user_ns(), arg);
			if (!gid_valid(gid)) {
				f2fs_err(sbi, "Invalid gid value %d", arg);
				return -EINVAL;
			}
			F2FS_OPTION(sbi).s_resgid = gid;
			break;
		case Opt_mode:
			name = match_strdup(&args[0]);

			if (!name)
				return -ENOMEM;
			if (strlen(name) == 8 &&
					!strncmp(name, "adaptive", 8)) {
				if (f2fs_sb_has_blkzoned(sbi)) {
					f2fs_warn(sbi, "adaptive mode is not allowed with zoned block device feature");
					kvfree(name);
					return -EINVAL;
				}
				set_opt_mode(sbi, F2FS_MOUNT_ADAPTIVE);
			} else if (strlen(name) == 3 &&
					!strncmp(name, "lfs", 3)) {
				set_opt_mode(sbi, F2FS_MOUNT_LFS);
			} else {
				kvfree(name);
				return -EINVAL;
			}
			kvfree(name);
			break;
		case Opt_io_size_bits:
			if (args->from && match_int(args, &arg))
				return -EINVAL;
			if (arg <= 0 || arg > __ilog2_u32(BIO_MAX_PAGES)) {
				f2fs_warn(sbi, "Not support %d, larger than %d",
					  1 << arg, BIO_MAX_PAGES);
				return -EINVAL;
			}
			F2FS_OPTION(sbi).write_io_size_bits = arg;
			break;
#ifdef CONFIG_F2FS_FAULT_INJECTION
		case Opt_fault_injection:
			if (args->from && match_int(args, &arg))
				return -EINVAL;
			f2fs_build_fault_attr(sbi, arg, F2FS_ALL_FAULT_TYPE);
			set_opt(sbi, FAULT_INJECTION);
			break;

		case Opt_fault_type:
			if (args->from && match_int(args, &arg))
				return -EINVAL;
			f2fs_build_fault_attr(sbi, 0, arg);
			set_opt(sbi, FAULT_INJECTION);
			break;
#else
		case Opt_fault_injection:
			f2fs_info(sbi, "fault_injection options not supported");
			break;

		case Opt_fault_type:
			f2fs_info(sbi, "fault_type options not supported");
			break;
#endif
		case Opt_lazytime:
			sb->s_flags |= MS_LAZYTIME;
			break;
		case Opt_nolazytime:
			sb->s_flags &= ~MS_LAZYTIME;
			break;
#ifdef CONFIG_QUOTA
		case Opt_quota:
		case Opt_usrquota:
			set_opt(sbi, USRQUOTA);
			break;
		case Opt_grpquota:
			set_opt(sbi, GRPQUOTA);
			break;
		case Opt_prjquota:
			if (F2FS_MAXQUOTAS <= 2) {
				f2fs_info(sbi, "prjquota operations not supported");
				return -EINVAL;
			}
			set_opt(sbi, PRJQUOTA);
			break;
		case Opt_usrjquota:
			ret = f2fs_set_qf_name(sb, USRQUOTA, &args[0]);
			if (ret)
				return ret;
			break;
		case Opt_grpjquota:
			ret = f2fs_set_qf_name(sb, GRPQUOTA, &args[0]);
			if (ret)
				return ret;
			break;
		case Opt_prjjquota:
			ret = f2fs_set_qf_name(sb, PRJQUOTA, &args[0]);
			if (ret)
				return ret;
			break;
		case Opt_offusrjquota:
			ret = f2fs_clear_qf_name(sb, USRQUOTA);
			if (ret)
				return ret;
			break;
		case Opt_offgrpjquota:
			ret = f2fs_clear_qf_name(sb, GRPQUOTA);
			if (ret)
				return ret;
			break;
		case Opt_offprjjquota:
			ret = f2fs_clear_qf_name(sb, PRJQUOTA);
			if (ret)
				return ret;
			break;
		case Opt_jqfmt_vfsold:
			F2FS_OPTION(sbi).s_jquota_fmt = QFMT_VFS_OLD;
			break;
		case Opt_jqfmt_vfsv0:
			F2FS_OPTION(sbi).s_jquota_fmt = QFMT_VFS_V0;
			break;
		case Opt_jqfmt_vfsv1:
			F2FS_OPTION(sbi).s_jquota_fmt = QFMT_VFS_V1;
			break;
		case Opt_noquota:
			clear_opt(sbi, QUOTA);
			clear_opt(sbi, USRQUOTA);
			clear_opt(sbi, GRPQUOTA);
			clear_opt(sbi, PRJQUOTA);
			break;
#else
		case Opt_quota:
		case Opt_usrquota:
		case Opt_grpquota:
		case Opt_prjquota:
		case Opt_usrjquota:
		case Opt_grpjquota:
		case Opt_prjjquota:
		case Opt_offusrjquota:
		case Opt_offgrpjquota:
		case Opt_offprjjquota:
		case Opt_jqfmt_vfsold:
		case Opt_jqfmt_vfsv0:
		case Opt_jqfmt_vfsv1:
		case Opt_noquota:
			f2fs_info(sbi, "quota operations not supported");
			break;
#endif
		case Opt_whint:
			name = match_strdup(&args[0]);
			if (!name)
				return -ENOMEM;
			if (strlen(name) == 10 &&
					!strncmp(name, "user-based", 10)) {
				F2FS_OPTION(sbi).whint_mode = WHINT_MODE_USER;
			} else if (strlen(name) == 3 &&
					!strncmp(name, "off", 3)) {
				F2FS_OPTION(sbi).whint_mode = WHINT_MODE_OFF;
			} else if (strlen(name) == 8 &&
					!strncmp(name, "fs-based", 8)) {
				F2FS_OPTION(sbi).whint_mode = WHINT_MODE_FS;
			} else {
				kvfree(name);
				return -EINVAL;
			}
			kvfree(name);
			break;
		case Opt_alloc:
			name = match_strdup(&args[0]);
			if (!name)
				return -ENOMEM;

			if (strlen(name) == 7 &&
					!strncmp(name, "default", 7)) {
				F2FS_OPTION(sbi).alloc_mode = ALLOC_MODE_DEFAULT;
			} else if (strlen(name) == 5 &&
					!strncmp(name, "reuse", 5)) {
				F2FS_OPTION(sbi).alloc_mode = ALLOC_MODE_REUSE;
			} else {
				kvfree(name);
				return -EINVAL;
			}
			kvfree(name);
			break;
		case Opt_fsync:
			name = match_strdup(&args[0]);
			if (!name)
				return -ENOMEM;
			if (strlen(name) == 5 &&
					!strncmp(name, "posix", 5)) {
				F2FS_OPTION(sbi).fsync_mode = FSYNC_MODE_POSIX;
			} else if (strlen(name) == 6 &&
					!strncmp(name, "strict", 6)) {
				F2FS_OPTION(sbi).fsync_mode = FSYNC_MODE_STRICT;
			} else if (strlen(name) == 9 &&
					!strncmp(name, "nobarrier", 9)) {
				F2FS_OPTION(sbi).fsync_mode =
							FSYNC_MODE_NOBARRIER;
			} else {
				kvfree(name);
				return -EINVAL;
			}
			kvfree(name);
			break;
		case Opt_test_dummy_encryption:
#ifdef CONFIG_F2FS_FS_ENCRYPTION
			if (!f2fs_sb_has_encrypt(sbi)) {
				f2fs_err(sbi, "Encrypt feature is off");
				return -EINVAL;
			}

			F2FS_OPTION(sbi).test_dummy_encryption = true;
			f2fs_info(sbi, "Test dummy encryption mode enabled");
#else
			f2fs_info(sbi, "Test dummy encryption mount option ignored");
#endif
			break;
		case Opt_checkpoint_disable_cap_perc:
			if (args->from && match_int(args, &arg))
				return -EINVAL;
			if (arg < 0 || arg > 100)
				return -EINVAL;
			if (arg == 100)
				F2FS_OPTION(sbi).unusable_cap =
					sbi->user_block_count;
			else
				F2FS_OPTION(sbi).unusable_cap =
					(sbi->user_block_count / 100) *	arg;
			set_opt(sbi, DISABLE_CHECKPOINT);
			break;
		case Opt_checkpoint_disable_cap:
			if (args->from && match_int(args, &arg))
				return -EINVAL;
			F2FS_OPTION(sbi).unusable_cap = arg;
			set_opt(sbi, DISABLE_CHECKPOINT);
			break;
		case Opt_checkpoint_disable:
			set_opt(sbi, DISABLE_CHECKPOINT);
			break;
		case Opt_checkpoint_enable:
			clear_opt(sbi, DISABLE_CHECKPOINT);
			break;
		default:
			f2fs_err(sbi, "Unrecognized mount option \"%s\" or missing value",
				 p);
			return -EINVAL;
		}
	}
#ifdef CONFIG_QUOTA
	if (f2fs_check_quota_options(sbi))
		return -EINVAL;
#else
	if (f2fs_sb_has_quota_ino(sbi) && !f2fs_readonly(sbi->sb)) {
		f2fs_info(sbi, "Filesystem with quota feature cannot be mounted RDWR without CONFIG_QUOTA");
		return -EINVAL;
	}
	if (f2fs_sb_has_project_quota(sbi) && !f2fs_readonly(sbi->sb)) {
		f2fs_err(sbi, "Filesystem with project quota feature cannot be mounted RDWR without CONFIG_QUOTA");
		return -EINVAL;
	}
#endif

	if (F2FS_IO_SIZE_BITS(sbi) && !test_opt(sbi, LFS)) {
		f2fs_err(sbi, "Should set mode=lfs with %uKB-sized IO",
			 F2FS_IO_SIZE_KB(sbi));
		return -EINVAL;
	}

	if (test_opt(sbi, INLINE_XATTR_SIZE)) {
		int min_size, max_size;

		if (!f2fs_sb_has_extra_attr(sbi) ||
			!f2fs_sb_has_flexible_inline_xattr(sbi)) {
			f2fs_err(sbi, "extra_attr or flexible_inline_xattr feature is off");
			return -EINVAL;
		}
		if (!test_opt(sbi, INLINE_XATTR)) {
			f2fs_err(sbi, "inline_xattr_size option should be set with inline_xattr option");
			return -EINVAL;
		}

		min_size = sizeof(struct f2fs_xattr_header) / sizeof(__le32);
		max_size = MAX_INLINE_XATTR_SIZE;

		if (F2FS_OPTION(sbi).inline_xattr_size < min_size ||
				F2FS_OPTION(sbi).inline_xattr_size > max_size) {
			f2fs_err(sbi, "inline xattr size is out of range: %d ~ %d",
				 min_size, max_size);
			return -EINVAL;
		}
	}

	if (test_opt(sbi, DISABLE_CHECKPOINT) && test_opt(sbi, LFS)) {
		f2fs_err(sbi, "LFS not compatible with checkpoint=disable\n");
		return -EINVAL;
	}

	/* Not pass down write hints if the number of active logs is lesser
	 * than NR_CURSEG_TYPE.
	 */
	if (F2FS_OPTION(sbi).active_logs != NR_CURSEG_TYPE)
		F2FS_OPTION(sbi).whint_mode = WHINT_MODE_OFF;
	return 0;
}

static struct inode *f2fs_alloc_inode(struct super_block *sb)
{
	struct f2fs_inode_info *fi;

	fi = kmem_cache_alloc(f2fs_inode_cachep, GFP_F2FS_ZERO);
	if (!fi)
		return NULL;

	init_once((void *) fi);

	/* Initialize f2fs-specific inode info */
	fi->vfs_inode.i_version = 1;
	atomic_set(&fi->dirty_pages, 0);
	fi->i_current_depth = 1;
	fi->i_advise = 0;
	rwlock_init(&fi->ext.ext_lock);
	init_rwsem(&fi->i_sem);
	INIT_LIST_HEAD(&fi->inmem_pages);
	mutex_init(&fi->inmem_lock);

	set_inode_flag(fi, FI_NEW_INODE);

	if (test_opt(F2FS_SB(sb), INLINE_XATTR))
		set_inode_flag(fi, FI_INLINE_XATTR);

	/* Will be used by directory only */
	fi->i_dir_level = F2FS_SB(sb)->dir_level;

	return &fi->vfs_inode;
}

static int f2fs_drop_inode(struct inode *inode)
{
	/*
	 * This is to avoid a deadlock condition like below.
	 * writeback_single_inode(inode)
	 *  - f2fs_write_data_page
	 *    - f2fs_gc -> iput -> evict
	 *       - inode_wait_for_writeback(inode)
	 */
	if (!inode_unhashed(inode) && inode->i_state & I_SYNC)
		return 0;
	return generic_drop_inode(inode);
}

/*
 * f2fs_dirty_inode() is called from __mark_inode_dirty()
 *
 * We should call set_dirty_inode to write the dirty inode through write_inode.
 */
static void f2fs_dirty_inode(struct inode *inode, int flags)
{
	set_inode_flag(F2FS_I(inode), FI_DIRTY_INODE);
}

static void f2fs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(f2fs_inode_cachep, F2FS_I(inode));
}

static void f2fs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, f2fs_i_callback);
}

static void f2fs_put_super(struct super_block *sb)
{
	struct f2fs_sb_info *sbi = F2FS_SB(sb);

	if (sbi->s_proc) {
		remove_proc_entry("segment_info", sbi->s_proc);
		remove_proc_entry(sb->s_id, f2fs_proc_root);
	}
	kobject_del(&sbi->s_kobj);

	f2fs_destroy_stats(sbi);
	stop_gc_thread(sbi);

	/* We don't need to do checkpoint when it's clean */
	if (sbi->s_dirty) {
		struct cp_control cpc = {
			.reason = CP_UMOUNT,
		};
		f2fs_write_checkpoint(sbi, &cpc);
	}

	/*
	 * normally superblock is clean, so we need to release this.
	 * In addition, EIO will skip do checkpoint, we need this as well.
	 */
	f2fs_release_ino_entry(sbi, true);

	f2fs_leave_shrinker(sbi);
	mutex_unlock(&sbi->umount_mutex);

	/* our cp_error case, we can wait for any writeback page */
	f2fs_flush_merged_writes(sbi);

	f2fs_wait_on_all_pages_writeback(sbi);

	f2fs_bug_on(sbi, sbi->fsync_node_num);

	iput(sbi->node_inode);
	sbi->node_inode = NULL;

	iput(sbi->meta_inode);
	sbi->meta_inode = NULL;

	/*
	 * iput() can update stat information, if f2fs_write_checkpoint()
	 * above failed with error.
	 */
	f2fs_destroy_stats(sbi);

	/* destroy f2fs internal modules */
	f2fs_destroy_node_manager(sbi);
	f2fs_destroy_segment_manager(sbi);

	kvfree(sbi->ckpt);

	f2fs_unregister_sysfs(sbi);

	sb->s_fs_info = NULL;
	if (sbi->s_chksum_driver)
		crypto_free_shash(sbi->s_chksum_driver);
	kvfree(sbi->raw_super);

	destroy_device_list(sbi);
	if (sbi->write_io_dummy)
		mempool_destroy(sbi->write_io_dummy);
#ifdef CONFIG_QUOTA
	for (i = 0; i < F2FS_MAXQUOTAS; i++)
		kvfree(F2FS_OPTION(sbi).s_qf_names[i]);
#endif
	destroy_percpu_info(sbi);
	for (i = 0; i < NR_PAGE_TYPE; i++)
		kvfree(sbi->write_io[i]);
	kvfree(sbi);
}

int f2fs_sync_fs(struct super_block *sb, int sync)
{
	struct f2fs_sb_info *sbi = F2FS_SB(sb);
	int err = 0;

	if (unlikely(f2fs_cp_error(sbi)))
		return 0;
	if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED)))
		return 0;

	trace_f2fs_sync_fs(sb, sync);

	if (unlikely(is_sbi_flag_set(sbi, SBI_POR_DOING)))
		return -EAGAIN;

	if (sync) {
		struct cp_control cpc;

		cpc.reason = __get_cp_reason(sbi);

		mutex_lock(&sbi->gc_mutex);
		err = f2fs_write_checkpoint(sbi, &cpc);
		mutex_unlock(&sbi->gc_mutex);
	}
	f2fs_trace_ios(NULL, 1);

	return err;
}

static int f2fs_freeze(struct super_block *sb)
{
	if (f2fs_readonly(sb))
		return 0;

	/* IO error happened before */
	if (unlikely(f2fs_cp_error(F2FS_SB(sb))))
		return -EIO;

	/* must be clean, since sync_filesystem() was already called */
	if (is_sbi_flag_set(F2FS_SB(sb), SBI_IS_DIRTY))
		return -EINVAL;
	return 0;
}

static int f2fs_unfreeze(struct super_block *sb)
{
	return 0;
}

#ifdef CONFIG_QUOTA
static int f2fs_statfs_project(struct super_block *sb,
				kprojid_t projid, struct kstatfs *buf)
{
	struct kqid qid;
	struct dquot *dquot;
	u64 limit;
	u64 curblock;

	qid = make_kqid_projid(projid);
	dquot = dqget(sb, qid);
	if (IS_ERR(dquot))
		return PTR_ERR(dquot);
	spin_lock(&dq_data_lock);

	limit = (dquot->dq_dqb.dqb_bsoftlimit ?
		 dquot->dq_dqb.dqb_bsoftlimit :
		 dquot->dq_dqb.dqb_bhardlimit) >> sb->s_blocksize_bits;
	if (limit && buf->f_blocks > limit) {
		curblock = dquot->dq_dqb.dqb_curspace >> sb->s_blocksize_bits;
		buf->f_blocks = limit;
		buf->f_bfree = buf->f_bavail =
			(buf->f_blocks > curblock) ?
			 (buf->f_blocks - curblock) : 0;
	}

	limit = dquot->dq_dqb.dqb_isoftlimit ?
		dquot->dq_dqb.dqb_isoftlimit :
		dquot->dq_dqb.dqb_ihardlimit;
	if (limit && buf->f_files > limit) {
		buf->f_files = limit;
		buf->f_ffree =
			(buf->f_files > dquot->dq_dqb.dqb_curinodes) ?
			 (buf->f_files - dquot->dq_dqb.dqb_curinodes) : 0;
	}

	spin_unlock(&dq_data_lock);
	dqput(dquot);
	return 0;
}
#endif

static int f2fs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct f2fs_sb_info *sbi = F2FS_SB(sb);
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);
	block_t total_count, user_block_count, start_count;
	u64 avail_node_count;

	total_count = le64_to_cpu(sbi->raw_super->block_count);
	user_block_count = sbi->user_block_count;
	start_count = le32_to_cpu(sbi->raw_super->segment0_blkaddr);
	buf->f_type = F2FS_SUPER_MAGIC;
	buf->f_bsize = sbi->blocksize;

	buf->f_blocks = total_count - start_count;
	buf->f_bfree = user_block_count - valid_user_blocks(sbi) -
						sbi->current_reserved_blocks;

	spin_lock(&sbi->stat_lock);
	if (unlikely(buf->f_bfree <= sbi->unusable_block_count))
		buf->f_bfree = 0;
	else
		buf->f_bfree -= sbi->unusable_block_count;
	spin_unlock(&sbi->stat_lock);

	if (buf->f_bfree > F2FS_OPTION(sbi).root_reserved_blocks)
		buf->f_bavail = buf->f_bfree -
				F2FS_OPTION(sbi).root_reserved_blocks;
	else
		buf->f_bavail = 0;

	avail_node_count = sbi->total_node_count - sbi->nquota_files -
						F2FS_RESERVED_NODE_NUM;

	if (avail_node_count > user_block_count) {
		buf->f_files = user_block_count;
		buf->f_ffree = buf->f_bavail;
	} else {
		buf->f_files = avail_node_count;
		buf->f_ffree = min(avail_node_count - valid_node_count(sbi),
					buf->f_bavail);
	}

	buf->f_namelen = F2FS_NAME_LEN;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);

#ifdef CONFIG_QUOTA
	if (is_inode_flag_set(dentry->d_inode, FI_PROJ_INHERIT) &&
			sb_has_quota_limits_enabled(sb, PRJQUOTA)) {
		f2fs_statfs_project(sb, F2FS_I(dentry->d_inode)->i_projid, buf);
	}
#endif
	return 0;
}

static inline void f2fs_show_quota_options(struct seq_file *seq,
					   struct super_block *sb)
{
#ifdef CONFIG_QUOTA
	struct f2fs_sb_info *sbi = F2FS_SB(sb);

	if (F2FS_OPTION(sbi).s_jquota_fmt) {
		char *fmtname = "";

		switch (F2FS_OPTION(sbi).s_jquota_fmt) {
		case QFMT_VFS_OLD:
			fmtname = "vfsold";
			break;
		case QFMT_VFS_V0:
			fmtname = "vfsv0";
			break;
		case QFMT_VFS_V1:
			fmtname = "vfsv1";
			break;
		}
		seq_printf(seq, ",jqfmt=%s", fmtname);
	}

	if (F2FS_OPTION(sbi).s_qf_names[USRQUOTA])
		seq_show_option(seq, "usrjquota",
			F2FS_OPTION(sbi).s_qf_names[USRQUOTA]);

	if (F2FS_OPTION(sbi).s_qf_names[GRPQUOTA])
		seq_show_option(seq, "grpjquota",
			F2FS_OPTION(sbi).s_qf_names[GRPQUOTA]);

	if (F2FS_MAXQUOTAS > 2 && F2FS_OPTION(sbi).s_qf_names[PRJQUOTA])
		seq_show_option(seq, "prjjquota",
			F2FS_OPTION(sbi).s_qf_names[PRJQUOTA]);
#endif
}

static int f2fs_show_options(struct seq_file *seq, struct dentry *root)
{
	struct f2fs_sb_info *sbi = F2FS_SB(root->d_sb);

	if (!f2fs_readonly(sbi->sb) && test_opt(sbi, BG_GC)) {
		if (test_opt(sbi, FORCE_FG_GC))
			seq_printf(seq, ",background_gc=%s", "sync");
		else
			seq_printf(seq, ",background_gc=%s", "on");
	} else {
		seq_printf(seq, ",background_gc=%s", "off");
	}
	if (test_opt(sbi, DISABLE_ROLL_FORWARD))
		seq_puts(seq, ",disable_roll_forward");
	if (test_opt(sbi, DISCARD))
		seq_puts(seq, ",discard");
	else
		seq_puts(seq, ",nodiscard");
	if (test_opt(sbi, NOHEAP))
		seq_puts(seq, ",no_heap");
	else
		seq_puts(seq, ",heap");
#ifdef CONFIG_F2FS_FS_XATTR
	if (test_opt(sbi, XATTR_USER))
		seq_puts(seq, ",user_xattr");
	else
		seq_puts(seq, ",nouser_xattr");
	if (test_opt(sbi, INLINE_XATTR))
		seq_puts(seq, ",inline_xattr");
	else
		seq_puts(seq, ",noinline_xattr");
	if (test_opt(sbi, INLINE_XATTR_SIZE))
		seq_printf(seq, ",inline_xattr_size=%u",
					F2FS_OPTION(sbi).inline_xattr_size);
#endif
#ifdef CONFIG_F2FS_FS_POSIX_ACL
	if (test_opt(sbi, POSIX_ACL))
		seq_puts(seq, ",acl");
	else
		seq_puts(seq, ",noacl");
#endif
	if (test_opt(sbi, DISABLE_EXT_IDENTIFY))
		seq_puts(seq, ",disable_ext_identify");
	if (test_opt(sbi, INLINE_DATA))
		seq_puts(seq, ",inline_data");
	else
		seq_puts(seq, ",noinline_data");
	if (test_opt(sbi, INLINE_DENTRY))
		seq_puts(seq, ",inline_dentry");
	else
		seq_puts(seq, ",noinline_dentry");
	if (!f2fs_readonly(sbi->sb) && test_opt(sbi, FLUSH_MERGE))
		seq_puts(seq, ",flush_merge");
	if (test_opt(sbi, NOBARRIER))
		seq_puts(seq, ",nobarrier");
	if (test_opt(sbi, FASTBOOT))
		seq_puts(seq, ",fastboot");
	if (test_opt(sbi, EXTENT_CACHE))
		seq_puts(seq, ",extent_cache");
	else
		seq_puts(seq, ",noextent_cache");
	if (test_opt(sbi, DATA_FLUSH))
		seq_puts(seq, ",data_flush");

	seq_puts(seq, ",mode=");
	if (test_opt(sbi, ADAPTIVE))
		seq_puts(seq, "adaptive");
	else if (test_opt(sbi, LFS))
		seq_puts(seq, "lfs");
	seq_printf(seq, ",active_logs=%u", F2FS_OPTION(sbi).active_logs);
	if (test_opt(sbi, RESERVE_ROOT))
		seq_printf(seq, ",reserve_root=%u,resuid=%u,resgid=%u",
				F2FS_OPTION(sbi).root_reserved_blocks,
				from_kuid_munged(&init_user_ns,
					F2FS_OPTION(sbi).s_resuid),
				from_kgid_munged(&init_user_ns,
					F2FS_OPTION(sbi).s_resgid));
	if (F2FS_IO_SIZE_BITS(sbi))
		seq_printf(seq, ",io_bits=%u",
				F2FS_OPTION(sbi).write_io_size_bits);
#ifdef CONFIG_F2FS_FAULT_INJECTION
	if (test_opt(sbi, FAULT_INJECTION)) {
		seq_printf(seq, ",fault_injection=%u",
				F2FS_OPTION(sbi).fault_info.inject_rate);
		seq_printf(seq, ",fault_type=%u",
				F2FS_OPTION(sbi).fault_info.inject_type);
	}
#endif
#ifdef CONFIG_QUOTA
	if (test_opt(sbi, QUOTA))
		seq_puts(seq, ",quota");
	if (test_opt(sbi, USRQUOTA))
		seq_puts(seq, ",usrquota");
	if (test_opt(sbi, GRPQUOTA))
		seq_puts(seq, ",grpquota");
	if (test_opt(sbi, PRJQUOTA))
		seq_puts(seq, ",prjquota");
#endif
	f2fs_show_quota_options(seq, sbi->sb);
	if (F2FS_OPTION(sbi).whint_mode == WHINT_MODE_USER)
		seq_printf(seq, ",whint_mode=%s", "user-based");
	else if (F2FS_OPTION(sbi).whint_mode == WHINT_MODE_FS)
		seq_printf(seq, ",whint_mode=%s", "fs-based");
#ifdef CONFIG_F2FS_FS_ENCRYPTION
	if (F2FS_OPTION(sbi).test_dummy_encryption)
		seq_puts(seq, ",test_dummy_encryption");
#endif

	if (F2FS_OPTION(sbi).alloc_mode == ALLOC_MODE_DEFAULT)
		seq_printf(seq, ",alloc_mode=%s", "default");
	else if (F2FS_OPTION(sbi).alloc_mode == ALLOC_MODE_REUSE)
		seq_printf(seq, ",alloc_mode=%s", "reuse");

	if (test_opt(sbi, DISABLE_CHECKPOINT))
		seq_printf(seq, ",checkpoint=disable:%u",
				F2FS_OPTION(sbi).unusable_cap);
	if (F2FS_OPTION(sbi).fsync_mode == FSYNC_MODE_POSIX)
		seq_printf(seq, ",fsync_mode=%s", "posix");
	else if (F2FS_OPTION(sbi).fsync_mode == FSYNC_MODE_STRICT)
		seq_printf(seq, ",fsync_mode=%s", "strict");
	else if (F2FS_OPTION(sbi).fsync_mode == FSYNC_MODE_NOBARRIER)
		seq_printf(seq, ",fsync_mode=%s", "nobarrier");
	return 0;
}

static void default_options(struct f2fs_sb_info *sbi)
{
	/* init some FS parameters */
	F2FS_OPTION(sbi).active_logs = NR_CURSEG_TYPE;
	F2FS_OPTION(sbi).inline_xattr_size = DEFAULT_INLINE_XATTR_ADDRS;
	F2FS_OPTION(sbi).whint_mode = WHINT_MODE_OFF;
	F2FS_OPTION(sbi).alloc_mode = ALLOC_MODE_DEFAULT;
	F2FS_OPTION(sbi).fsync_mode = FSYNC_MODE_POSIX;
	F2FS_OPTION(sbi).test_dummy_encryption = false;
	F2FS_OPTION(sbi).s_resuid = make_kuid(&init_user_ns, F2FS_DEF_RESUID);
	F2FS_OPTION(sbi).s_resgid = make_kgid(&init_user_ns, F2FS_DEF_RESGID);

	set_opt(sbi, BG_GC);
	set_opt(sbi, INLINE_XATTR);
	set_opt(sbi, INLINE_DATA);
	set_opt(sbi, INLINE_DENTRY);
	set_opt(sbi, EXTENT_CACHE);
	set_opt(sbi, NOHEAP);
	sbi->sb->s_flags |= MS_LAZYTIME;
	clear_opt(sbi, DISABLE_CHECKPOINT);
	F2FS_OPTION(sbi).unusable_cap = 0;
	set_opt(sbi, FLUSH_MERGE);
	set_opt(sbi, DISCARD);
	if (f2fs_sb_has_blkzoned(sbi))
		set_opt_mode(sbi, F2FS_MOUNT_LFS);
	else
		set_opt_mode(sbi, F2FS_MOUNT_ADAPTIVE);

#ifdef CONFIG_F2FS_FS_XATTR
	set_opt(sbi, XATTR_USER);
#endif
#ifdef CONFIG_F2FS_FS_POSIX_ACL
	set_opt(sbi, POSIX_ACL);
#endif

	f2fs_build_fault_attr(sbi, 0, 0);
}

#ifdef CONFIG_QUOTA
static int f2fs_enable_quotas(struct super_block *sb);
#endif

static int f2fs_disable_checkpoint(struct f2fs_sb_info *sbi)
{
	unsigned int s_flags = sbi->sb->s_flags;
	struct cp_control cpc;
	int err = 0;
	int ret;
	block_t unusable;

	if (s_flags & MS_RDONLY) {
		f2fs_err(sbi, "checkpoint=disable on readonly fs");
		return -EINVAL;
	}
	sbi->sb->s_flags |= MS_ACTIVE;

	f2fs_update_time(sbi, DISABLE_TIME);

	while (!f2fs_time_over(sbi, DISABLE_TIME)) {
		mutex_lock(&sbi->gc_mutex);
		err = f2fs_gc(sbi, true, false, NULL_SEGNO);
		if (err == -ENODATA) {
			err = 0;
			break;
		}
		if (err && err != -EAGAIN)
			break;
	}

	ret = sync_filesystem(sbi->sb);
	if (ret || err) {
		err = ret ? ret: err;
		goto restore_flag;
	}

	unusable = f2fs_get_unusable_blocks(sbi);
	if (f2fs_disable_cp_again(sbi, unusable)) {
		err = -EAGAIN;
		goto restore_flag;
	}

	mutex_lock(&sbi->gc_mutex);
	cpc.reason = CP_PAUSE;
	set_sbi_flag(sbi, SBI_CP_DISABLED);
	err = f2fs_write_checkpoint(sbi, &cpc);
	if (err)
		goto out_unlock;

	spin_lock(&sbi->stat_lock);
	sbi->unusable_block_count = unusable;
	spin_unlock(&sbi->stat_lock);

out_unlock:
	mutex_unlock(&sbi->gc_mutex);
restore_flag:
	sbi->sb->s_flags = s_flags;	/* Restore MS_RDONLY status */
	return err;
}

static void f2fs_enable_checkpoint(struct f2fs_sb_info *sbi)
{
	mutex_lock(&sbi->gc_mutex);
	f2fs_dirty_to_prefree(sbi);

	clear_sbi_flag(sbi, SBI_CP_DISABLED);
	set_sbi_flag(sbi, SBI_IS_DIRTY);
	mutex_unlock(&sbi->gc_mutex);

	f2fs_sync_fs(sbi->sb, 1);
}

static int f2fs_remount(struct super_block *sb, int *flags, char *data)
{
	struct f2fs_sb_info *sbi = F2FS_SB(sb);
	struct f2fs_mount_info org_mount_opt;
	unsigned long old_sb_flags;
	int err;
	bool need_restart_gc = false;
	bool need_stop_gc = false;
	bool no_extent_cache = !test_opt(sbi, EXTENT_CACHE);
	bool disable_checkpoint = test_opt(sbi, DISABLE_CHECKPOINT);
	bool checkpoint_changed;
#ifdef CONFIG_QUOTA
	int i, j;
#endif

	/*
	 * Save the old mount options in case we
	 * need to restore them.
	 */
	org_mount_opt = sbi->mount_opt;
	old_sb_flags = sb->s_flags;

#ifdef CONFIG_QUOTA
	org_mount_opt.s_jquota_fmt = F2FS_OPTION(sbi).s_jquota_fmt;
	for (i = 0; i < F2FS_MAXQUOTAS; i++) {
		if (F2FS_OPTION(sbi).s_qf_names[i]) {
			org_mount_opt.s_qf_names[i] =
				kstrdup(F2FS_OPTION(sbi).s_qf_names[i],
				GFP_KERNEL);
			if (!org_mount_opt.s_qf_names[i]) {
				for (j = 0; j < i; j++)
					kvfree(org_mount_opt.s_qf_names[j]);
				return -ENOMEM;
			}
		} else {
			org_mount_opt.s_qf_names[i] = NULL;
		}
	}
#endif

	/* recover superblocks we couldn't write due to previous RO mount */
	if (!(*flags & MS_RDONLY) && is_sbi_flag_set(sbi, SBI_NEED_SB_WRITE)) {
		err = f2fs_commit_super(sbi, false);
		f2fs_info(sbi, "Try to recover all the superblocks, ret: %d",
			  err);
		if (!err)
			clear_sbi_flag(sbi, SBI_NEED_SB_WRITE);
	}

	default_options(sbi);

	/* parse mount options */
	err = parse_options(sb, data);
	if (err)
		goto restore_opts;
	checkpoint_changed =
			disable_checkpoint != test_opt(sbi, DISABLE_CHECKPOINT);

	/*
	 * Previous and new state of filesystem is RO,
	 * so skip checking GC and FLUSH_MERGE conditions.
	 */
	if (f2fs_readonly(sb) && (*flags & MS_RDONLY))
		goto skip;

#ifdef CONFIG_QUOTA
	if (!f2fs_readonly(sb) && (*flags & MS_RDONLY)) {
		err = dquot_suspend(sb, -1);
		if (err < 0)
			goto restore_opts;
	} else if (f2fs_readonly(sb) && !(*flags & MS_RDONLY)) {
		/* dquot_resume needs RW */
		sb->s_flags &= ~MS_RDONLY;
		if (sb_any_quota_suspended(sb)) {
			dquot_resume(sb, -1);
		} else if (f2fs_sb_has_quota_ino(sbi)) {
			err = f2fs_enable_quotas(sb);
			if (err)
				goto restore_opts;
		}
	}
#endif
	/* disallow enable/disable extent_cache dynamically */
	if (no_extent_cache == !!test_opt(sbi, EXTENT_CACHE)) {
		err = -EINVAL;
		f2fs_warn(sbi, "switch extent_cache option is not allowed");
		goto restore_opts;
	}

	if ((*flags & MS_RDONLY) && test_opt(sbi, DISABLE_CHECKPOINT)) {
		err = -EINVAL;
		f2fs_warn(sbi, "disabling checkpoint not compatible with read-only");
		goto restore_opts;
	}

	/*
	 * We stop the GC thread if FS is mounted as RO
	 * or if background_gc = off is passed in mount
	 * option. Also sync the filesystem.
	 */
	if ((*flags & MS_RDONLY) || !test_opt(sbi, BG_GC)) {
		if (sbi->gc_thread) {
			f2fs_stop_gc_thread(sbi);
			need_restart_gc = true;
		}
	} else if (!sbi->gc_thread) {
		err = f2fs_start_gc_thread(sbi);
		if (err)
			goto restore_opts;
		need_stop_gc = true;
	}

	if (*flags & MS_RDONLY ||
		F2FS_OPTION(sbi).whint_mode != org_mount_opt.whint_mode) {
		writeback_inodes_sb(sb, WB_REASON_SYNC);
		sync_inodes_sb(sb);

		set_sbi_flag(sbi, SBI_IS_DIRTY);
		set_sbi_flag(sbi, SBI_IS_CLOSE);
		f2fs_sync_fs(sb, 1);
		clear_sbi_flag(sbi, SBI_IS_CLOSE);
	}

	if (checkpoint_changed) {
		if (test_opt(sbi, DISABLE_CHECKPOINT)) {
			err = f2fs_disable_checkpoint(sbi);
			if (err)
				goto restore_gc;
		} else {
			f2fs_enable_checkpoint(sbi);
		}
	}

	/*
	 * We stop issue flush thread if FS is mounted as RO
	 * or if flush_merge is not passed in mount option.
	 */
	if ((*flags & MS_RDONLY) || !test_opt(sbi, FLUSH_MERGE)) {
		clear_opt(sbi, FLUSH_MERGE);
		f2fs_destroy_flush_cmd_control(sbi, false);
	} else {
		err = f2fs_create_flush_cmd_control(sbi);
		if (err)
			goto restore_gc;
	}
skip:
#ifdef CONFIG_QUOTA
	/* Release old quota file names */
	for (i = 0; i < F2FS_MAXQUOTAS; i++)
		kvfree(org_mount_opt.s_qf_names[i]);
#endif
	/* Update the POSIXACL Flag */
	sb->s_flags = (sb->s_flags & ~MS_POSIXACL) |
		(test_opt(sbi, POSIX_ACL) ? MS_POSIXACL : 0);

	limit_reserve_root(sbi);
	*flags = (*flags & ~MS_LAZYTIME) | (sb->s_flags & MS_LAZYTIME);
	return 0;
restore_gc:
	if (need_restart_gc) {
		if (f2fs_start_gc_thread(sbi))
			f2fs_warn(sbi, "background gc thread has stopped");
	} else if (need_stop_gc) {
		f2fs_stop_gc_thread(sbi);
	}
restore_opts:
#ifdef CONFIG_QUOTA
	F2FS_OPTION(sbi).s_jquota_fmt = org_mount_opt.s_jquota_fmt;
	for (i = 0; i < F2FS_MAXQUOTAS; i++) {
		kvfree(F2FS_OPTION(sbi).s_qf_names[i]);
		F2FS_OPTION(sbi).s_qf_names[i] = org_mount_opt.s_qf_names[i];
	}
#endif
	sbi->mount_opt = org_mount_opt;
	sb->s_flags = old_sb_flags;
	return err;
}

#ifdef CONFIG_QUOTA
/* Read data from quotafile */
static ssize_t f2fs_quota_read(struct super_block *sb, int type, char *data,
			       size_t len, loff_t off)
{
	struct inode *inode = sb_dqopt(sb)->files[type];
	struct address_space *mapping = inode->i_mapping;
	block_t blkidx = F2FS_BYTES_TO_BLK(off);
	int offset = off & (sb->s_blocksize - 1);
	int tocopy;
	size_t toread;
	loff_t i_size = i_size_read(inode);
	struct page *page;
	char *kaddr;

	if (off > i_size)
		return 0;

	if (off + len > i_size)
		len = i_size - off;
	toread = len;
	while (toread > 0) {
		tocopy = min_t(unsigned long, sb->s_blocksize - offset, toread);
repeat:
		page = read_cache_page_gfp(mapping, blkidx, GFP_NOFS);
		if (IS_ERR(page)) {
			if (PTR_ERR(page) == -ENOMEM) {
				congestion_wait(BLK_RW_ASYNC, HZ/50);
				goto repeat;
			}
			set_sbi_flag(F2FS_SB(sb), SBI_QUOTA_NEED_REPAIR);
			return PTR_ERR(page);
		}

		lock_page(page);

		if (unlikely(page->mapping != mapping)) {
			f2fs_put_page(page, 1);
			goto repeat;
		}
		if (unlikely(!PageUptodate(page))) {
			f2fs_put_page(page, 1);
			set_sbi_flag(F2FS_SB(sb), SBI_QUOTA_NEED_REPAIR);
			return -EIO;
		}

		kaddr = kmap_atomic(page);
		memcpy(data, kaddr + offset, tocopy);
		kunmap_atomic(kaddr);
		f2fs_put_page(page, 1);

		offset = 0;
		toread -= tocopy;
		data += tocopy;
		blkidx++;
	}
	return len;
}

/* Write to quotafile */
static ssize_t f2fs_quota_write(struct super_block *sb, int type,
				const char *data, size_t len, loff_t off)
{
	struct inode *inode = sb_dqopt(sb)->files[type];
	struct address_space *mapping = inode->i_mapping;
	const struct address_space_operations *a_ops = mapping->a_ops;
	int offset = off & (sb->s_blocksize - 1);
	size_t towrite = len;
	struct page *page;
	char *kaddr;
	int err = 0;
	int tocopy;

	while (towrite > 0) {
		tocopy = min_t(unsigned long, sb->s_blocksize - offset,
								towrite);
retry:
		err = a_ops->write_begin(NULL, mapping, off, tocopy, 0,
							&page, NULL);
		if (unlikely(err)) {
			if (err == -ENOMEM) {
				congestion_wait(BLK_RW_ASYNC, HZ/50);
				goto retry;
			}
			set_sbi_flag(F2FS_SB(sb), SBI_QUOTA_NEED_REPAIR);
			break;
		}

		kaddr = kmap_atomic(page);
		memcpy(kaddr + offset, data, tocopy);
		kunmap_atomic(kaddr);
		flush_dcache_page(page);

		a_ops->write_end(NULL, mapping, off, tocopy, tocopy,
						page, NULL);
		offset = 0;
		towrite -= tocopy;
		off += tocopy;
		data += tocopy;
		cond_resched();
	}

	if (len == towrite)
		return err;
	inode->i_mtime = inode->i_ctime = current_time(inode);
	f2fs_mark_inode_dirty_sync(inode, false);
	return len - towrite;
}

static qsize_t *f2fs_get_reserved_space(struct inode *inode)
{
	return &F2FS_I(inode)->i_reserved_quota;
}

static int f2fs_quota_on_mount(struct f2fs_sb_info *sbi, int type)
{
	if (is_set_ckpt_flags(sbi, CP_QUOTA_NEED_FSCK_FLAG)) {
		f2fs_err(sbi, "quota sysfile may be corrupted, skip loading it");
		return 0;
	}

	return dquot_quota_on_mount(sbi->sb, F2FS_OPTION(sbi).s_qf_names[type],
					F2FS_OPTION(sbi).s_jquota_fmt, type);
}

int f2fs_enable_quota_files(struct f2fs_sb_info *sbi, bool rdonly)
{
	int enabled = 0;
	int i, err;

	if (f2fs_sb_has_quota_ino(sbi) && rdonly) {
		err = f2fs_enable_quotas(sbi->sb);
		if (err) {
			f2fs_err(sbi, "Cannot turn on quota_ino: %d", err);
			return 0;
		}
		return 1;
	}

	for (i = 0; i < F2FS_MAXQUOTAS; i++) {
		if (F2FS_OPTION(sbi).s_qf_names[i]) {
			err = f2fs_quota_on_mount(sbi, i);
			if (!err) {
				enabled = 1;
				continue;
			}
			f2fs_err(sbi, "Cannot turn on quotas: %d on %d",
				 err, i);
		}
	}
	return enabled;
}

static int f2fs_quota_enable(struct super_block *sb, int type, int format_id,
			     unsigned int flags)
{
	struct inode *qf_inode;
	unsigned long qf_inum;
	int err;

	BUG_ON(!f2fs_sb_has_quota_ino(F2FS_SB(sb)));

	qf_inum = f2fs_qf_ino(sb, type);
	if (!qf_inum)
		return -EPERM;

	qf_inode = f2fs_iget(sb, qf_inum);
	if (IS_ERR(qf_inode)) {
		f2fs_err(F2FS_SB(sb), "Bad quota inode %u:%lu", type, qf_inum);
		return PTR_ERR(qf_inode);
	}

	/* Don't account quota for quota files to avoid recursion */
	qf_inode->i_flags |= S_NOQUOTA;
	err = dquot_enable(qf_inode, type, format_id, flags);
	iput(qf_inode);
	return err;
}

static int f2fs_enable_quotas(struct super_block *sb)
{
	struct f2fs_sb_info *sbi = F2FS_SB(sb);
	int type, err = 0;
	unsigned long qf_inum;
	bool quota_mopt[MAXQUOTAS] = {
		test_opt(sbi, USRQUOTA),
		test_opt(sbi, GRPQUOTA),
#if 0	/* not support */
		test_opt(F2FS_SB(sb), PRJQUOTA),
#endif
	};

	if (is_set_ckpt_flags(F2FS_SB(sb), CP_QUOTA_NEED_FSCK_FLAG)) {
		f2fs_err(sbi, "quota file may be corrupted, skip loading it");
		return 0;
	}

	sb_dqopt(sb)->flags |= DQUOT_QUOTA_SYS_FILE;

	for (type = 0; type < MAXQUOTAS; type++) {
		qf_inum = f2fs_qf_ino(sb, type);
		if (qf_inum) {
			err = f2fs_quota_enable(sb, type, QFMT_VFS_V1,
				DQUOT_USAGE_ENABLED |
				(quota_mopt[type] ? DQUOT_LIMITS_ENABLED : 0));
			if (err) {
				f2fs_err(sbi, "Failed to enable quota tracking (type=%d, err=%d). Please run fsck to fix.",
					 type, err);
				for (type--; type >= 0; type--)
					dquot_quota_off(sb, type);
				set_sbi_flag(F2FS_SB(sb),
						SBI_QUOTA_NEED_REPAIR);
				return err;
			}
		}
	}
	return 0;
}

int f2fs_quota_sync(struct super_block *sb, int type)
{
	struct f2fs_sb_info *sbi = F2FS_SB(sb);
	struct quota_info *dqopt = sb_dqopt(sb);
	int cnt;
	int ret;

	ret = dquot_writeback_dquots(sb, type);
	if (ret)
		goto out;

	/*
	 * Now when everything is written we can discard the pagecache so
	 * that userspace sees the changes.
	 */
	for (cnt = 0; cnt < F2FS_MAXQUOTAS; cnt++) {
		struct address_space *mapping;

		if (type != -1 && cnt != type)
			continue;
		if (!sb_has_quota_active(sb, cnt))
			continue;

	/*
	 * normally superblock is clean, so we need to release this.
	 * In addition, EIO will skip do checkpoint, we need this as well.
	 */
	release_dirty_inode(sbi);
	release_discard_addrs(sbi);

	iput(sbi->node_inode);
	iput(sbi->meta_inode);

	/* destroy f2fs internal modules */
	destroy_node_manager(sbi);
	destroy_segment_manager(sbi);

	kfree(sbi->ckpt);
	kobject_put(&sbi->s_kobj);
	wait_for_completion(&sbi->s_kobj_unregister);

	sb->s_fs_info = NULL;
	brelse(sbi->raw_super_buf);
	kfree(sbi);
}

int f2fs_sync_fs(struct super_block *sb, int sync)
{
	struct f2fs_sb_info *sbi = F2FS_SB(sb);

	trace_f2fs_sync_fs(sb, sync);

	if (sync) {
		struct cp_control cpc = {
			.reason = CP_SYNC,
		};
		mutex_lock(&sbi->gc_mutex);
		write_checkpoint(sbi, &cpc);
		mutex_unlock(&sbi->gc_mutex);
	} else {
		f2fs_balance_fs(sbi);
	}

	return 0;
}

static int f2fs_freeze(struct super_block *sb)
{
	int err;

	if (f2fs_readonly(sb))
		return 0;

	err = f2fs_sync_fs(sb, 1);
	return err;
}

static int f2fs_unfreeze(struct super_block *sb)
{
	return 0;
}

static int f2fs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct f2fs_sb_info *sbi = F2FS_SB(sb);
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);
	block_t total_count, user_block_count, start_count, ovp_count;

	total_count = le64_to_cpu(sbi->raw_super->block_count);
	user_block_count = sbi->user_block_count;
	start_count = le32_to_cpu(sbi->raw_super->segment0_blkaddr);
	ovp_count = SM_I(sbi)->ovp_segments << sbi->log_blocks_per_seg;
	buf->f_type = F2FS_SUPER_MAGIC;
	buf->f_bsize = sbi->blocksize;

			f2fs_err(F2FS_SB(sb), "Fail to turn off disk quota (type: %d, err: %d, ret:%d), Please run fsck to fix it.",
				 type, err, ret);
			set_sbi_flag(F2FS_SB(sb), SBI_QUOTA_NEED_REPAIR);
		}
	}
	/*
	 * In case of checkpoint=disable, we must flush quota blocks.
	 * This can cause NULL exception for node_inode in end_io, since
	 * put_super already dropped it.
	 */
	sync_filesystem(sb);
}

	buf->f_files = sbi->total_node_count - F2FS_RESERVED_NODE_NUM;
	buf->f_ffree = buf->f_files - valid_inode_count(sbi);

	buf->f_namelen = F2FS_NAME_LEN;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);

	return 0;
}

static int f2fs_show_options(struct seq_file *seq, struct dentry *root)
{
	struct f2fs_sb_info *sbi = F2FS_SB(root->d_sb);

	if (!f2fs_readonly(sbi->sb) && test_opt(sbi, BG_GC))
		seq_printf(seq, ",background_gc=%s", "on");
	else
		seq_printf(seq, ",background_gc=%s", "off");
	if (test_opt(sbi, DISABLE_ROLL_FORWARD))
		seq_puts(seq, ",disable_roll_forward");
	if (test_opt(sbi, DISCARD))
		seq_puts(seq, ",discard");
	if (test_opt(sbi, NOHEAP))
		seq_puts(seq, ",no_heap_alloc");
#ifdef CONFIG_F2FS_FS_XATTR
	if (test_opt(sbi, XATTR_USER))
		seq_puts(seq, ",user_xattr");
	else
		seq_puts(seq, ",nouser_xattr");
	if (test_opt(sbi, INLINE_XATTR))
		seq_puts(seq, ",inline_xattr");
#endif
#ifdef CONFIG_F2FS_FS_POSIX_ACL
	if (test_opt(sbi, POSIX_ACL))
		seq_puts(seq, ",acl");
	else
		seq_puts(seq, ",noacl");
#endif
	if (test_opt(sbi, DISABLE_EXT_IDENTIFY))
		seq_puts(seq, ",disable_ext_identify");
	if (test_opt(sbi, INLINE_DATA))
		seq_puts(seq, ",inline_data");
	if (!f2fs_readonly(sbi->sb) && test_opt(sbi, FLUSH_MERGE))
		seq_puts(seq, ",flush_merge");
	if (test_opt(sbi, NOBARRIER))
		seq_puts(seq, ",nobarrier");
	seq_printf(seq, ",active_logs=%u", sbi->active_logs);

	return 0;
}

static int segment_info_seq_show(struct seq_file *seq, void *offset)
{
	struct super_block *sb = seq->private;
	struct f2fs_sb_info *sbi = F2FS_SB(sb);
	unsigned int total_segs =
			le32_to_cpu(sbi->raw_super->segment_count_main);
	int i;

	seq_puts(seq, "format: segment_type|valid_blocks\n"
		"segment_type(0:HD, 1:WD, 2:CD, 3:HN, 4:WN, 5:CN)\n");

	for (i = 0; i < total_segs; i++) {
		struct seg_entry *se = get_seg_entry(sbi, i);

		if ((i % 10) == 0)
			seq_printf(seq, "%-5d", i);
		seq_printf(seq, "%d|%-3u", se->type,
					get_valid_blocks(sbi, i, 1));
		if ((i % 10) == 9 || i == (total_segs - 1))
			seq_putc(seq, '\n');
		else
			seq_putc(seq, ' ');
	}

	return 0;
}

static int segment_info_open_fs(struct inode *inode, struct file *file)
{
	return single_open(file, segment_info_seq_show, PDE_DATA(inode));
}

static const struct file_operations f2fs_seq_segment_info_fops = {
	.owner = THIS_MODULE,
	.open = segment_info_open_fs,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int f2fs_remount(struct super_block *sb, int *flags, char *data)
{
	struct f2fs_sb_info *sbi = F2FS_SB(sb);
	struct f2fs_mount_info org_mount_opt;
	int err, active_logs;
	bool need_restart_gc = false;
	bool need_stop_gc = false;

	sync_filesystem(sb);

	/*
	 * Save the old mount options in case we
	 * need to restore them.
	 */
	org_mount_opt = sbi->mount_opt;
	active_logs = sbi->active_logs;

	sbi->mount_opt.opt = 0;
	sbi->active_logs = NR_CURSEG_TYPE;

	/* parse mount options */
	err = parse_options(sb, data);
	if (err)
		goto restore_opts;

	/*
	 * Previous and new state of filesystem is RO,
	 * so skip checking GC and FLUSH_MERGE conditions.
	 */
	if (f2fs_readonly(sb) && (*flags & MS_RDONLY))
		goto skip;

	/*
	 * We stop the GC thread if FS is mounted as RO
	 * or if background_gc = off is passed in mount
	 * option. Also sync the filesystem.
	 */
	if ((*flags & MS_RDONLY) || !test_opt(sbi, BG_GC)) {
		if (sbi->gc_thread) {
			stop_gc_thread(sbi);
			f2fs_sync_fs(sb, 1);
			need_restart_gc = true;
		}
	} else if (test_opt(sbi, BG_GC) && !sbi->gc_thread) {
		err = start_gc_thread(sbi);
		if (err)
			goto restore_opts;
		need_stop_gc = true;
	}

	/*
	 * We stop issue flush thread if FS is mounted as RO
	 * or if flush_merge is not passed in mount option.
	 */
	if ((*flags & MS_RDONLY) || !test_opt(sbi, FLUSH_MERGE)) {
		destroy_flush_cmd_control(sbi);
	} else if (test_opt(sbi, FLUSH_MERGE) && !SM_I(sbi)->cmd_control_info) {
		err = create_flush_cmd_control(sbi);
		if (err)
			goto restore_gc;
	}
skip:
	/* Update the POSIXACL Flag */
	 sb->s_flags = (sb->s_flags & ~MS_POSIXACL) |
		(test_opt(sbi, POSIX_ACL) ? MS_POSIXACL : 0);
	return 0;
restore_gc:
	if (need_restart_gc) {
		if (start_gc_thread(sbi))
			f2fs_msg(sbi->sb, KERN_WARNING,
				"background gc thread has stopped");
	} else if (need_stop_gc) {
		stop_gc_thread(sbi);
	}
restore_opts:
	sbi->mount_opt = org_mount_opt;
	sbi->active_logs = active_logs;
	return err;
}

static struct super_operations f2fs_sops = {
	.alloc_inode	= f2fs_alloc_inode,
	.drop_inode	= f2fs_drop_inode,
	.destroy_inode	= f2fs_destroy_inode,
	.write_inode	= f2fs_write_inode,
	.dirty_inode	= f2fs_dirty_inode,
	.show_options	= f2fs_show_options,
	.evict_inode	= f2fs_evict_inode,
	.put_super	= f2fs_put_super,
	.sync_fs	= f2fs_sync_fs,
	.freeze_fs	= f2fs_freeze,
	.unfreeze_fs	= f2fs_unfreeze,
	.statfs		= f2fs_statfs,
	.remount_fs	= f2fs_remount,
};

static struct inode *f2fs_nfs_get_inode(struct super_block *sb,
		u64 ino, u32 generation)
{
	struct f2fs_sb_info *sbi = F2FS_SB(sb);
	struct inode *inode;

	if (check_nid_range(sbi, ino))
		return ERR_PTR(-ESTALE);

	/*
	 * f2fs_iget isn't quite right if the inode is currently unallocated!
	 * However f2fs_iget currently does appropriate checks to handle stale
	 * inodes so everything is OK.
	 */
	inode = f2fs_iget(sb, ino);
	if (IS_ERR(inode))
		return ERR_CAST(inode);
	if (unlikely(generation && inode->i_generation != generation)) {
		/* we didn't find the right inode.. */
		iput(inode);
		return ERR_PTR(-ESTALE);
	}
	return inode;
}

static struct dentry *f2fs_fh_to_dentry(struct super_block *sb, struct fid *fid,
		int fh_len, int fh_type)
{
	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
				    f2fs_nfs_get_inode);
}

static struct dentry *f2fs_fh_to_parent(struct super_block *sb, struct fid *fid,
		int fh_len, int fh_type)
{
	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
				    f2fs_nfs_get_inode);
}

static const struct export_operations f2fs_export_ops = {
	.fh_to_dentry = f2fs_fh_to_dentry,
	.fh_to_parent = f2fs_fh_to_parent,
	.get_parent = f2fs_get_parent,
};

static loff_t max_file_size(unsigned bits)
{
	loff_t result = (DEF_ADDRS_PER_INODE - F2FS_INLINE_XATTR_ADDRS);
	loff_t leaf_count = ADDRS_PER_BLOCK;

	/* two direct node blocks */
	result += (leaf_count * 2);

	/* two indirect node blocks */
	leaf_count *= NIDS_PER_BLOCK;
	result += (leaf_count * 2);

	/* one double indirect node block */
	leaf_count *= NIDS_PER_BLOCK;
	result += leaf_count;

	result <<= bits;
	return result;
}

static inline bool sanity_check_area_boundary(struct super_block *sb,
					struct f2fs_super_block *raw_super)
{
	u32 segment0_blkaddr = le32_to_cpu(raw_super->segment0_blkaddr);
	u32 cp_blkaddr = le32_to_cpu(raw_super->cp_blkaddr);
	u32 sit_blkaddr = le32_to_cpu(raw_super->sit_blkaddr);
	u32 nat_blkaddr = le32_to_cpu(raw_super->nat_blkaddr);
	u32 ssa_blkaddr = le32_to_cpu(raw_super->ssa_blkaddr);
	u32 main_blkaddr = le32_to_cpu(raw_super->main_blkaddr);
	u32 segment_count_ckpt = le32_to_cpu(raw_super->segment_count_ckpt);
	u32 segment_count_sit = le32_to_cpu(raw_super->segment_count_sit);
	u32 segment_count_nat = le32_to_cpu(raw_super->segment_count_nat);
	u32 segment_count_ssa = le32_to_cpu(raw_super->segment_count_ssa);
	u32 segment_count_main = le32_to_cpu(raw_super->segment_count_main);
	u32 segment_count = le32_to_cpu(raw_super->segment_count);
	u32 log_blocks_per_seg = le32_to_cpu(raw_super->log_blocks_per_seg);

	if (segment0_blkaddr != cp_blkaddr) {
		f2fs_info(sbi, "Mismatch start address, segment0(%u) cp_blkaddr(%u)",
			  segment0_blkaddr, cp_blkaddr);
		return true;
	}

	if (cp_blkaddr + (segment_count_ckpt << log_blocks_per_seg) !=
							sit_blkaddr) {
		f2fs_info(sbi, "Wrong CP boundary, start(%u) end(%u) blocks(%u)",
			  cp_blkaddr, sit_blkaddr,
			  segment_count_ckpt << log_blocks_per_seg);
		return true;
	}

	if (sit_blkaddr + (segment_count_sit << log_blocks_per_seg) !=
							nat_blkaddr) {
		f2fs_info(sbi, "Wrong SIT boundary, start(%u) end(%u) blocks(%u)",
			  sit_blkaddr, nat_blkaddr,
			  segment_count_sit << log_blocks_per_seg);
		return true;
	}

	if (nat_blkaddr + (segment_count_nat << log_blocks_per_seg) !=
							ssa_blkaddr) {
		f2fs_info(sbi, "Wrong NAT boundary, start(%u) end(%u) blocks(%u)",
			  nat_blkaddr, ssa_blkaddr,
			  segment_count_nat << log_blocks_per_seg);
		return true;
	}

	if (ssa_blkaddr + (segment_count_ssa << log_blocks_per_seg) !=
							main_blkaddr) {
		f2fs_info(sbi, "Wrong SSA boundary, start(%u) end(%u) blocks(%u)",
			  ssa_blkaddr, main_blkaddr,
			  segment_count_ssa << log_blocks_per_seg);
		return true;
	}

	if (main_end_blkaddr > seg_end_blkaddr) {
		f2fs_info(sbi, "Wrong MAIN_AREA boundary, start(%u) end(%u) block(%u)",
			  main_blkaddr,
			  segment0_blkaddr +
			  (segment_count << log_blocks_per_seg),
			  segment_count_main << log_blocks_per_seg);
		return true;
	} else if (main_end_blkaddr < seg_end_blkaddr) {
		int err = 0;
		char *res;

		/* fix in-memory information all the time */
		raw_super->segment_count = cpu_to_le32((main_end_blkaddr -
				segment0_blkaddr) >> log_blocks_per_seg);

		if (f2fs_readonly(sb) || bdev_read_only(sb->s_bdev)) {
			set_sbi_flag(sbi, SBI_NEED_SB_WRITE);
			res = "internally";
		} else {
			err = __f2fs_commit_super(bh, NULL);
			res = err ? "failed" : "done";
		}
		f2fs_info(sbi, "Fix alignment : %s, start(%u) end(%u) block(%u)",
			  res, main_blkaddr,
			  segment0_blkaddr +
			  (segment_count << log_blocks_per_seg),
			  segment_count_main << log_blocks_per_seg);
		if (err)
			return true;
	}

	return false;
}

static int sanity_check_raw_super(struct super_block *sb,
			struct f2fs_super_block *raw_super)
{
	block_t segment_count, segs_per_sec, secs_per_zone;
	block_t total_sections, blocks_per_seg;
	struct f2fs_super_block *raw_super = (struct f2fs_super_block *)
					(bh->b_data + F2FS_SUPER_OFFSET);
	unsigned int blocksize;
	size_t crc_offset = 0;
	__u32 crc = 0;

	/* Check checksum_offset and crc in superblock */
	if (__F2FS_HAS_FEATURE(raw_super, F2FS_FEATURE_SB_CHKSUM)) {
		crc_offset = le32_to_cpu(raw_super->checksum_offset);
		if (crc_offset !=
			offsetof(struct f2fs_super_block, crc)) {
			f2fs_info(sbi, "Invalid SB checksum offset: %zu",
				  crc_offset);
			return 1;
		}
		crc = le32_to_cpu(raw_super->crc);
		if (!f2fs_crc_valid(sbi, crc, raw_super, crc_offset)) {
			f2fs_info(sbi, "Invalid SB checksum value: %u", crc);
			return 1;
		}
	}

	if (F2FS_SUPER_MAGIC != le32_to_cpu(raw_super->magic)) {
		f2fs_info(sbi, "Magic Mismatch, valid(0x%x) - read(0x%x)",
			  F2FS_SUPER_MAGIC, le32_to_cpu(raw_super->magic));
		return 1;
	}

	/* Currently, support only 4KB page cache size */
	if (F2FS_BLKSIZE != PAGE_SIZE) {
		f2fs_info(sbi, "Invalid page_cache_size (%lu), supports only 4KB",
			  PAGE_SIZE);
		return 1;
	}

	/* Currently, support only 4KB block size */
	blocksize = 1 << le32_to_cpu(raw_super->log_blocksize);
	if (blocksize != F2FS_BLKSIZE) {
		f2fs_info(sbi, "Invalid blocksize (%u), supports only 4KB",
			  blocksize);
		return 1;
	}

	/* check log blocks per segment */
	if (le32_to_cpu(raw_super->log_blocks_per_seg) != 9) {
		f2fs_info(sbi, "Invalid log blocks per segment (%u)",
			  le32_to_cpu(raw_super->log_blocks_per_seg));
		return 1;
	}

	/* Currently, support 512/1024/2048/4096 bytes sector size */
	if (le32_to_cpu(raw_super->log_sectorsize) >
				F2FS_MAX_LOG_SECTOR_SIZE ||
		le32_to_cpu(raw_super->log_sectorsize) <
				F2FS_MIN_LOG_SECTOR_SIZE) {
		f2fs_info(sbi, "Invalid log sectorsize (%u)",
			  le32_to_cpu(raw_super->log_sectorsize));
		return 1;
	}
	if (le32_to_cpu(raw_super->log_sectors_per_block) +
		le32_to_cpu(raw_super->log_sectorsize) !=
			F2FS_MAX_LOG_SECTOR_SIZE) {
		f2fs_info(sbi, "Invalid log sectors per block(%u) log sectorsize(%u)",
			  le32_to_cpu(raw_super->log_sectors_per_block),
			  le32_to_cpu(raw_super->log_sectorsize));
		return 1;
	}

	segment_count = le32_to_cpu(raw_super->segment_count);
	segs_per_sec = le32_to_cpu(raw_super->segs_per_sec);
	secs_per_zone = le32_to_cpu(raw_super->secs_per_zone);
	total_sections = le32_to_cpu(raw_super->section_count);

	/* blocks_per_seg should be 512, given the above check */
	blocks_per_seg = 1 << le32_to_cpu(raw_super->log_blocks_per_seg);

	if (segment_count > F2FS_MAX_SEGMENT ||
				segment_count < F2FS_MIN_SEGMENTS) {
		f2fs_info(sbi, "Invalid segment count (%u)", segment_count);
		return 1;
	}

	if (total_sections > segment_count ||
			total_sections < F2FS_MIN_SEGMENTS ||
			segs_per_sec > segment_count || !segs_per_sec) {
		f2fs_info(sbi, "Invalid segment/section count (%u, %u x %u)",
			  segment_count, total_sections, segs_per_sec);
		return 1;
	}

	if ((segment_count / segs_per_sec) < total_sections) {
		f2fs_info(sbi, "Small segment_count (%u < %u * %u)",
			  segment_count, segs_per_sec, total_sections);
		return 1;
	}

	if (segment_count > (le64_to_cpu(raw_super->block_count) >> 9)) {
		f2fs_info(sbi, "Wrong segment_count / block_count (%u > %llu)",
			  segment_count, le64_to_cpu(raw_super->block_count));
		return 1;
	}

	if (secs_per_zone > total_sections || !secs_per_zone) {
		f2fs_info(sbi, "Wrong secs_per_zone / total_sections (%u, %u)",
			  secs_per_zone, total_sections);
		return 1;
	}
	if (le32_to_cpu(raw_super->extension_count) > F2FS_MAX_EXTENSION ||
			raw_super->hot_ext_count > F2FS_MAX_EXTENSION ||
			(le32_to_cpu(raw_super->extension_count) +
			raw_super->hot_ext_count) > F2FS_MAX_EXTENSION) {
		f2fs_info(sbi, "Corrupted extension count (%u + %u > %u)",
			  le32_to_cpu(raw_super->extension_count),
			  raw_super->hot_ext_count,
			  F2FS_MAX_EXTENSION);
		return 1;
	}

	if (le32_to_cpu(raw_super->cp_payload) >
				(blocks_per_seg - F2FS_CP_PACKS)) {
		f2fs_info(sbi, "Insane cp_payload (%u > %u)",
			  le32_to_cpu(raw_super->cp_payload),
			  blocks_per_seg - F2FS_CP_PACKS);
		return 1;
	}

	/* check reserved ino info */
	if (le32_to_cpu(raw_super->node_ino) != 1 ||
		le32_to_cpu(raw_super->meta_ino) != 2 ||
		le32_to_cpu(raw_super->root_ino) != 3) {
		f2fs_info(sbi, "Invalid Fs Meta Ino: node(%u) meta(%u) root(%u)",
			  le32_to_cpu(raw_super->node_ino),
			  le32_to_cpu(raw_super->meta_ino),
			  le32_to_cpu(raw_super->root_ino));
		return 1;
	}

	if (le32_to_cpu(raw_super->segment_count) > F2FS_MAX_SEGMENT) {
		f2fs_msg(sb, KERN_INFO,
			"Invalid segment count (%u)",
			le32_to_cpu(raw_super->segment_count));
		return 1;
	}

	/* check CP/SIT/NAT/SSA/MAIN_AREA area boundary */
	if (sanity_check_area_boundary(sb, raw_super))
		return 1;

	return 0;
}

static int sanity_check_ckpt(struct f2fs_sb_info *sbi)
{
	unsigned int total, fsmeta;
	struct f2fs_super_block *raw_super = F2FS_RAW_SUPER(sbi);
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	unsigned int main_segs, blocks_per_seg;
	unsigned int sit_segs, nat_segs;
	unsigned int sit_bitmap_size, nat_bitmap_size;
	unsigned int log_blocks_per_seg;
	int i;

	total = le32_to_cpu(raw_super->segment_count);
	fsmeta = le32_to_cpu(raw_super->segment_count_ckpt);
	sit_segs = le32_to_cpu(raw_super->segment_count_sit);
	fsmeta += sit_segs;
	nat_segs = le32_to_cpu(raw_super->segment_count_nat);
	fsmeta += nat_segs;
	fsmeta += le32_to_cpu(ckpt->rsvd_segment_count);
	fsmeta += le32_to_cpu(raw_super->segment_count_ssa);

	if (unlikely(fsmeta >= total))
		return 1;

	ovp_segments = le32_to_cpu(ckpt->overprov_segment_count);
	reserved_segments = le32_to_cpu(ckpt->rsvd_segment_count);

	if (unlikely(fsmeta < F2FS_MIN_SEGMENTS ||
			ovp_segments == 0 || reserved_segments == 0)) {
		f2fs_err(sbi, "Wrong layout: check mkfs.f2fs version");
		return 1;
	}

	user_block_count = le64_to_cpu(ckpt->user_block_count);
	segment_count_main = le32_to_cpu(raw_super->segment_count_main);
	log_blocks_per_seg = le32_to_cpu(raw_super->log_blocks_per_seg);
	if (!user_block_count || user_block_count >=
			segment_count_main << log_blocks_per_seg) {
		f2fs_err(sbi, "Wrong user_block_count: %u",
			 user_block_count);
		return 1;
	}

	valid_user_blocks = le64_to_cpu(ckpt->valid_block_count);
	if (valid_user_blocks > user_block_count) {
		f2fs_err(sbi, "Wrong valid_user_blocks: %u, user_block_count: %u",
			 valid_user_blocks, user_block_count);
		return 1;
	}

	valid_node_count = le32_to_cpu(ckpt->valid_node_count);
	avail_node_count = sbi->total_node_count - sbi->nquota_files -
						F2FS_RESERVED_NODE_NUM;
	if (valid_node_count > avail_node_count) {
		f2fs_err(sbi, "Wrong valid_node_count: %u, avail_node_count: %u",
			 valid_node_count, avail_node_count);
		return 1;
	}

	main_segs = le32_to_cpu(raw_super->segment_count_main);
	blocks_per_seg = sbi->blocks_per_seg;

	for (i = 0; i < NR_CURSEG_NODE_TYPE; i++) {
		if (le32_to_cpu(ckpt->cur_node_segno[i]) >= main_segs ||
			le16_to_cpu(ckpt->cur_node_blkoff[i]) >= blocks_per_seg)
			return 1;
		for (j = i + 1; j < NR_CURSEG_NODE_TYPE; j++) {
			if (le32_to_cpu(ckpt->cur_node_segno[i]) ==
				le32_to_cpu(ckpt->cur_node_segno[j])) {
				f2fs_err(sbi, "Node segment (%u, %u) has the same segno: %u",
					 i, j,
					 le32_to_cpu(ckpt->cur_node_segno[i]));
				return 1;
			}
		}
	}
	for (i = 0; i < NR_CURSEG_DATA_TYPE; i++) {
		if (le32_to_cpu(ckpt->cur_data_segno[i]) >= main_segs ||
			le16_to_cpu(ckpt->cur_data_blkoff[i]) >= blocks_per_seg)
			return 1;
		for (j = i + 1; j < NR_CURSEG_DATA_TYPE; j++) {
			if (le32_to_cpu(ckpt->cur_data_segno[i]) ==
				le32_to_cpu(ckpt->cur_data_segno[j])) {
				f2fs_err(sbi, "Data segment (%u, %u) has the same segno: %u",
					 i, j,
					 le32_to_cpu(ckpt->cur_data_segno[i]));
				return 1;
			}
		}
	}
	for (i = 0; i < NR_CURSEG_NODE_TYPE; i++) {
		for (j = i; j < NR_CURSEG_DATA_TYPE; j++) {
			if (le32_to_cpu(ckpt->cur_node_segno[i]) ==
				le32_to_cpu(ckpt->cur_data_segno[j])) {
				f2fs_err(sbi, "Data segment (%u) and Data segment (%u) has the same segno: %u",
					 i, j,
					 le32_to_cpu(ckpt->cur_node_segno[i]));
				return 1;
			}
		}
	}

	sit_bitmap_size = le32_to_cpu(ckpt->sit_ver_bitmap_bytesize);
	nat_bitmap_size = le32_to_cpu(ckpt->nat_ver_bitmap_bytesize);
	log_blocks_per_seg = le32_to_cpu(raw_super->log_blocks_per_seg);

	if (sit_bitmap_size != ((sit_segs / 2) << log_blocks_per_seg) / 8 ||
		nat_bitmap_size != ((nat_segs / 2) << log_blocks_per_seg) / 8) {
		f2fs_err(sbi, "Wrong bitmap size: sit: %u, nat:%u",
			 sit_bitmap_size, nat_bitmap_size);
		return 1;
	}

	cp_pack_start_sum = __start_sum_addr(sbi);
	cp_payload = __cp_payload(sbi);
	if (cp_pack_start_sum < cp_payload + 1 ||
		cp_pack_start_sum > blocks_per_seg - 1 -
			NR_CURSEG_TYPE) {
		f2fs_err(sbi, "Wrong cp_pack_start_sum: %u",
			 cp_pack_start_sum);
		return 1;
	}

	if (__is_set_ckpt_flags(ckpt, CP_LARGE_NAT_BITMAP_FLAG) &&
		le32_to_cpu(ckpt->checksum_offset) != CP_MIN_CHKSUM_OFFSET) {
		f2fs_warn(sbi, "layout of large_nat_bitmap is deprecated, run fsck to repair, chksum_offset: %u",
			  le32_to_cpu(ckpt->checksum_offset));
		return 1;
	}

	if (unlikely(f2fs_cp_error(sbi))) {
		f2fs_err(sbi, "A bug case: need to run fsck");
		return 1;
	}
	return 0;
}

static void init_sb_info(struct f2fs_sb_info *sbi)
{
	struct f2fs_super_block *raw_super = sbi->raw_super;
	int i;

	sbi->log_sectors_per_block =
		le32_to_cpu(raw_super->log_sectors_per_block);
	sbi->log_blocksize = le32_to_cpu(raw_super->log_blocksize);
	sbi->blocksize = 1 << sbi->log_blocksize;
	sbi->log_blocks_per_seg = le32_to_cpu(raw_super->log_blocks_per_seg);
	sbi->blocks_per_seg = 1 << sbi->log_blocks_per_seg;
	sbi->segs_per_sec = le32_to_cpu(raw_super->segs_per_sec);
	sbi->secs_per_zone = le32_to_cpu(raw_super->secs_per_zone);
	sbi->total_sections = le32_to_cpu(raw_super->section_count);
	sbi->total_node_count =
		(le32_to_cpu(raw_super->segment_count_nat) / 2)
			* sbi->blocks_per_seg * NAT_ENTRY_PER_BLOCK;
	sbi->root_ino_num = le32_to_cpu(raw_super->root_ino);
	sbi->node_ino_num = le32_to_cpu(raw_super->node_ino);
	sbi->meta_ino_num = le32_to_cpu(raw_super->meta_ino);
	sbi->cur_victim_sec = NULL_SECNO;
	sbi->max_victim_search = DEF_MAX_VICTIM_SEARCH;

	for (i = 0; i < NR_COUNT_TYPE; i++)
		atomic_set(&sbi->nr_pages[i], 0);

	sbi->dir_level = DEF_DIR_LEVEL;
	sbi->need_fsck = false;
}

/*
 * Read f2fs raw super block.
 * Because we have two copies of super block, so read the first one at first,
 * if the first one is invalid, move to read the second one.
 */
static int read_raw_super_block(struct super_block *sb,
			struct f2fs_super_block **raw_super,
			struct buffer_head **raw_super_buf)
{
	struct super_block *sb = sbi->sb;
	int block;
	struct buffer_head *bh;
	struct f2fs_super_block *super;
	int err = 0;

	super = kzalloc(sizeof(struct f2fs_super_block), GFP_KERNEL);
	if (!super)
		return -ENOMEM;

	for (block = 0; block < 2; block++) {
		bh = sb_bread(sb, block);
		if (!bh) {
			f2fs_err(sbi, "Unable to read %dth superblock",
				 block + 1);
			err = -EIO;
			continue;
		}

		/* sanity checking of raw super */
		if (sanity_check_raw_super(sbi, bh)) {
			f2fs_err(sbi, "Can't find valid F2FS filesystem in %dth superblock",
				 block + 1);
			err = -EINVAL;
			brelse(bh);
			continue;
		}

		if (!*raw_super) {
			memcpy(super, bh->b_data + F2FS_SUPER_OFFSET,
							sizeof(*super));
			*valid_super_block = block;
			*raw_super = super;
		}
	}

	*raw_super = (struct f2fs_super_block *)
		((char *)(*raw_super_buf)->b_data + F2FS_SUPER_OFFSET);

	/* sanity checking of raw super */
	if (sanity_check_raw_super(sb, *raw_super)) {
		brelse(*raw_super_buf);
		f2fs_msg(sb, KERN_ERR,
			"Can't find valid F2FS filesystem in %dth superblock",
								block + 1);
		if (block == 0) {
			block++;
			goto retry;
		} else {
			/* Multi-device mount */
			memcpy(FDEV(i).path, RDEV(i).path, MAX_PATH_LEN);
			FDEV(i).total_segments =
				le32_to_cpu(RDEV(i).total_segments);
			if (i == 0) {
				FDEV(i).start_blk = 0;
				FDEV(i).end_blk = FDEV(i).start_blk +
				    (FDEV(i).total_segments <<
				    sbi->log_blocks_per_seg) - 1 +
				    le32_to_cpu(raw_super->segment0_blkaddr);
			} else {
				FDEV(i).start_blk = FDEV(i - 1).end_blk + 1;
				FDEV(i).end_blk = FDEV(i).start_blk +
					(FDEV(i).total_segments <<
					sbi->log_blocks_per_seg) - 1;
			}
			FDEV(i).bdev = blkdev_get_by_path(FDEV(i).path,
					sbi->sb->s_mode, sbi->sb->s_type);
		}
		if (IS_ERR(FDEV(i).bdev))
			return PTR_ERR(FDEV(i).bdev);

		/* to release errored devices */
		sbi->s_ndevs = i + 1;

#ifdef CONFIG_BLK_DEV_ZONED
		if (bdev_zoned_model(FDEV(i).bdev) == BLK_ZONED_HM &&
				!f2fs_sb_has_blkzoned(sbi)) {
			f2fs_err(sbi, "Zoned block device feature not enabled\n");
			return -EINVAL;
		}
		if (bdev_zoned_model(FDEV(i).bdev) != BLK_ZONED_NONE) {
			if (init_blkz_info(sbi, i)) {
				f2fs_err(sbi, "Failed to initialize F2FS blkzone information");
				return -EINVAL;
			}
			if (max_devices == 1)
				break;
			f2fs_info(sbi, "Mount Device [%2d]: %20s, %8u, %8x - %8x (zone: %s)",
				  i, FDEV(i).path,
				  FDEV(i).total_segments,
				  FDEV(i).start_blk, FDEV(i).end_blk,
				  bdev_zoned_model(FDEV(i).bdev) == BLK_ZONED_HA ?
				  "Host-aware" : "Host-managed");
			continue;
		}
#endif
		f2fs_info(sbi, "Mount Device [%2d]: %20s, %8u, %8x - %8x",
			  i, FDEV(i).path,
			  FDEV(i).total_segments,
			  FDEV(i).start_blk, FDEV(i).end_blk);
	}
	f2fs_info(sbi,
		  "IO Block Size: %8d KB", F2FS_IO_SIZE_KB(sbi));
	return 0;
}

static void f2fs_tuning_parameters(struct f2fs_sb_info *sbi)
{
	struct f2fs_sm_info *sm_i = SM_I(sbi);

	/* adjust parameters according to the volume size */
	if (sm_i->main_segments <= SMALL_VOLUME_SEGMENTS) {
		F2FS_OPTION(sbi).alloc_mode = ALLOC_MODE_REUSE;
		sm_i->dcc_info->discard_granularity = 1;
		sm_i->ipu_policy = 1 << F2FS_IPU_FORCE;
	}

	return 0;
}

static int f2fs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct f2fs_sb_info *sbi;
	struct f2fs_super_block *raw_super;
	struct buffer_head *raw_super_buf;
	struct inode *root;
	long err = -EINVAL;
	bool retry = true;
	int i;

try_onemore:
	/* allocate memory for f2fs-specific super block info */
	sbi = kzalloc(sizeof(struct f2fs_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sbi->sb = sb;

	/* Load the checksum driver */
	sbi->s_chksum_driver = crypto_alloc_shash("crc32", 0, 0);
	if (IS_ERR(sbi->s_chksum_driver)) {
		f2fs_err(sbi, "Cannot load crc32 driver.");
		err = PTR_ERR(sbi->s_chksum_driver);
		sbi->s_chksum_driver = NULL;
		goto free_sbi;
	}

	/* set a block size */
	if (unlikely(!sb_set_blocksize(sb, F2FS_BLKSIZE))) {
		f2fs_err(sbi, "unable to set blocksize");
		goto free_sbi;
	}

	err = read_raw_super_block(sb, &raw_super, &raw_super_buf);
	if (err)
		goto free_sbi;

	sb->s_fs_info = sbi;
	/* init some FS parameters */
	sbi->active_logs = NR_CURSEG_TYPE;

	set_opt(sbi, BG_GC);

	/*
	 * The BLKZONED feature indicates that the drive was formatted with
	 * zone alignment optimization. This is optional for host-aware
	 * devices, but mandatory for host-managed zoned block devices.
	 */
#ifndef CONFIG_BLK_DEV_ZONED
	if (f2fs_sb_has_blkzoned(sbi)) {
		f2fs_err(sbi, "Zoned block device support is not enabled");
		err = -EOPNOTSUPP;
		goto free_sb_buf;
	}
#endif
	/* parse mount options */
	err = parse_options(sb, (char *)data);
	if (err)
		goto free_sb_buf;

	sb->s_maxbytes = max_file_size(le32_to_cpu(raw_super->log_blocksize));
	sb->s_max_links = F2FS_LINK_MAX;
	get_random_bytes(&sbi->s_next_generation, sizeof(u32));

	sb->s_op = &f2fs_sops;
	sb->s_xattr = f2fs_xattr_handlers;
	sb->s_export_op = &f2fs_export_ops;
	sb->s_magic = F2FS_SUPER_MAGIC;
	sb->s_time_gran = 1;
	sb->s_flags = (sb->s_flags & ~MS_POSIXACL) |
		(test_opt(sbi, POSIX_ACL) ? MS_POSIXACL : 0);
	memcpy(sb->s_uuid, raw_super->uuid, sizeof(raw_super->uuid));

	/* init f2fs-specific super block info */
	sbi->sb = sb;
	sbi->raw_super = raw_super;
	sbi->raw_super_buf = raw_super_buf;
	mutex_init(&sbi->gc_mutex);
	mutex_init(&sbi->writepages);
	mutex_init(&sbi->cp_mutex);
	mutex_init(&sbi->resize_mutex);
	init_rwsem(&sbi->node_write);
	sbi->por_doing = false;
	spin_lock_init(&sbi->stat_lock);

	init_rwsem(&sbi->read_io.io_rwsem);
	sbi->read_io.sbi = sbi;
	sbi->read_io.bio = NULL;
	for (i = 0; i < NR_PAGE_TYPE; i++) {
		init_rwsem(&sbi->write_io[i].io_rwsem);
		sbi->write_io[i].sbi = sbi;
		sbi->write_io[i].bio = NULL;
	}

	init_rwsem(&sbi->cp_rwsem);
	init_waitqueue_head(&sbi->cp_wait);
	init_sb_info(sbi);

	/* get an inode for meta space */
	sbi->meta_inode = f2fs_iget(sb, F2FS_META_INO(sbi));
	if (IS_ERR(sbi->meta_inode)) {
		f2fs_err(sbi, "Failed to read F2FS meta data inode");
		err = PTR_ERR(sbi->meta_inode);
		goto free_sb_buf;
	}

	err = get_valid_checkpoint(sbi);
	if (err) {
		f2fs_err(sbi, "Failed to get valid F2FS checkpoint");
		goto free_meta_inode;
	}

	if (__is_set_ckpt_flags(F2FS_CKPT(sbi), CP_QUOTA_NEED_FSCK_FLAG))
		set_sbi_flag(sbi, SBI_QUOTA_NEED_REPAIR);
	if (__is_set_ckpt_flags(F2FS_CKPT(sbi), CP_DISABLED_QUICK_FLAG)) {
		set_sbi_flag(sbi, SBI_CP_DISABLED_QUICK);
		sbi->interval_time[DISABLE_TIME] = DEF_DISABLE_QUICK_INTERVAL;
	}

	if (__is_set_ckpt_flags(F2FS_CKPT(sbi), CP_FSCK_FLAG))
		set_sbi_flag(sbi, SBI_NEED_FSCK);

	/* Initialize device list */
	err = f2fs_scan_devices(sbi);
	if (err) {
		f2fs_err(sbi, "Failed to find devices");
		goto free_devices;
	}

	sbi->total_valid_node_count =
				le32_to_cpu(sbi->ckpt->valid_node_count);
	sbi->total_valid_inode_count =
				le32_to_cpu(sbi->ckpt->valid_inode_count);
	sbi->user_block_count = le64_to_cpu(sbi->ckpt->user_block_count);
	sbi->total_valid_block_count =
				le64_to_cpu(sbi->ckpt->valid_block_count);
	sbi->last_valid_block_count = sbi->total_valid_block_count;
	sbi->alloc_valid_block_count = 0;
	INIT_LIST_HEAD(&sbi->dir_inode_list);
	spin_lock_init(&sbi->dir_inode_lock);

	init_ino_entry_info(sbi);

	/* setup f2fs internal modules */
	err = build_segment_manager(sbi);
	if (err) {
		f2fs_err(sbi, "Failed to initialize F2FS segment manager (%d)",
			 err);
		goto free_sm;
	}
	err = build_node_manager(sbi);
	if (err) {
		f2fs_err(sbi, "Failed to initialize F2FS node manager (%d)",
			 err);
		goto free_nm;
	}

	build_gc_manager(sbi);

	/* get an inode for node space */
	sbi->node_inode = f2fs_iget(sb, F2FS_NODE_INO(sbi));
	if (IS_ERR(sbi->node_inode)) {
		f2fs_err(sbi, "Failed to read node inode");
		err = PTR_ERR(sbi->node_inode);
		goto free_nm;
	}

	/* if there are nt orphan nodes free them */
	recover_orphan_inodes(sbi);

	/* read root inode and dentry */
	root = f2fs_iget(sb, F2FS_ROOT_INO(sbi));
	if (IS_ERR(root)) {
		f2fs_err(sbi, "Failed to read root inode");
		err = PTR_ERR(root);
		goto free_node_inode;
	}
	if (!S_ISDIR(root->i_mode) || !root->i_blocks || !root->i_size) {
		iput(root);
		err = -EINVAL;
		goto free_node_inode;
	}

	sb->s_root = d_make_root(root); /* allocate root dentry */
	if (!sb->s_root) {
		err = -ENOMEM;
		goto free_root_inode;
	}

	err = f2fs_build_stats(sbi);
	if (err)
		goto free_root_inode;

#ifdef CONFIG_QUOTA
	/* Enable quota usage during mount */
	if (f2fs_sb_has_quota_ino(sbi) && !f2fs_readonly(sb)) {
		err = f2fs_enable_quotas(sb);
		if (err)
			f2fs_err(sbi, "Cannot turn on quotas: error %d", err);
	}

	sbi->s_kobj.kset = f2fs_kset;
	init_completion(&sbi->s_kobj_unregister);
	err = kobject_init_and_add(&sbi->s_kobj, &f2fs_ktype, NULL,
							"%s", sb->s_id);
	if (err)
		goto free_proc;

	if (!retry)
		sbi->need_fsck = true;

	/* recover fsynced data */
	if (!test_opt(sbi, DISABLE_ROLL_FORWARD)) {
		/*
		 * mount should be failed, when device has readonly mode, and
		 * previous checkpoint was not done by clean system shutdown.
		 */
		if (f2fs_hw_is_readonly(sbi)) {
			if (!is_set_ckpt_flags(sbi, CP_UMOUNT_FLAG)) {
				err = -EROFS;
				f2fs_err(sbi, "Need to recover fsync data, but write access unavailable");
				goto free_meta;
			}
			f2fs_info(sbi, "write access unavailable, skipping recovery");
			goto reset_checkpoint;
		}

		if (need_fsck)
			set_sbi_flag(sbi, SBI_NEED_FSCK);

		if (skip_recovery)
			goto reset_checkpoint;

		err = f2fs_recover_fsync_data(sbi, false);
		if (err < 0) {
			if (err != -ENOMEM)
				skip_recovery = true;
			need_fsck = true;
			f2fs_err(sbi, "Cannot recover all fsync data errno=%d",
				 err);
			goto free_meta;
		}
	} else {
		err = f2fs_recover_fsync_data(sbi, true);

		if (!f2fs_readonly(sb) && err > 0) {
			err = -EINVAL;
			f2fs_err(sbi, "Need to recover fsync data");
			goto free_meta;
		}
	}

	/*
	 * If filesystem is not mounted as read-only then
	 * do start the gc_thread.
	 */
	if (!f2fs_readonly(sb)) {
		/* After POR, we can run background GC thread.*/
		err = start_gc_thread(sbi);
		if (err)
			goto free_kobj;
	}
	kvfree(options);

	/* recover broken superblock */
	if (recovery) {
		err = f2fs_commit_super(sbi, true);
		f2fs_info(sbi, "Try to recover %dth superblock, ret: %d",
			  sbi->valid_super_block ? 1 : 2, err);
	}

	f2fs_join_shrinker(sbi);

	f2fs_tuning_parameters(sbi);

	f2fs_notice(sbi, "Mounted with checkpoint version = %llx",
		    cur_cp_version(F2FS_CKPT(sbi)));
	f2fs_update_time(sbi, CP_TIME);
	f2fs_update_time(sbi, REQ_TIME);
	clear_sbi_flag(sbi, SBI_CP_DISABLED_QUICK);
	return 0;

free_kobj:
	kobject_del(&sbi->s_kobj);
free_proc:
	if (sbi->s_proc) {
		remove_proc_entry("segment_info", sbi->s_proc);
		remove_proc_entry(sb->s_id, f2fs_proc_root);
	}
	f2fs_destroy_stats(sbi);
free_root_inode:
	dput(sb->s_root);
	sb->s_root = NULL;
free_node_inode:
	iput(sbi->node_inode);
free_nm:
	destroy_node_manager(sbi);
free_sm:
	destroy_segment_manager(sbi);
free_cp:
	kfree(sbi->ckpt);
free_meta_inode:
	make_bad_inode(sbi->meta_inode);
	iput(sbi->meta_inode);
free_sb_buf:
	brelse(raw_super_buf);
free_sbi:
	kfree(sbi);

	/* give only one another chance */
	if (retry) {
		retry = 0;
		shrink_dcache_sb(sb);
		goto try_onemore;
	}
	return err;
}

static struct dentry *f2fs_mount(struct file_system_type *fs_type, int flags,
			const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, f2fs_fill_super);
}

static struct file_system_type f2fs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "f2fs",
	.mount		= f2fs_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("f2fs");

static int __init init_inodecache(void)
{
	f2fs_inode_cachep = f2fs_kmem_cache_create("f2fs_inode_cache",
			sizeof(struct f2fs_inode_info));
	if (!f2fs_inode_cachep)
		return -ENOMEM;
	return 0;
}

static void destroy_inodecache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(f2fs_inode_cachep);
}

static int __init init_f2fs_fs(void)
{
	int err;

	err = init_inodecache();
	if (err)
		goto fail;
	err = create_node_manager_caches();
	if (err)
		goto free_inodecache;
	err = create_segment_manager_caches();
	if (err)
		goto free_node_manager_caches;
	err = create_gc_caches();
	if (err)
		goto free_segment_manager_caches;
	err = create_checkpoint_caches();
	if (err)
		goto free_gc_caches;
	f2fs_kset = kset_create_and_add("f2fs", NULL, fs_kobj);
	if (!f2fs_kset) {
		err = -ENOMEM;
		goto free_checkpoint_caches;
	}
	err = register_filesystem(&f2fs_fs_type);
	if (err)
		goto free_kset;
	f2fs_create_root_stats();
	f2fs_proc_root = proc_mkdir("fs/f2fs", NULL);
	return 0;

free_kset:
	kset_unregister(f2fs_kset);
free_checkpoint_caches:
	destroy_checkpoint_caches();
free_gc_caches:
	destroy_gc_caches();
free_segment_manager_caches:
	destroy_segment_manager_caches();
free_node_manager_caches:
	destroy_node_manager_caches();
free_inodecache:
	destroy_inodecache();
fail:
	return err;
}

static void __exit exit_f2fs_fs(void)
{
	remove_proc_entry("fs/f2fs", NULL);
	f2fs_destroy_root_stats();
	unregister_filesystem(&f2fs_fs_type);
	destroy_checkpoint_caches();
	destroy_gc_caches();
	destroy_segment_manager_caches();
	destroy_node_manager_caches();
	destroy_inodecache();
	kset_unregister(f2fs_kset);
}

module_init(init_f2fs_fs)
module_exit(exit_f2fs_fs)

MODULE_AUTHOR("Samsung Electronics's Praesto Team");
MODULE_DESCRIPTION("Flash Friendly File System");
MODULE_LICENSE("GPL");
