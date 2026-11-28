#include <linux/module.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/namei.h>
#include <linux/blk_types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/hashtable.h>
#include <linux/mount.h>
#include <linux/path.h>

#include "kernel_compat.h"
#include "baseband_guard.h"
#include "tracing/tracing.h"
#include "blkdev_helper.h"

struct device_hash_node { dev_t dev; struct hlist_node h; };
DEFINE_HASHTABLE(allowed_devs, 7);

static bool allow_has(dev_t dev)
{
	struct device_hash_node *p;

	hash_for_each_possible(allowed_devs, p, h, (u64)dev)
		if (p->dev == dev) return true;
	return false;
}

static void allow_add(dev_t dev)
{
	struct device_hash_node *n;
	if (!dev || allow_has(dev)) return;
	n = kmalloc(sizeof(*n), GFP_ATOMIC);
	if (!n) return;
	n->dev = dev;
	hash_add(allowed_devs, &n->h, (u64)dev);
	bb_pr("allow-cache dev %u:%u\n", MAJOR(dev), MINOR(dev));
}

static bool is_zram_device(dev_t dev)
{
	bool is_zram = bbg_is_named_device(dev, "zram");
	if (is_zram) {
		bb_pr("zram dev %u:%u identified, whitelisting\n",
				MAJOR(dev), MINOR(dev));
	}
	return is_zram;
}

static bool reverse_allow_match_and_cache(dev_t cur)
{
	if (!cur) return false;
	if (is_zram_device(cur)) {
		allow_add(cur);
		return true;
	}
	if (is_allowed_partition_dev_resolve(cur)) {
		allow_add(cur);
		return true;
	}
	return false;
}

static const char *bbg_file_path(struct file *file, char *buf, int buflen)
{
	char *p;
	if (!file || !buf || buflen <= 0) return NULL;
	buf[0] = '\0';
	p = d_path(&file->f_path, buf, buflen);
	return IS_ERR(p) ? NULL : p;
}

static int bbg_get_cmdline(char *buf, int buflen)
{
	int n, i;
	if (!buf || buflen <= 0) return 0;
	n = get_cmdline(current, buf, buflen);
	if (n <= 0) return 0;
	for (i = 0; i < n - 1; i++) if (buf[i] == '\0') buf[i] = ' ';
	if (n < buflen) buf[n] = '\0';
	else buf[buflen - 1] = '\0';
	return n;
}

static void bbg_log_deny_detail(const char *why, struct file *file, struct inode *inode, unsigned int cmd_opt)
{
	const int PATH_BUFLEN = 256;
	const int CMD_BUFLEN  = 256;

	char *pathbuf = kmalloc(PATH_BUFLEN, GFP_ATOMIC);
	char *cmdbuf  = kmalloc(CMD_BUFLEN,  GFP_ATOMIC);

	const char *path = pathbuf ? bbg_file_path(file, pathbuf, PATH_BUFLEN) : NULL;
	dev_t dev = inode ? inode->i_rdev : 0;

	if (cmdbuf)
		bbg_get_cmdline(cmdbuf, CMD_BUFLEN);

	if (cmd_opt) {
		pr_info(
			"baseband_guard: deny %s cmd=0x%x dev=%u:%u path=%s pid=%d comm=%s argv=\"%s\"\n",
			why, cmd_opt, MAJOR(dev), MINOR(dev),
			path ? path : "?", current->pid, current->comm,
			cmdbuf ? cmdbuf : "?");
	} else {
		pr_info(
			"baseband_guard: deny %s dev=%u:%u path=%s pid=%d comm=%s argv=\"%s\"\n",
			why, MAJOR(dev), MINOR(dev),
			path ? path : "?", current->pid, current->comm,
			cmdbuf ? cmdbuf : "?");
	}

	kfree(cmdbuf);
	kfree(pathbuf);
}

static int deny(const char *why, struct file *file, struct inode *inode, unsigned int cmd_opt)
{
	bbg_log_deny_detail(why, file, inode, cmd_opt);
	bb_pr_rl("deny %s pid=%d comm=%s\n", why, current->pid, current->comm);
	if (!BB_ENFORCING) return 0;
	return -EPERM;
}

static int bb_file_permission(struct file *file, int mask)
{
	struct inode *inode;

	if (likely(current_process_trusted()))
		return 0;

	if (!(mask & MAY_WRITE)) return 0;
	if (!file) return 0;

	inode = file_inode(file);
	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	if (allow_has(inode->i_rdev) || reverse_allow_match_and_cache(inode->i_rdev))
		return 0;

	return deny("write to protected partition", file, inode, 0);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0)
static int bb_inode_setattr(struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *iattr)
#else
static int bb_inode_setattr(struct dentry *dentry, struct iattr *iattr) 
#endif
{
	struct inode *inode;

	if (current_process_trusted())
        return 0;
	
	inode = d_inode(dentry);

	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	if (allow_has(inode->i_rdev) || reverse_allow_match_and_cache(inode->i_rdev))
		return 0;

	return deny("setattr on protected partition", 0, inode, 0);
}

static inline bool is_destructive_ioctl(unsigned int cmd)
{
	switch (cmd) {
	case BLKDISCARD:
	case BLKSECDISCARD:
	case BLKZEROOUT:
#ifdef BLKPG
	case BLKPG:
#endif
#ifdef BLKTRIM
	case BLKTRIM:
#endif
#ifdef BLKRRPART
	case BLKRRPART:
#endif
#ifdef BLKSETRO
	case BLKSETRO:
#endif
#ifdef BLKSETBADSECTORS
	case BLKSETBADSECTORS:
#endif
		return true;
	default:
		return false;
	}
}

static int bb_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode;

	if (!file) return 0;
	inode = file_inode(file);
	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	if (!is_destructive_ioctl(cmd))
		return 0;

	if (likely(current_process_trusted()))
		return 0;

	if (allow_has(inode->i_rdev) || reverse_allow_match_and_cache(inode->i_rdev))
		return 0;

	return deny("destructive ioctl on protected partition", file, inode, cmd);
}

#ifdef BB_HAS_IOCTL_COMPAT
static int bb_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
	return bb_file_ioctl(file, cmd, arg);
}
#endif

static bool bbg_matches_rw_mount(const char *mountpoint, const struct super_block *sb)
{
	struct path p;
	bool matched = false;

	if (!mountpoint || !sb)
		return false;
	if (kern_path(mountpoint, LOOKUP_FOLLOW, &p) == 0) {
		if (p.mnt && p.mnt->mnt_sb == sb)
			matched = true;
		path_put(&p);
	}
	return matched;
}

static bool bbg_is_allowed_mount_sb(const struct super_block *sb)
{
	if (!sb || MAJOR(sb->s_dev) == 0)
		return true;
	if (allow_has(sb->s_dev) || reverse_allow_match_and_cache(sb->s_dev))
		return true;
	/* Permit dm-backed /data and /metadata mounts whose s_dev lacks GPT volname */
	if (bbg_matches_rw_mount("/data", sb) || bbg_matches_rw_mount("/metadata", sb))
		return true;
	return false;
}

static int bb_sb_mount(const char *dev_name, const struct path *path,
		       const char *type, unsigned long flags, void *data)
{
	dev_t dev;

	(void)type;
	(void)data;

	if (likely(current_process_trusted()))
		return 0;

	if ((flags & MS_MGC_MSK) == MS_MGC_VAL)
		flags &= ~MS_MGC_MSK;

	if (!(flags & (MS_REMOUNT | MS_BIND | MS_MOVE)) &&
	    (flags & (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE)))
		return 0;

	if ((flags & MS_REMOUNT) && !(flags & MS_RDONLY)) {
		struct super_block *sb = (path && path->mnt) ? path->mnt->mnt_sb : NULL;
		bool currently_ro = false;

		if (!sb && path && path->dentry && d_backing_inode(path->dentry))
			sb = d_backing_inode(path->dentry)->i_sb;
		if (path && path->mnt && (path->mnt->mnt_flags & MNT_READONLY))
			currently_ro = true;
		if (sb && (sb->s_flags & SB_RDONLY))
			currently_ro = true;
		if (currently_ro && !bbg_is_allowed_mount_sb(sb))
			return deny("remount protected partition rw", NULL,
				    path && path->dentry ? d_backing_inode(path->dentry) : NULL,
				    0);
	}

	if (!(flags & (MS_BIND | MS_MOVE | MS_REMOUNT |
		       MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE)) &&
	    !(flags & MS_RDONLY) && dev_name && dev_name[0] != '\0') {
		if (lookup_bdev_compat(dev_name, &dev) == 0 &&
		    !allow_has(dev) && !reverse_allow_match_and_cache(dev))
			return deny("mount protected partition rw", NULL,
				    path && path->dentry ? d_backing_inode(path->dentry) : NULL,
				    0);
	}

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
static int bb_sb_kern_mount(const struct super_block *sb)
#else
static int bb_sb_kern_mount(struct super_block *sb)
#endif
{
	if (!sb || MAJOR(sb->s_dev) == 0 || (sb->s_flags & SB_RDONLY))
		return 0;

	if (likely(current_process_trusted()))
		return 0;

	if (bbg_is_allowed_mount_sb(sb))
		return 0;

	return deny("kern_mount protected partition rw", NULL,
		    sb->s_root ? d_backing_inode(sb->s_root) : NULL, 0);
}

static int bb_sb_remount(struct super_block *sb, void *mnt_opts)
{
	(void)mnt_opts;

	if (!sb || MAJOR(sb->s_dev) == 0 || !(sb->s_flags & SB_RDONLY))
		return 0;

	if (likely(current_process_trusted()))
		return 0;

	if (bbg_is_allowed_mount_sb(sb))
		return 0;

	return deny("remount protected partition", NULL,
		    sb->s_root ? d_backing_inode(sb->s_root) : NULL, 0);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
static int bb_move_mount(const struct path *from_path, const struct path *to_path)
{
	(void)to_path;

	if (likely(current_process_trusted()))
		return 0;

	if (from_path && from_path->mnt && !(from_path->mnt->mnt_flags & MNT_READONLY)) {
		struct super_block *sb = from_path->mnt->mnt_sb;

		if (!sb && from_path->dentry && d_backing_inode(from_path->dentry))
			sb = d_backing_inode(from_path->dentry)->i_sb;
		if (sb && !(sb->s_flags & SB_RDONLY) && !bbg_is_allowed_mount_sb(sb))
			return deny("move_mount protected partition rw", NULL,
				    from_path->dentry ? d_backing_inode(from_path->dentry) : NULL,
				    0);
	}

	return 0;
}
#endif

extern int bb_bprm_set_creds(struct linux_binprm *bprm);
extern void bb_cred_transfer(struct cred *new, const struct cred *old);
extern int bb_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp);

static struct security_hook_list bb_hooks[] = {
	LSM_HOOK_INIT(file_permission,      bb_file_permission),
	LSM_HOOK_INIT(file_ioctl,           bb_file_ioctl),
	LSM_HOOK_INIT(inode_setattr, 		bb_inode_setattr),
	LSM_HOOK_INIT(sb_mount,             bb_sb_mount),
	LSM_HOOK_INIT(sb_kern_mount,        bb_sb_kern_mount),
	LSM_HOOK_INIT(sb_remount,           bb_sb_remount),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
	LSM_HOOK_INIT(move_mount,           bb_move_mount),
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
	LSM_HOOK_INIT(bprm_creds_for_exec,  bb_bprm_set_creds),
#else
	LSM_HOOK_INIT(bprm_set_creds, 		bb_bprm_set_creds),
#endif
	LSM_HOOK_INIT(cred_transfer, 		bb_cred_transfer),
	LSM_HOOK_INIT(cred_prepare, 	    bb_cred_prepare),

#ifdef BB_HAS_IOCTL_COMPAT
	LSM_HOOK_INIT(file_ioctl_compat,    bb_file_ioctl_compat),
#endif
};

static int __init bbg_init(void)
{
	security_add_hooks_compat(bb_hooks, ARRAY_SIZE(bb_hooks)); // init lsm hooks and print version notice
	pr_info("baseband_guard power by https://t.me/qdykernel\n");
	pr_info("baseband_guard repo: %s", __stringify(BBG_REPO));
	pr_info("baseband_guard version: %s", __stringify(BBG_VERSION));
	return 0;
}

extern struct lsm_blob_sizes bbg_blob_sizes;

#ifndef BBG_USE_DEFINE_LSM
security_initcall(bbg_init);
#else
DEFINE_LSM(baseband_guard) = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,19,0)
	// https://github.com/torvalds/linux/commit/9f9dc69e06ecbc61e7a50b823b82a78daf130dc0
	.id = &bbg_lsmid,
#else
	.name = "baseband_guard",
#endif
	.init = bbg_init,
	.blobs = &bbg_blob_sizes
};
#endif

MODULE_DESCRIPTION("protect All Block & Power by TG@qdykernel");
MODULE_AUTHOR("秋刀鱼 & https://t.me/qdykernel");
MODULE_LICENSE("GPL v2");


