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
#include <linux/ratelimit.h>

#if defined(BBG_HAS_URING_CMD) && defined(CONFIG_IO_URING)
#if defined(BBG_URING_CMD_HEADER_CMD) && \
	defined(BBG_URING_CMD_HEADER_LEGACY)
#error "Baseband-guard: multiple io_uring command headers selected"
#elif defined(BBG_URING_CMD_HEADER_CMD)
#include <linux/io_uring/cmd.h>
#elif defined(BBG_URING_CMD_HEADER_LEGACY)
#include <linux/io_uring.h>
#else
#error "Baseband-guard: io_uring command header not selected"
#endif
#endif

#include "kernel_compat.h"
#include "baseband_guard.h"
#include "tracing/tracing.h"
#include "blkdev_helper.h"
#include "block_policy.h"

static DEFINE_RATELIMIT_STATE(bbg_deny_rs, DEFAULT_RATELIMIT_INTERVAL,
			      DEFAULT_RATELIMIT_BURST);

static bool is_zram_device(dev_t dev)
{
	bool is_zram = bbg_is_named_device(dev, "zram");
	if (is_zram) {
		bb_pr("zram dev %u:%u allowed for current access\n",
				MAJOR(dev), MINOR(dev));
	}
	return is_zram;
}

static bool is_allowed_block_device(dev_t dev)
{
	if (!dev) return false;
	return is_zram_device(dev) || is_allowed_partition_dev_resolve(dev);
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
	buf[0] = '\0';
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
	char *pathbuf;
	char *cmdbuf;
	const char *path;
	const char *cmdline = NULL;
	dev_t dev;

	pathbuf = kmalloc(PATH_BUFLEN, GFP_ATOMIC);
	cmdbuf = kmalloc(CMD_BUFLEN, GFP_ATOMIC);
	path = pathbuf ? bbg_file_path(file, pathbuf, PATH_BUFLEN) : NULL;
	dev = inode ? inode->i_rdev : 0;

	if (cmdbuf && bbg_get_cmdline(cmdbuf, CMD_BUFLEN) > 0)
		cmdline = cmdbuf;

	pr_info(
		"baseband_guard: deny %s cmd=0x%x dev=%u:%u path=%s pid=%d comm=%s argv=\"%s\"\n",
		why, cmd_opt, MAJOR(dev), MINOR(dev),
		path ? path : "?", current->pid, current->comm,
		cmdline ? cmdline : "?");

	kfree(cmdbuf);
	kfree(pathbuf);
}

static int deny(const char *why, struct file *file, struct inode *inode, unsigned int cmd_opt)
{
	if (__ratelimit(&bbg_deny_rs))
		bbg_log_deny_detail(why, file, inode, cmd_opt);
	if (!BB_ENFORCING) return 0;
	return -EPERM;
}

#if defined(BBG_HAS_URING_CMD) && defined(CONFIG_IO_URING)
static int bb_uring_cmd(struct io_uring_cmd *ioucmd)
{
	struct file *file;
	struct inode *inode;

	if (!ioucmd) return 0;
	file = ioucmd->file;
	if (!file) return 0;

	inode = file_inode(file);
	if (!inode || likely(!S_ISBLK(inode->i_mode))) return 0;
	if (likely(current_process_trusted())) return 0;

	if (bbg_block_uring_allowed(false))
		return 0;
	return deny("unsafe uring command on block device", file, inode, 0);
}
#endif

static int bb_file_open(struct file *file)
{
	struct inode *inode;

	if (likely(current_process_trusted()))
		return 0;
	if (!file) return 0;

	inode = file_inode(file);
	if (!inode || likely(!S_ISBLK(inode->i_mode))) return 0;
	if (!(file->f_mode & FMODE_WRITE)) return 0;

	if (bbg_block_write_allowed(false,
			is_allowed_block_device(inode->i_rdev)))
		return 0;

	return deny("write-capable open on protected partition", file, inode, 0);
}

static int bb_file_permission(struct file *file, int mask)
{
	struct inode *inode;

	if (likely(current_process_trusted()))
		return 0;

	if (!(mask & MAY_WRITE)) return 0;
	if (!file) return 0;

	inode = file_inode(file);
	if (!inode || likely(!S_ISBLK(inode->i_mode))) return 0;

	if (bbg_block_write_allowed(false,
			is_allowed_block_device(inode->i_rdev)))
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
	if (!dentry) return 0;

	inode = d_inode(dentry);

	if (!inode || likely(!S_ISBLK(inode->i_mode))) return 0;

	if (bbg_block_write_allowed(false,
			is_allowed_block_device(inode->i_rdev)))
		return 0;

	return deny("setattr on protected partition", 0, inode, 0);
}

static int bb_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode;
	bool device_allowed;

	if (likely(current_process_trusted()))
		return 0;
	if (!file) return 0;

	inode = file_inode(file);
	if (!inode || likely(!S_ISBLK(inode->i_mode))) return 0;

	if (bbg_block_ioctl_allowed(false, false, cmd))
		return 0;
	if (!bbg_block_ioctl_allowed(false, true, cmd))
		return deny("unsafe ioctl on block device", file, inode, cmd);

	/* Only bounded mutations differ between the two policy probes. */
	device_allowed = is_allowed_block_device(inode->i_rdev);
	if (bbg_block_ioctl_allowed(false, device_allowed, cmd))
		return 0;

	return deny("unsafe ioctl on block device", file, inode, cmd);
}

#ifdef BB_HAS_IOCTL_COMPAT
static int bb_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
	return bb_file_ioctl(file, bbg_block_ioctl_compat_normalize(cmd), arg);
}
#endif

extern int bb_bprm_set_creds(struct linux_binprm *bprm);
extern void bb_cred_transfer(struct cred *new, const struct cred *old);
extern int bb_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp);

static struct security_hook_list bb_hooks[] = {
	LSM_HOOK_INIT(file_open,            bb_file_open),
	LSM_HOOK_INIT(file_permission,      bb_file_permission),
	LSM_HOOK_INIT(file_ioctl,           bb_file_ioctl),
#if defined(BBG_HAS_URING_CMD) && defined(CONFIG_IO_URING)
	LSM_HOOK_INIT(uring_cmd,             bb_uring_cmd),
#endif
	LSM_HOOK_INIT(inode_setattr, 		bb_inode_setattr),

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
	.name = "baseband_guard",
	.init = bbg_init,
	.blobs = &bbg_blob_sizes
};
#endif

MODULE_DESCRIPTION("protect All Block & Power by TG@qdykernel");
MODULE_AUTHOR("秋刀鱼 & https://t.me/qdykernel");
MODULE_LICENSE("GPL v2");


