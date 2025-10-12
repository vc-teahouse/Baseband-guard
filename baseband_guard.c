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
#include "kernel_compat.h"
#include "baseband_guard.h"

extern char *saved_command_line; 
static const char *slot_suffix_from_cmdline(void)
{
	const char *p = saved_command_line;
	if (!p) return NULL;
	p = strstr(p, "androidboot.slot_suffix=");
	if (!p) return NULL;
	p += strlen("androidboot.slot_suffix=");
	if (p[0] == '_' && (p[1] == 'a' || p[1] == 'b')) return (p[1] == 'a') ? "_a" : "_b";
	return NULL;
}

static bool inline resolve_byname_dev(const char *name, dev_t *out)
{
	char *path;
	dev_t dev;
	int ret;

	if (!name || !out) return false;

	path = kasprintf(GFP_KERNEL, "%s/%s", BB_BYNAME_DIR, name);
	if (!path) return false;

	ret = lookup_bdev_compat(path, &dev);
	kfree(path);
	if (ret) return false;

	*out = dev;
	return true;
}

struct allow_node { dev_t dev; struct hlist_node h; };
DEFINE_HASHTABLE(allowed_devs, 7);

static bool allow_has(dev_t dev)
{
	struct allow_node *p;
	hash_for_each_possible(allowed_devs, p, h, (u64)dev)
		if (p->dev == dev) return true;
	return false;
}

static void allow_add(dev_t dev)
{
	struct allow_node *n;
	if (!dev || allow_has(dev)) return;
	n = kmalloc(sizeof(*n), GFP_ATOMIC);
	if (!n) return;
	n->dev = dev;
	hash_add(allowed_devs, &n->h, (u64)dev);
	bb_pr("allow-cache dev %u:%u\n", MAJOR(dev), MINOR(dev));
}

static inline bool is_allowed_partition_dev_resolve(dev_t cur)
{
	size_t i;
	dev_t dev;
	const char *suf = slot_suffix_from_cmdline();

	for (i = 0; i < allowlist_cnt; i++) {
		const char *n = allowlist_names[i];
		bool ok = false;

		if (resolve_byname_dev(n, &dev) && dev == cur) return true;

		if (!ok && suf) {
			char *nm = kasprintf(GFP_ATOMIC, "%s%s", n, suf);
			if (nm) {
				ok = resolve_byname_dev(nm, &dev);
				kfree(nm);
				if (ok && dev == cur) return true;
			}
		}
		if (!ok) {
			char *na = kasprintf(GFP_ATOMIC, "%s_a", n);
			char *nb = kasprintf(GFP_ATOMIC, "%s_b", n);
			if (na) {
				ok = resolve_byname_dev(na, &dev);
				kfree(na);
				if (ok && dev == cur) { if (nb) kfree(nb); return true; }
			}
			if (nb) {
				ok = resolve_byname_dev(nb, &dev);
				kfree(nb);
				if (ok && dev == cur) return true;
			}
		}
	}
	return false;
}

static bool is_zram_device(dev_t dev)
{
	struct block_device *bdev;
	bool is_zram = bbg_is_named_device(dev, "zram");
	if (is_zram) {
		bb_pr("zram dev %u:%u (%s) identified, whitelisting\n",
				MAJOR(dev), MINOR(dev), bdev->bd_disk->disk_name);
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

#ifdef CONFIG_BBG_DOMAIN_PROTECTION_TRACE_ALL_SU
extern int current_process_trusted(void);
#endif

static bool current_domain_allowed(void)
{
#ifdef CONFIG_SECURITY_SELINUX
	u32 sid = 0;
	char *ctx = NULL;
	u32 len = 0;
	bool ok = false;
	size_t i;

	security_cred_getsecid_compat(current_cred(), &sid);

	if (!sid) return false;
	if (security_secid_to_secctx(sid, &ctx, &len)) return false;
	if (!ctx || !len) goto out;

	for (i = 0; i < allowed_domain_substrings_cnt; i++) {
		const char *needle = allowed_domain_substrings[i];
		if (needle && *needle) {
			if (strnstr(ctx, needle, len)) { ok = true; break; }
		}
	}
out:
	security_release_secctx(ctx, len);
	return ok;
#else
	return false;
#endif
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

static void bbg_log_deny_detail(const char *why, struct file *file, unsigned int cmd_opt)
{
	u32 sid = 0;
	char *ctx = NULL;
	u32 len = 0;
	const int PATH_BUFLEN = 256;
	const int CMD_BUFLEN  = 256;

	char *pathbuf = kmalloc(PATH_BUFLEN, GFP_ATOMIC);
	char *cmdbuf  = kmalloc(CMD_BUFLEN,  GFP_ATOMIC);

	const char *path = pathbuf ? bbg_file_path(file, pathbuf, PATH_BUFLEN) : NULL;
	struct inode *inode = file ? file_inode(file) : NULL;
	dev_t dev = inode ? inode->i_rdev : 0;

	if (cmdbuf)
		bbg_get_cmdline(cmdbuf, CMD_BUFLEN);

	security_cred_getsecid_compat(current_cred(), &sid);

	if (!sid || security_secid_to_secctx(sid, &ctx, &len) || !ctx || !len) {
		ctx = "unknown";
		len = strlen("unknown");
	}

	if (cmd_opt) {
		pr_info(
			"baseband_guard: deny %s cmd=0x%x dev=%u:%u path=%s pid=%d selinux_domain: %.*s comm=%s argv=\"%s\"\n",
			why, cmd_opt, MAJOR(dev), MINOR(dev),
			path ? path : "?", current->pid, len, ctx, current->comm,
			cmdbuf ? cmdbuf : "?");
	} else {
		pr_info(
			"baseband_guard: deny %s dev=%u:%u path=%s pid=%d selinux_domain: %.*s comm=%s argv=\"%s\"\n",
			why, MAJOR(dev), MINOR(dev),
			path ? path : "?", current->pid, len, ctx, current->comm,
			cmdbuf ? cmdbuf : "?");
	}

	kfree(cmdbuf);
	kfree(pathbuf);
}

static int deny(const char *why, struct file *file, unsigned int cmd_opt)
{
	bbg_log_deny_detail(why, file, cmd_opt);
	bb_pr_rl("deny %s pid=%d comm=%s\n", why, current->pid, current->comm);
	if (!BB_ENFORCING) return 0;
	return -EPERM;
}

static int bb_file_permission(struct file *file, int mask)
{
	struct inode *inode;

	if (!(mask & MAY_WRITE)) return 0;
	if (!file) return 0;

	inode = file_inode(file);
	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	if (likely(current_domain_allowed() && current_process_trusted()))
		return 0;

	if (allow_has(inode->i_rdev) || reverse_allow_match_and_cache(inode->i_rdev))
		return 0;

	return deny("write to protected partition", file, 0);
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

	if (likely(current_domain_allowed() && current_process_trusted()))
		return 0;

	if (allow_has(inode->i_rdev) || reverse_allow_match_and_cache(inode->i_rdev))
		return 0;

	return deny("destructive ioctl on protected partition", file, cmd);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
static int bb_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
	return bb_file_ioctl(file, cmd, arg);
}
#endif

#ifdef CONFIG_BBG_DOMAIN_PROTECTION_TRACE_ALL_SU
extern int bb_bprm_set_creds(struct linux_binprm *bprm);
extern void bb_cred_transfer(struct cred *new, const struct cred *old);
extern int bb_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp);
#endif

static struct security_hook_list bb_hooks[] = {
	LSM_HOOK_INIT(file_permission,      bb_file_permission),
	LSM_HOOK_INIT(file_ioctl,           bb_file_ioctl),

#ifdef CONFIG_BBG_DOMAIN_PROTECTION_TRACE_ALL_SU
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
	LSM_HOOK_INIT(bprm_creds_for_exec,  bb_bprm_set_creds),
#else
	LSM_HOOK_INIT(bprm_set_creds, 		bb_bprm_set_creds),
#endif
	LSM_HOOK_INIT(cred_transfer, 		bb_cred_transfer),
	LSM_HOOK_INIT(cred_prepare, 	    bb_cred_prepare),
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
	LSM_HOOK_INIT(file_ioctl_compat,    bb_file_ioctl_compat),
#endif
};

static int __init bbg_init(void)
{
	security_add_hooks_compat(bb_hooks, ARRAY_SIZE(bb_hooks));
	pr_info("baseband_guard power by https://t.me/qdykernel\n");
	pr_info("baseband_guard repo: %s", __stringify(BBG_REPO));
	pr_info("baseband_guard version: %s", __stringify(BBG_VERSION));
	return 0;
}

#ifdef CONFIG_BBG_DOMAIN_PROTECTION_TRACE_ALL_SU
extern struct lsm_blob_sizes bbg_blob_sizes;
#endif

#ifndef BBG_USE_DEFINE_LSM
security_initcall(bbg_init);
#else
DEFINE_LSM(baseband_guard) = {
	.name = "baseband_guard",
	.init = bbg_init,
#ifdef CONFIG_BBG_DOMAIN_PROTECTION_TRACE_ALL_SU
	.blobs = &bbg_blob_sizes
#endif
};
#endif

MODULE_DESCRIPTION("protect All Block & Power by TG@qdykernel");
MODULE_AUTHOR("秋刀鱼 & https://t.me/qdykernel");
MODULE_LICENSE("GPL v2");


