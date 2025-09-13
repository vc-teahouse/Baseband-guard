#include <linux/module.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/namei.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/hashtable.h>

#define BB_ENFORCING 1

#ifdef CONFIG_SECURITY_BASEBAND_GUARD_VERBOSE
#define BB_VERBOSE 1
#else
#define BB_VERBOSE 0
#endif

#define bb_pr(fmt, ...)    pr_debug("baseband_guard: " fmt, ##__VA_ARGS__)
#define bb_pr_rl(fmt, ...) pr_info_ratelimited("baseband_guard: " fmt, ##__VA_ARGS__)

#define BB_BYNAME_DIR "/dev/block/by-name"

static const char * const allowed_domain_substrings[] = {
	"update_engine",
	"fastbootd",
	"recovery",
	"rmt_storage",
	"oplus",
	"oppo",
	"feature",
	"swap",
	"system_perf_init",
	"hal_bootctl_default",
	"fsck",
	"vendor_qti",
	"mi_ric",
};
static const size_t allowed_domain_substrings_cnt = ARRAY_SIZE(allowed_domain_substrings);

static const char * const allowlist_names[] = {
	"boot", "init_boot", "dtbo", "vendor_boot",
	"userdata", "cache", "metadata", "misc",
};
static const size_t allowlist_cnt = ARRAY_SIZE(allowlist_names);

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

static bool resolve_byname_dev(const char *name, dev_t *out)
{
	char *path;
	
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
       struct block_device *bdev;
#else
        dev_t dev;
		int ret;
#endif

	if (!name || !out) return false;

	path = kasprintf(GFP_KERNEL, "%s/%s", BB_BYNAME_DIR, name);
	if (!path) return false;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
	bdev = lookup_bdev(path);
	kfree(path);
	if (IS_ERR(bdev))
		return false;
	*out = bdev->bd_dev;
	bdput(bdev);
	return true;
#else
	ret = lookup_bdev(path, &dev);
	kfree(path);
	if (ret) return false;

	*out = dev;
	return true;
#endif
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
#if BB_VERBOSE
	bb_pr("allow-cache dev %u:%u\n", MAJOR(dev), MINOR(dev));
#endif
}

static bool is_allowed_partition_dev_resolve(dev_t cur)
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

static bool reverse_allow_match_and_cache(dev_t cur)
{
	if (!cur) return false;
	if (is_allowed_partition_dev_resolve(cur)) { allow_add(cur); return true; }
	return false;
}

static bool current_domain_allowed(void)
{
#ifdef CONFIG_SECURITY_SELINUX
	u32 sid = 0;
	char *ctx = NULL;
	u32 len = 0;
	bool ok = false;
	size_t i;

	security_cred_getsecid(current_cred(), &sid);
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
	const int PATH_BUFLEN = 256;
	const int CMD_BUFLEN  = 256;

	char *pathbuf = kmalloc(PATH_BUFLEN, GFP_ATOMIC);
	char *cmdbuf  = kmalloc(CMD_BUFLEN,  GFP_ATOMIC);

	const char *path = pathbuf ? bbg_file_path(file, pathbuf, PATH_BUFLEN) : NULL;
	struct inode *inode = file ? file_inode(file) : NULL;
	dev_t dev = inode ? inode->i_rdev : 0;

	if (cmdbuf)
		bbg_get_cmdline(cmdbuf, CMD_BUFLEN);

#if BB_VERBOSE
	if (cmd_opt) {
		pr_info_ratelimited(
			"baseband_guard: deny %s cmd=0x%x dev=%u:%u path=%s pid=%d comm=%s argv=\"%s\"\n",
			why, cmd_opt, MAJOR(dev), MINOR(dev),
			path ? path : "?", current->pid, current->comm,
			cmdbuf ? cmdbuf : "?");
	} else {
		pr_info_ratelimited(
			"baseband_guard: deny %s dev=%u:%u path=%s pid=%d comm=%s argv=\"%s\"\n",
			why, MAJOR(dev), MINOR(dev),
			path ? path : "?", current->pid, current->comm,
			cmdbuf ? cmdbuf : "?");
	}
#else
	if (cmd_opt) {
		pr_info_ratelimited(
			"baseband_guard: deny %s cmd=0x%x dev=%u:%u path=%s pid=%d\n",
			why, cmd_opt, MAJOR(dev), MINOR(dev),
			path ? path : "?", current->pid);
	} else {
		pr_info_ratelimited(
			"baseband_guard: deny %s dev=%u:%u path=%s pid=%d\n",
			why, MAJOR(dev), MINOR(dev),
			path ? path : "?", current->pid);
	}
#endif

	kfree(cmdbuf);
	kfree(pathbuf);
}

static int deny(const char *why, struct file *file, unsigned int cmd_opt)
{
	if (!BB_ENFORCING) return 0;
	bbg_log_deny_detail(why, file, cmd_opt);
	bb_pr_rl("deny %s pid=%d comm=%s\n", why, current->pid, current->comm);
	return -EPERM;
}

static int bb_file_permission(struct file *file, int mask)
{
	struct inode *inode;

	if (!(mask & MAY_WRITE)) return 0;
	if (!file) return 0;

	inode = file_inode(file);
	if (!S_ISBLK(inode->i_mode)) return 0;

	if (current_domain_allowed())
		return 0;

	if (allow_has(inode->i_rdev) || reverse_allow_match_and_cache(inode->i_rdev))
		return 0;

	return deny("write to protected partition", file, 0);
}

static bool is_destructive_ioctl(unsigned int cmd)
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
	if (!S_ISBLK(inode->i_mode)) return 0;

	if (!is_destructive_ioctl(cmd))
		return 0;

	if (current_domain_allowed())
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

static struct security_hook_list bb_hooks[] = {
	LSM_HOOK_INIT(file_permission,      bb_file_permission),
	LSM_HOOK_INIT(file_ioctl,           bb_file_ioctl),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
	LSM_HOOK_INIT(file_ioctl_compat,    bb_file_ioctl_compat),
#endif
};

static int __init bbg_init(void)
{
	security_add_hooks(bb_hooks, ARRAY_SIZE(bb_hooks), "baseband_guard");
	pr_info("baseband_guard_all power by https://t.me/qdykernel\n");
	return 0;
}

DEFINE_LSM(baseband_guard) = {
	.name = "baseband_guard",
	.init = bbg_init,
};

MODULE_DESCRIPTION("protect ALL form TG@qdykernel");
MODULE_AUTHOR("秋刀鱼&https://t.me/qdykernel");
MODULE_LICENSE("GPL v2");

