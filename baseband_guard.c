#include <linux/module.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include <linux/cred.h>
#include <linux/limits.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#include "baseband_guard.h"

extern char *saved_command_line; 
#define BB_ENFORCING                 1

#ifdef CONFIG_SECURITY_BASEBAND_GUARD_ALLOW_IN_RECOVERY
#define BB_ALLOW_IN_RECOVERY         1
#else
#define BB_ALLOW_IN_RECOVERY         0
#endif

#ifdef CONFIG_SECURITY_BASEBAND_GUARD_PROTECT_BOOTIMG
#define BB_PROTECT_BOOTIMG           1
#else
#define BB_PROTECT_BOOTIMG           0
#endif

#ifdef CONFIG_SECURITY_BASEBAND_GUARD_BLOCK_WHOLEDISK
#define BB_BLOCK_WHOLEDISK           1
#else
#define BB_BLOCK_WHOLEDISK           0
#endif

#ifdef CONFIG_SECURITY_BASEBAND_GUARD_VERBOSE
#define BB_VERBOSE                   1
#else
#define BB_VERBOSE                   0
#endif

#define BB_BYNAME_DIR   "/dev/block/by-name"

static const char * const qcom_core_parts[] = {
"modem","modemst1","modemst2","fsg","fsc","bluetooth",
"dsp","cdsp","qweslicstore","qweslicstorebak",
"xbl","xbl_config","abl","tz","hyp","cmnlib","cmnlib64",
"keymaster","devcfg","uefisecapp","qupfw","featenabler",
"vbmeta","vbmeta_system","vbmeta_vendor","vbmeta_system_ext",
"keystore","rpm","rpmfw","uefi","spunvm","apdp","msadp","ocdt"
};

static const char * const bootimg_parts[] = {
"boot","dtbo","vendor_boot","init_boot","recovery"
};

static const char * const wholedisk_prefixes[] = { "sd", "mmcblk", "nvme" };

struct bbg_node { dev_t dev; struct hlist_node h; };
DEFINE_HASHTABLE(bbg_protected_devs, 8); 

static bool in_recovery_mode(void)
{
#if BB_ALLOW_IN_RECOVERY
if (!saved_command_line)
	return false;
if (strstr(saved_command_line, "androidboot.mode=recovery"))
	return true;
if (strstr(saved_command_line, "skip_initramfs=1") &&
	strstr(saved_command_line, "recovery"))
	return true;
#endif
return false;
}

static bool is_write_open(const struct file *file)
{
if (!file) return false;
if (file->f_mode & FMODE_WRITE) return true;
return ((file->f_flags & O_ACCMODE) != O_RDONLY);
}

static bool is_wholedisk(struct block_device *bdev)
{
size_t i;
const char *dn;

if (!bdev || !bdev->bd_disk)
	return false;
dn = bdev->bd_disk->disk_name;
if (!dn)
	return false;

for (i = 0; i < ARRAY_SIZE(wholedisk_prefixes); i++) {
	size_t p = strlen(wholedisk_prefixes[i]);
	if (!strncmp(dn, wholedisk_prefixes[i], p))
		return true;
}
return false;
}

static void bbg_protect_dev(dev_t dev)
{
struct bbg_node *n;

if (!dev)
	return;

{
	struct bbg_node *cur;
	hash_for_each_possible(bbg_protected_devs, cur, h, (u64)dev) {
		if (cur->dev == dev)
			return;
	}
}

n = kmalloc(sizeof(*n), GFP_KERNEL);
if (!n)
	return;
n->dev = dev;
hash_add(bbg_protected_devs, &n->h, (u64)dev);

#if BB_VERBOSE
pr_info("baseband_guard: protect dev %u:%u\n", MAJOR(dev), MINOR(dev));
#endif
}

static bool bbg_is_protected_dev(dev_t dev)
{
struct bbg_node *cur;
hash_for_each_possible(bbg_protected_devs, cur, h, (u64)dev) {
	if (cur->dev == dev) return true;
}
return false;
}

static int deny(const char *why)
{
if (!BB_ENFORCING)
	return 0;
if (BB_ALLOW_IN_RECOVERY && in_recovery_mode())
	return 0;
#if BB_VERBOSE
pr_info("baseband_guard: deny %s pid=%d comm=%s\n",
	why, current->pid, current->comm);
#endif
return -EPERM;
}


static int bbg_try_add_one(const char *name)
{
char *path;
struct path p;
struct inode *inode;
int ret;

path = kasprintf(GFP_KERNEL, "%s/%s", BB_BYNAME_DIR, name);
if (!path)
	return -ENOMEM;

ret = kern_path(path, LOOKUP_FOLLOW, &p);
kfree(path);
if (ret)
	return ret;

inode = d_backing_inode(p.dentry);
if (inode && S_ISBLK(inode->i_mode)) {
	bbg_protect_dev(inode->i_rdev);
#if BB_VERBOSE
	pr_info("baseband_guard: protect dev %u:%u for %s\n",
		MAJOR(inode->i_rdev), MINOR(inode->i_rdev), name);
#endif
}
path_put(&p);
return 0;
}

static void bbg_scan_byname_fixedlist(void)
{
size_t i;

for (i = 0; i < ARRAY_SIZE(qcom_core_parts); i++) {
	const char *n = qcom_core_parts[i];
	bbg_try_add_one(n);
	/* 自动识别A/B分区 */
	{
		char buf[64];
		if (snprintf(buf, sizeof(buf), "%s_a", n) < sizeof(buf))
			bbg_try_add_one(buf);
		if (snprintf(buf, sizeof(buf), "%s_b", n) < sizeof(buf))
			bbg_try_add_one(buf);
	}
}

#if BB_PROTECT_BOOTIMG
for (i = 0; i < ARRAY_SIZE(bootimg_parts); i++) {
	const char *n = bootimg_parts[i];
	bbg_try_add_one(n);
	{
		char buf[64];
		if (snprintf(buf, sizeof(buf), "%s_a", n) < sizeof(buf))
			bbg_try_add_one(buf);
		if (snprintf(buf, sizeof(buf), "%s_b", n) < sizeof(buf))
			bbg_try_add_one(buf);
	}
}
#endif
}

static struct delayed_work bbg_scan_work;
static atomic_t bbg_scan_done = ATOMIC_INIT(0);
static int bbg_scan_retries;

static int bbg_protected_count(void)
{
struct bbg_node *cur; unsigned bkt; int n = 0;
hash_for_each(bbg_protected_devs, bkt, cur, h) n++;
return n;
}

static void bbg_scan_worker(struct work_struct *ws)
{
int before = bbg_protected_count();
bbg_scan_byname_fixedlist();
if (bbg_protected_count() > before) {
	atomic_set(&bbg_scan_done, 1);
#if BB_VERBOSE
	pr_info("baseband_guard: scan OK, protected=%d\n", bbg_protected_count());
#endif
} else if (++bbg_scan_retries < BBG_SCAN_MAX_RETRY) {
	schedule_delayed_work(&bbg_scan_work, msecs_to_jiffies(BBG_SCAN_RETRY_MS));
#if BB_VERBOSE
	pr_info("baseband_guard: scan retry %d (by-name not ready?)\n", bbg_scan_retries);
#endif
} else {
	atomic_set(&bbg_scan_done, 1);
#if BB_VERBOSE
	pr_info("baseband_guard: scan give up, protected=%d\n", bbg_protected_count());
#endif
}
}

/* ===== LSM钩子 ===== */

static int bb_file_open(struct file *file)
{
struct inode *inode;
struct block_device *bdev;

if (!file)
	return 0;

inode = file_inode(file);

if (!S_ISBLK(inode->i_mode) || !is_write_open(file))
	return 0;

bdev = I_BDEV(inode);

#if BB_BLOCK_WHOLEDISK
if (is_wholedisk(bdev))
	return deny("open wholedisk writable");
#endif

if (bbg_is_protected_dev(inode->i_rdev))
	return deny("open protected partition writable");

#if BB_VERBOSE
{
	const char *dn = (bdev && bdev->bd_disk) ? bdev->bd_disk->disk_name : "?";
	pr_info("baseband_guard: pass blk open fmode=%x flags=%x disk=%s dev=%u:%u\n",
		file->f_mode, file->f_flags, dn,
		MAJOR(inode->i_rdev), MINOR(inode->i_rdev));
}
#endif
return 0;
}

static bool is_destructive_ioctl(unsigned int cmd)
{
switch (cmd) {
case BLKDISCARD:
case BLKSECDISCARD:
case BLKZEROOUT:
#ifdef BLKDISCARDZEROES
case BLKDISCARDZEROES:
#endif
#ifdef BLKPG
case BLKPG:
#endif
#ifdef BLKTRIM
case BLKTRIM:
#endif
#ifdef BLKRESETZONE
case BLKRESETZONE:
#endif
#ifdef BLKOPENZONE
case BLKOPENZONE:
#endif
#ifdef BLKCLOSEZONE
case BLKCLOSEZONE:
#endif
#ifdef BLKRMZGROUP
case BLKRMZGROUP:
#endif
#ifdef BLKSETRO
case BLKSETRO:
#endif
#ifdef BLKROSET
case BLKROSET:
#endif
#ifdef BLKSETBADSECTORS
case BLKSETBADSECTORS:
#endif
case BLKRRPART:
	return true;
default:
	return false;
}
}

static int bb_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
struct inode *inode;
struct block_device *bdev;

if (!file)
	return 0;

inode = file_inode(file);
if (!S_ISBLK(inode->i_mode))
	return 0;

bdev = I_BDEV(inode);

if (bbg_is_protected_dev(inode->i_rdev)
#if BB_BLOCK_WHOLEDISK
	|| is_wholedisk(bdev)
#endif
	) {
	if (is_destructive_ioctl(cmd))
		return deny("destructive ioctl on protected device");
}

return 0;
}

static int bb_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
return bb_file_ioctl(file, cmd, arg);
}

static struct security_hook_list bb_hooks[] = {
LSM_HOOK_INIT(file_open, bb_file_open),
LSM_HOOK_INIT(file_ioctl, bb_file_ioctl),
LSM_HOOK_INIT(file_ioctl_compat, bb_file_ioctl_compat),
};

static int __init bb_init(void)
{
security_add_hooks(bb_hooks, ARRAY_SIZE(bb_hooks), "baseband_guard");
INIT_DELAYED_WORK(&bbg_scan_work, bbg_scan_worker);
schedule_delayed_work(&bbg_scan_work, msecs_to_jiffies(BBG_SCAN_DELAY_MS));

#if BB_VERBOSE
pr_info("baseband_guard: initialized (always ENFORCING), "
	"allow_in_recovery=%d, block_wholedisk=%d, delayed_scan=%ums\n",
	(int)BB_ALLOW_IN_RECOVERY, (int)BB_BLOCK_WHOLEDISK,
	(unsigned)BBG_SCAN_DELAY_MS);
pr_info("baseband_guard: scan retry policy: %ums x %d (failure-only)\n",
	(unsigned)BBG_SCAN_RETRY_MS, (int)BBG_SCAN_MAX_RETRY);
#endif
return 0;
}

DEFINE_LSM(baseband_guard) = {
.name = "baseband_guard",
.init = bb_init,
};
MODULE_DESCRIPTION("LSM保护基带/BL引导加载程序分区（基于dev_t、扫描直接分区）");
MODULE_AUTHOR("秋刀鱼");
MODULE_LICENSE("GPL v2");
