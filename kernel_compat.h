#include <linux/blkdev.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
static inline int lookup_bdev_compat(char *path, dev_t *out) {
    struct block_device *bdev;

    if (!path || !out) {
        return 1;
    }

    bdev = lookup_bdev(path);
	if (IS_ERR(bdev))
		return 1;
	*out = bdev->bd_dev;
	bdput(bdev);
	return 0;
}
#else
static inline int lookup_bdev_compat(char *path, dev_t *out) {
    dev_t dev;
	int ret;

    if (!path || !out) {
        return 1;
    }

    ret = lookup_bdev(path, &dev);
	if (ret) return ret;

	*out = dev;
	return 0;
}
#endif

// https://github.com/torvalds/linux/commit/22ae8ce8b89241c94ac00c237752c0ffa37ba5ae
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0) 

static bool bbg_is_named_device(dev_t dev, const char *name_prefix)
{
    struct block_device *bdev;
    bool match = false;

    bdev = blkdev_get_by_dev(dev, FMODE_READ, THIS_MODULE);
    if (IS_ERR(bdev))
        return false;

    if (bdev->bd_disk && name_prefix) {
        const char *disk_name = bdev->bd_disk->disk_name;
        size_t prefix_len = strlen(name_prefix);

        if (strncmp(disk_name, name_prefix, prefix_len) == 0) {
            match = true;
        }
    }

    blkdev_put(bdev, FMODE_READ);
    return match;
}
#else

static bool bbg_is_named_device(dev_t dev, const char *name_prefix)
{
    struct block_device *bdev;
    bool match = false;

// https://github.com/torvalds/linux/commit/5f33b5226c9d92359e58e91ad0bf0c1791da36a1
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,15,0)
    bdev = blkdev_get_no_open(dev);
#else
    bdev = blkdev_get_no_open(dev, true);
#endif

    if (IS_ERR(bdev))
        return false;

    if (bdev->bd_disk && name_prefix) {
        const char *disk_name = bdev->bd_disk->disk_name;
        size_t prefix_len = strlen(name_prefix);
        match = (strncmp(disk_name, name_prefix, prefix_len) == 0);
    }

    blkdev_put_no_open(bdev);

    return match;
}

#endif

#ifdef CONFIG_SECURITY_SELINUX

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0)
struct task_security_struct {
	u32 osid;		/* SID prior to last execve */
	u32 sid;		/* current SID */
	u32 exec_sid;		/* exec SID */
	u32 create_sid;		/* fscreate SID */
	u32 keycreate_sid;	/* keycreate SID */
	u32 sockcreate_sid;	/* fscreate SID */
};
static inline void security_cred_getsecid_compat(const struct cred *c, u32 *secid) {
    const struct task_security_struct *tsec;

    if (!c || !secid) {
        return;
    }

	tsec = c->security;
	*secid = tsec->sid;
}
#else
static inline void security_cred_getsecid_compat(const struct cred *c, u32 *secid) {
    security_cred_getsecid(c, secid);
}
#endif


#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
const struct lsm_id bbg_lsmid = {
	.name = "baseband_guard",
	.id = 995,
};
#endif

static inline void __init security_add_hooks_compat(struct security_hook_list *hooks, int count) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
	security_add_hooks(hooks, count, &bbg_lsmid);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
	security_add_hooks(hooks, count, "baseband_guard");
#else
	security_add_hooks(hooks, count);
#endif

}
