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

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,5,0)
static inline struct block_device *blkdev_get_by_dev_compat(dev_t dev, fmode_t mode, void *holder)
{
	return blkdev_get_by_dev(dev,mode,holder);
}
static inline void blkdev_put_compat(struct block_device *dev, fmode_t mode, void *holder)
{
	blkdev_put(dev,mode);
}
#else
static inline struct block_device *blkdev_get_by_dev_compat(dev_t dev, fmode_t mode, void *holder)
{
	return blkdev_get_by_dev(dev,mode,holder,NULL);
}
static inline void blkdev_put_compat(struct block_device *dev, fmode_t mode, void *holder)
{
	blkdev_put(dev,holder);
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
