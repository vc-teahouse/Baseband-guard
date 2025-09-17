#include <linux/blkdev.h>
#include <linux/security.h>

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
