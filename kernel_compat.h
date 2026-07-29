#include <linux/blkdev.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/version.h>
#include "objsec.h"
#include "blkdev_compat.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
static __maybe_unused inline int lookup_bdev_compat(char *path, dev_t *out) {
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
static __maybe_unused inline int lookup_bdev_compat(char *path, dev_t *out) {
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
const struct lsm_id bbg_lsmid = {
	.name = "baseband_guard",
	.id = 995,
};
#endif

static __maybe_unused inline void __init security_add_hooks_compat(struct security_hook_list *hooks, int count) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
	security_add_hooks(hooks, count, &bbg_lsmid);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
	security_add_hooks(hooks, count, "baseband_guard");
#else
	security_add_hooks(hooks, count);
#endif

}
