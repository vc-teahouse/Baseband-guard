#ifndef _BBG_BLKDEV_COMPAT_H_
#define _BBG_BLKDEV_COMPAT_H_

#include <linux/blkdev.h>
#include <linux/err.h>
#include <linux/string.h>

#ifdef BBG_HAS_BLKDEV_GET_NO_OPEN
#include "blk.h"
#else
#include <linux/genhd.h>
#endif

#ifdef BBG_HAS_BLKDEV_GET_NO_OPEN
static inline struct block_device *bbg_blkdev_get_no_open(dev_t dev)
{
#ifdef BBG_BLKDEV_GET_NO_OPEN_HAS_AUTOLOAD
	return blkdev_get_no_open(dev, false);
#else
	return blkdev_get_no_open(dev);
#endif
}

static inline void bbg_blkdev_put_no_open(struct block_device *bdev)
{
	blkdev_put_no_open(bdev);
}
#endif

static __maybe_unused bool bbg_is_named_device(dev_t dev,
					       const char *name_prefix)
{
	struct gendisk *disk;
#ifdef BBG_HAS_BLKDEV_GET_NO_OPEN
	struct block_device *bdev;
#else
	int partno = 0;
#endif
	bool match = false;

#ifdef BBG_HAS_BLKDEV_GET_NO_OPEN
	bdev = bbg_blkdev_get_no_open(dev);
	if (IS_ERR_OR_NULL(bdev))
		return false;
	disk = bdev->bd_disk;
#else
	disk = get_gendisk(dev, &partno);
	if (!disk)
		return false;
#endif

	if (disk && name_prefix) {
		const char *disk_name = disk->disk_name;
		size_t prefix_len = strlen(name_prefix);

		match = strncmp(disk_name, name_prefix, prefix_len) == 0;
	}

#ifdef BBG_HAS_BLKDEV_GET_NO_OPEN
	bbg_blkdev_put_no_open(bdev);
#else
	put_disk(disk);
#endif
	return match;
}

#endif
