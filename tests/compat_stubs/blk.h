#ifndef _BBG_TEST_BLK_H_
#define _BBG_TEST_BLK_H_

#include <linux/blkdev.h>

struct block_device *blkdev_get_no_open(dev_t dev);
void blkdev_put_no_open(struct block_device *bdev);

#endif
