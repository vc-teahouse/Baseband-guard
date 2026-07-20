#ifndef _BBG_TEST_LINUX_GENHD_H_
#define _BBG_TEST_LINUX_GENHD_H_

#include <linux/blkdev.h>

struct gendisk *get_gendisk(dev_t dev, int *partno);
void put_disk(struct gendisk *disk);

#endif
