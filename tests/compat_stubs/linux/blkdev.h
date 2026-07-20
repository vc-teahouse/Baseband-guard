#ifndef _BBG_TEST_LINUX_BLKDEV_H_
#define _BBG_TEST_LINUX_BLKDEV_H_

#include <stdbool.h>
#include <stddef.h>

typedef unsigned int dev_t;

#define __maybe_unused

struct gendisk {
	char disk_name[32];
};

struct block_device {
	struct gendisk *bd_disk;
};

#endif
