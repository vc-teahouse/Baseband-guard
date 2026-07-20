#include <stdbool.h>
#include <stdio.h>

#define BBG_HAS_BLKDEV_GET_NO_OPEN
#include "../blkdev_compat.h"

bool bbg_test_lookup_missing;

static struct gendisk fake_disk = { "zram0" };
static struct block_device fake_bdev = { &fake_disk };
static int get_count;
static int put_count;

struct block_device *blkdev_get_no_open(dev_t dev)
{
	(void)dev;
	get_count++;
	return &fake_bdev;
}

void blkdev_put_no_open(struct block_device *bdev)
{
	if (bdev == &fake_bdev)
		put_count++;
}

int main(void)
{
	int failures = 0;

	bbg_test_lookup_missing = true;
	get_count = 0;
	put_count = 0;
	if (bbg_is_named_device(1, "zram")) {
		fprintf(stderr, "FAIL missing lookup matched device\n");
		failures++;
	}

	bbg_test_lookup_missing = false;
	get_count = 0;
	put_count = 0;
	if (!bbg_is_named_device(1, "zram")) {
		fprintf(stderr, "FAIL normal lookup missed device\n");
		failures++;
	}
	if (get_count != 1 || put_count != 1) {
		fprintf(stderr, "FAIL unbalanced lookup: get=%d put=%d\n",
			get_count, put_count);
		failures++;
	}

	return failures ? 1 : 0;
}
