#include <stdbool.h>
#include <stdio.h>

#include "../blkdev_compat.h"

static struct gendisk fake_disk = { "zram0" };
static bool lookup_missing;
static int get_count;
static int put_count;

struct gendisk *get_gendisk(dev_t dev, int *partno)
{
	(void)dev;
	get_count++;
	*partno = 0;
	return lookup_missing ? NULL : &fake_disk;
}

void put_disk(struct gendisk *disk)
{
	if (disk == &fake_disk)
		put_count++;
}

static void reset_lookup(bool missing)
{
	lookup_missing = missing;
	get_count = 0;
	put_count = 0;
}

static int expect_counts(const char *label, int expected_get,
			 int expected_put)
{
	if (get_count == expected_get && put_count == expected_put)
		return 0;
	fprintf(stderr, "FAIL %s refs: get=%d put=%d expected=%d/%d\n",
		label, get_count, put_count, expected_get, expected_put);
	return 1;
}

int main(void)
{
	int failures = 0;

	reset_lookup(true);
	if (bbg_is_named_device(1, "zram")) {
		fprintf(stderr, "FAIL missing lookup matched device\n");
		failures++;
	}
	failures += expect_counts("missing lookup", 1, 0);

	reset_lookup(false);
	if (!bbg_is_named_device(1, "zram")) {
		fprintf(stderr, "FAIL normal lookup missed prefix\n");
		failures++;
	}
	failures += expect_counts("normal lookup", 1, 1);

	reset_lookup(false);
	if (bbg_is_named_device(1, "loop")) {
		fprintf(stderr, "FAIL prefix mismatch matched device\n");
		failures++;
	}
	failures += expect_counts("prefix mismatch", 1, 1);

	reset_lookup(false);
	if (bbg_is_named_device(1, NULL)) {
		fprintf(stderr, "FAIL null prefix matched device\n");
		failures++;
	}
	failures += expect_counts("null prefix", 1, 1);

	return failures ? 1 : 0;
}
