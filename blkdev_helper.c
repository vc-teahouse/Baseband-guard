#include <linux/blkdev.h>
#include <linux/err.h>
#include <linux/string.h>

#include "baseband_guard.h"
#include "blkdev_compat.h"
#include "blkdev_helper.h"
#include "partition_match.h"

extern char *saved_command_line;
static const char *slot_suffix_from_cmdline(void)
{
	const char *p = saved_command_line;
	if (!p) return NULL;
	p = strstr(p, "androidboot.slot_suffix=");
	if (!p) return NULL;
	p += strlen("androidboot.slot_suffix=");
	if (p[0] == '_' && (p[1] == 'a' || p[1] == 'b')) return (p[1] == 'a') ? "_a" : "_b";
	return NULL;
}

static bool partition_name_in_allowlist(const char *name, size_t max_len)
{
	return bbg_partition_name_allowed(name, max_len,
					  slot_suffix_from_cmdline(),
					  allowlist_names, allowlist_cnt);
}

#if defined(BBG_HAS_BD_META_INFO) && defined(BBG_HAS_BLKDEV_GET_NO_OPEN)

/*
 * Linux 5.11+：
 *
 * dev_t
 *   -> struct block_device
 *   -> bd_meta_info
 *   -> volname
 */
bool is_allowed_partition_dev_resolve(dev_t dev)
{
	struct block_device *bdev;
	const struct partition_meta_info *info;
	bool allowed = false;

	if (!dev)
		return false;

	bdev = bbg_blkdev_get_no_open(dev);
	if (IS_ERR_OR_NULL(bdev))
		return false;

	info = READ_ONCE(bdev->bd_meta_info);
	if (info) {
		allowed = partition_name_in_allowlist(
			(const char *)info->volname,
			sizeof(info->volname));
	}

	bbg_blkdev_put_no_open(bdev);
	return allowed;
}

#elif defined(BBG_HAS_DISK_GET_PART)
#include <linux/genhd.h>

/*
 * Linux 3.18～5.10：
 *
 * dev_t
 *   -> struct gendisk + partno
 *   -> struct hd_struct
 *   -> info
 *   -> volname
 */
bool is_allowed_partition_dev_resolve(dev_t dev)
{
	struct gendisk *disk;
	struct hd_struct *part;
	const struct partition_meta_info *info;
	bool allowed = false;
	int partno = 0;

	if (!dev)
		return false;

	disk = get_gendisk(dev, &partno);
	if (!disk)
		return false;

	if (partno <= 0)
		goto out_put_disk;

	part = disk_get_part(disk, partno);
	if (!part)
		goto out_put_disk;

	info = READ_ONCE(part->info);
	if (info) {
		allowed = partition_name_in_allowlist(
			(const char *)info->volname,
			sizeof(info->volname));
	}

	disk_put_part(part);

out_put_disk:
	put_disk(disk);
	return allowed;
}

#else
#error "Baseband-guard: unsupported block partition metadata API"
#endif
