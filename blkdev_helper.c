#include <linux/version.h>
#include <linux/blkdev.h>
#include <linux/err.h>
#include <linux/string.h>

#include "baseband_guard.h"
#include "blkdev_helper.h"

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

static bool partition_name_matches(const char *partition_name,
				   size_t partition_len,
				   const char *base_name,
				   const char *suffix)
{
	size_t base_len;
	size_t suffix_len;

	if (!partition_name || !base_name || !suffix)
		return false;

	base_len = strlen(base_name);
	suffix_len = strlen(suffix);

	if (partition_len != base_len + suffix_len)
		return false;

	return !memcmp(partition_name, base_name, base_len) &&
	       !memcmp(partition_name + base_len, suffix, suffix_len);
}

static bool partition_name_in_allowlist(const char *name, size_t max_len)
{
	const char *slot_suffix = slot_suffix_from_cmdline();
	size_t name_len;
	size_t i;

	if (!name || !max_len)
		return false;

	name_len = strnlen(name, max_len);
	if (!name_len || name_len == max_len)
		return false;

	for (i = 0; i < allowlist_cnt; i++) {
		const char *allowed = allowlist_names[i];
		size_t allowed_len;

		if (!allowed)
			continue;

		allowed_len = strlen(allowed);

		if (name_len == allowed_len &&
		    !memcmp(name, allowed, name_len))
			return true;

		if (slot_suffix) {
			if (partition_name_matches(name, name_len,
						   allowed, slot_suffix))
				return true;

			continue;
		}

		if (partition_name_matches(name, name_len,
					   allowed, "_a"))
			return true;

		if (partition_name_matches(name, name_len,
					   allowed, "_b"))
			return true;
	}

	return false;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0) || defined(BBG_COMPAT_HAS_BLOCK_DEVICE_API)

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

	bdev = blkdev_get_no_open(dev);
	if (IS_ERR_OR_NULL(bdev))
		return false;

	info = READ_ONCE(bdev->bd_meta_info);
	if (info) {
		allowed = partition_name_in_allowlist(
			(const char *)info->volname,
			sizeof(info->volname));
	}

	blkdev_put_no_open(bdev);
	return allowed;
}

#else
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

#endif