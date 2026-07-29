#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp_dir=${TMPDIR:-/tmp}/bbg-detect-block-api-$$
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

run_case()
{
	name=$1
	expected=$2
	root=$3
	actual=$(sh "$repo_dir/scripts/detect-block-api.sh" "$root")
	if [ "$actual" != "$expected" ]; then
		echo "FAIL $name: got '$actual' expected '$expected'" >&2
		exit 1
	fi
	echo "PASS $name"
}

mkdir -p "$tmp_dir/legacy/include/linux"
printf '%s\n' 'struct hd_struct *disk_get_part(struct gendisk *, int);' \
	> "$tmp_dir/legacy/include/linux/genhd.h"
run_case legacy '-DBBG_HAS_DISK_GET_PART' "$tmp_dir/legacy"

mkdir -p "$tmp_dir/modern/include/linux"
printf '%s\n' \
	'struct block_device { void *bd_meta_info; };' \
	'struct block_device *blkdev_get_no_open(dev_t dev);' \
	'void blkdev_put_no_open(struct block_device *bdev);' \
	> "$tmp_dir/modern/include/linux/blkdev.h"
run_case modern \
	'-DBBG_HAS_BD_META_INFO -DBBG_HAS_BLKDEV_GET_NO_OPEN' \
	"$tmp_dir/modern"

mkdir -p "$tmp_dir/missing-put/include/linux"
printf '%s\n' \
	'struct block_device { void *bd_meta_info; };' \
	'struct block_device *blkdev_get_no_open(dev_t dev);' \
	> "$tmp_dir/missing-put/include/linux/blkdev.h"
run_case missing-put '-DBBG_HAS_BD_META_INFO' "$tmp_dir/missing-put"

mkdir -p "$tmp_dir/autoload/include/linux" "$tmp_dir/autoload/block"
printf '%s\n' 'struct block_device { void *bd_meta_info; };' \
	> "$tmp_dir/autoload/include/linux/blkdev.h"
printf '%s\n' \
	'struct block_device *blkdev_get_no_open(dev_t dev, bool autoload);' \
	'void blkdev_put_no_open(struct block_device *bdev);' \
	> "$tmp_dir/autoload/block/blk.h"
run_case autoload \
	'-DBBG_HAS_BD_META_INFO -DBBG_HAS_BLKDEV_GET_NO_OPEN -DBBG_BLKDEV_GET_NO_OPEN_HAS_AUTOLOAD' \
	"$tmp_dir/autoload"

mkdir -p "$tmp_dir/partial/include/linux"
printf '%s\n' 'struct block_device { void *bd_meta_info; };' \
	> "$tmp_dir/partial/include/linux/blkdev.h"
run_case partial '-DBBG_HAS_BD_META_INFO' "$tmp_dir/partial"
