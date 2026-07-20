#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
	exit 2
fi

root=$1
public=$root/include/linux/blkdev.h
types=$root/include/linux/blk_types.h
legacy=$root/include/linux/genhd.h
private=$root/block/blk.h
flags=

append_flag()
{
	if [ -n "$flags" ]; then
		flags="$flags $1"
	else
		flags=$1
	fi
}

if grep -q 'disk_get_part' "$legacy" 2>/dev/null; then
	append_flag -DBBG_HAS_DISK_GET_PART
fi

if grep -q 'bd_meta_info' "$public" "$types" 2>/dev/null; then
	append_flag -DBBG_HAS_BD_META_INFO
fi

declarations=$(
	for file in "$public" "$private"; do
		if [ -f "$file" ]; then
			tr '\n' ' ' < "$file"
		fi
	done
)

has_get=false
has_put=false
if printf '%s\n' "$declarations" | grep -Eq \
	'blkdev_get_no_open[[:space:]]*\([^;]*dev_t[[:space:]]+dev'; then
	has_get=true
fi
if printf '%s\n' "$declarations" | grep -Eq \
	'blkdev_put_no_open[[:space:]]*\([^;]*struct[[:space:]]+block_device[[:space:]]*\*'; then
	has_put=true
fi

if [ "$has_get" = true ] && [ "$has_put" = true ]; then
	append_flag -DBBG_HAS_BLKDEV_GET_NO_OPEN
	if printf '%s\n' "$declarations" | grep -Eq \
		'blkdev_get_no_open[[:space:]]*\([^;]*dev_t[[:space:]]+dev[[:space:]]*,[[:space:]]*bool'; then
		append_flag -DBBG_BLKDEV_GET_NO_OPEN_HAS_AUTOLOAD
	fi
fi

printf '%s\n' "$flags"
