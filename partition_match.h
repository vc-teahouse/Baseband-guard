#ifndef _BBG_PARTITION_MATCH_H_
#define _BBG_PARTITION_MATCH_H_

#ifdef BBG_HOST_TEST
#include <stdbool.h>
#include <stddef.h>
#else
#include <linux/types.h>
#endif

bool bbg_partition_name_allowed(const char *name, size_t max_len,
				const char *slot_suffix,
				const char * const *allowlist,
				size_t allowlist_count);

#endif
