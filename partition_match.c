#ifdef BBG_HOST_TEST
#include <string.h>
#else
#include <linux/string.h>
#endif

#include "partition_match.h"

static size_t bbg_bounded_strlen(const char *value, size_t max_len)
{
	size_t len;

	for (len = 0; len < max_len; len++)
		if (value[len] == '\0')
			break;
	return len;
}

static bool bbg_partition_name_matches(const char *name, size_t name_len,
				       const char *base, const char *suffix)
{
	size_t base_len = strlen(base);
	size_t suffix_len = strlen(suffix);

	return name_len == base_len + suffix_len &&
	       !memcmp(name, base, base_len) &&
	       !memcmp(name + base_len, suffix, suffix_len);
}

bool bbg_partition_name_allowed(const char *name, size_t max_len,
				const char *slot_suffix,
				const char * const *allowlist,
				size_t allowlist_count)
{
	size_t name_len;
	size_t i;

	if (!name || !max_len || !allowlist)
		return false;
	name_len = bbg_bounded_strlen(name, max_len);
	if (!name_len || name_len == max_len)
		return false;

	for (i = 0; i < allowlist_count; i++) {
		const char *allowed = allowlist[i];
		size_t allowed_len;

		if (!allowed)
			continue;
		allowed_len = strlen(allowed);
		if (name_len == allowed_len && !memcmp(name, allowed, name_len))
			return true;
		if (slot_suffix) {
			if (bbg_partition_name_matches(name, name_len, allowed,
						       slot_suffix))
				return true;
			continue;
		}
		if (bbg_partition_name_matches(name, name_len, allowed, "_a") ||
		    bbg_partition_name_matches(name, name_len, allowed, "_b"))
			return true;
	}

	return false;
}
