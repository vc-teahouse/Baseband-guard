#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "../partition_match.h"

static const char * const allowed[] = { "boot", "userdata", "misc" };
#define ALLOWED_COUNT (sizeof(allowed) / sizeof(allowed[0]))

struct test_case {
	const char *label;
	const char *name;
	size_t max_len;
	const char *slot_suffix;
	size_t allowlist_count;
	bool expected;
};

int main(void)
{
	static const char unterminated[] = { 'b', 'o', 'o', 't' };
	const struct test_case cases[] = {
		{ "exact", "boot", 5, "_a", ALLOWED_COUNT, true },
		{ "later allowlist entry", "userdata", 9, "_a", ALLOWED_COUNT, true },
		{ "later entry excluded by count", "userdata", 9, "_a", 1, false },
		{ "active a", "boot_a", 7, "_a", ALLOWED_COUNT, true },
		{ "inactive b", "boot_b", 7, "_a", ALLOWED_COUNT, false },
		{ "active b", "boot_b", 7, "_b", ALLOWED_COUNT, true },
		{ "both slots without cmdline", "boot_a", 7, NULL, ALLOWED_COUNT, true },
		{ "both slots without cmdline b", "boot_b", 7, NULL, ALLOWED_COUNT, true },
		{ "near prefix", "bootx", 6, "_a", ALLOWED_COUNT, false },
		{ "empty", "", 1, "_a", ALLOWED_COUNT, false },
		{ "unterminated", unterminated, sizeof(unterminated), "_a",
		  ALLOWED_COUNT, false },
	};
	size_t i;
	int failures = 0;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		bool actual = bbg_partition_name_allowed(
			cases[i].name, cases[i].max_len, cases[i].slot_suffix,
			allowed, cases[i].allowlist_count);
		if (actual != cases[i].expected) {
			fprintf(stderr, "FAIL %s: got %d expected %d\n",
				cases[i].label, actual, cases[i].expected);
			failures++;
		}
	}

	return failures ? 1 : 0;
}
