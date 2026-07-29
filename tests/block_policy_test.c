#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <linux/fs.h>
#include <linux/hdreg.h>

#include "../block_policy.h"

#define BBG_UNKNOWN_IOCTL 0xBB01001Au
#define BBG_TEST_BLKBSZGET_COMPAT _IOR(0x12, 112, int)
#define BBG_TEST_BLKGETSIZE64_COMPAT _IOR(0x12, 114, int)

struct ioctl_case {
	const char *label;
	unsigned int cmd;
};

static const struct ioctl_case query_cases[] = {
	{ "BLKROGET", BLKROGET },
	{ "BLKGETSIZE", BLKGETSIZE },
	{ "BLKGETSIZE64", BLKGETSIZE64 },
	{ "BLKSSZGET", BLKSSZGET },
	{ "BLKBSZGET", BLKBSZGET },
	{ "BLKPBSZGET", BLKPBSZGET },
	{ "BLKIOMIN", BLKIOMIN },
	{ "BLKIOOPT", BLKIOOPT },
	{ "BLKALIGNOFF", BLKALIGNOFF },
	{ "BLKSECTGET", BLKSECTGET },
	{ "BLKDISCARDZEROES", BLKDISCARDZEROES },
	{ "BLKRAGET", BLKRAGET },
	{ "BLKFRAGET", BLKFRAGET },
	{ "BLKGETDISKSEQ", BLKGETDISKSEQ },
	{ "BLKROTATIONAL", BLKROTATIONAL },
	{ "HDIO_GETGEO", HDIO_GETGEO },
};

static const struct ioctl_case mutation_cases[] = {
	{ "BLKDISCARD", BLKDISCARD },
	{ "BLKSECDISCARD", BLKSECDISCARD },
	{ "BLKZEROOUT", BLKZEROOUT },
};

static const struct ioctl_case unsafe_cases[] = {
	{ "BLKROSET", BLKROSET },
	{ "BLKPG", BLKPG },
	{ "SG_IO", SG_IO },
	{ "MMC_IOC_CMD", MMC_IOC_CMD },
	{ "NVME_IOCTL_IO_CMD", NVME_IOCTL_IO_CMD },
	{ "HDIO_DRIVE_CMD", HDIO_DRIVE_CMD },
	{ "unknown", BBG_UNKNOWN_IOCTL },
};

static const struct ioctl_case compat_query_cases[] = {
	{ "compat BLKBSZGET normalization", BBG_TEST_BLKBSZGET_COMPAT },
	{ "compat BLKGETSIZE64 normalization", BBG_TEST_BLKGETSIZE64_COMPAT },
};

static const unsigned int compat_query_native_cmds[] = {
	BLKBSZGET,
	BLKGETSIZE64,
};

#define COMPAT_QUERY_COUNT \
	(sizeof(compat_query_cases) / sizeof(compat_query_cases[0]))

typedef char compat_query_fixture_count_must_match[
	COMPAT_QUERY_COUNT == sizeof(compat_query_native_cmds) /
			      sizeof(compat_query_native_cmds[0]) ? 1 : -1];

static int expect(const char *label, bool actual, bool expected)
{
	if (actual == expected)
		return 0;
	fprintf(stderr, "FAIL %s: got %d expected %d\n",
		label, actual, expected);
	return 1;
}

static int expect_cmd(const char *label, unsigned int actual,
		      unsigned int expected)
{
	if (actual == expected)
		return 0;
	fprintf(stderr, "FAIL %s: got 0x%x expected 0x%x\n",
		label, actual, expected);
	return 1;
}

static int check_unique_fixtures(void)
{
	const struct ioctl_case *groups[] = {
		query_cases, mutation_cases, unsafe_cases,
	};
	const size_t counts[] = {
		sizeof(query_cases) / sizeof(query_cases[0]),
		sizeof(mutation_cases) / sizeof(mutation_cases[0]),
		sizeof(unsafe_cases) / sizeof(unsafe_cases[0]),
	};
	size_t group;
	size_t index;
	size_t other_group;
	size_t other_index;
	int failures = 0;

	for (group = 0; group < sizeof(groups) / sizeof(groups[0]); group++) {
		for (index = 0; index < counts[group]; index++) {
			for (other_group = group; other_group <
			     sizeof(groups) / sizeof(groups[0]); other_group++) {
				size_t start = other_group == group ? index + 1 : 0;

				for (other_index = start;
				     other_index < counts[other_group];
				     other_index++) {
					if (groups[group][index].cmd !=
					    groups[other_group][other_index].cmd)
						continue;
					fprintf(stderr,
						"FAIL duplicate fixtures: %s and %s\n",
						groups[group][index].label,
						groups[other_group][other_index].label);
					failures++;
				}
			}
		}
	}
	return failures;
}

int main(void)
{
	const struct ioctl_case *groups[] = {
		query_cases, mutation_cases, unsafe_cases,
	};
	const size_t counts[] = {
		sizeof(query_cases) / sizeof(query_cases[0]),
		sizeof(mutation_cases) / sizeof(mutation_cases[0]),
		sizeof(unsafe_cases) / sizeof(unsafe_cases[0]),
	};
	size_t group;
	size_t i;
	int failures = check_unique_fixtures();

	failures += expect("trusted ordinary write",
			   bbg_block_write_allowed(true, false), true);
	failures += expect("trusted ordinary write to allowed device",
			   bbg_block_write_allowed(true, true), true);
	failures += expect("untrusted write to allowed device",
			   bbg_block_write_allowed(false, true), true);
	failures += expect("untrusted write to protected device",
			   bbg_block_write_allowed(false, false), false);
	failures += expect("allowed device still rejects unsafe SG_IO",
			   bbg_block_ioctl_allowed(false, true, SG_IO), false);
	failures += expect("protected device permits query BLKROGET",
			   bbg_block_ioctl_allowed(false, false, BLKROGET), true);
	failures += expect("compat query fixtures are distinct",
		compat_query_cases[0].cmd != compat_query_cases[1].cmd, true);

	for (i = 0; i < COMPAT_QUERY_COUNT; i++) {
		unsigned int normalized = bbg_block_ioctl_compat_normalize(
			compat_query_cases[i].cmd);

		failures += expect_cmd(compat_query_cases[i].label, normalized,
				       compat_query_native_cmds[i]);
		failures += expect(compat_query_cases[i].label,
			bbg_block_ioctl_allowed(false, false, normalized), true);
	}

	for (group = 0; group < sizeof(groups) / sizeof(groups[0]); group++) {
		for (i = 0; i < counts[group]; i++) {
			failures += expect_cmd(groups[group][i].label,
				bbg_block_ioctl_compat_normalize(
					groups[group][i].cmd),
				groups[group][i].cmd);
		}
	}

	for (group = 0; group < sizeof(groups) / sizeof(groups[0]); group++) {
		for (i = 0; i < counts[group]; i++) {
			failures += expect(groups[group][i].label,
				bbg_block_ioctl_allowed(true, false,
							groups[group][i].cmd),
				true);
			failures += expect(groups[group][i].label,
				bbg_block_ioctl_allowed(true, true,
							groups[group][i].cmd),
				true);
		}
	}

	for (i = 0; i < sizeof(query_cases) / sizeof(query_cases[0]); i++) {
		failures += expect(query_cases[i].label,
			bbg_block_ioctl_allowed(false, false,
						query_cases[i].cmd),
			true);
		failures += expect(query_cases[i].label,
			bbg_block_ioctl_allowed(false, true,
						query_cases[i].cmd),
			true);
	}

	for (i = 0; i < sizeof(mutation_cases) / sizeof(mutation_cases[0]); i++) {
		failures += expect(mutation_cases[i].label,
			bbg_block_ioctl_allowed(false, true,
						mutation_cases[i].cmd),
			true);
		failures += expect(mutation_cases[i].label,
			bbg_block_ioctl_allowed(false, false,
						mutation_cases[i].cmd),
			false);
	}

	for (i = 0; i < sizeof(unsafe_cases) / sizeof(unsafe_cases[0]); i++) {
		failures += expect(unsafe_cases[i].label,
			bbg_block_ioctl_allowed(false, true,
						unsafe_cases[i].cmd),
			false);
	}

	failures += expect("trusted uring command",
			   bbg_block_uring_allowed(true), true);
	failures += expect("untrusted uring command",
			   bbg_block_uring_allowed(false), false);

	return failures ? 1 : 0;
}
