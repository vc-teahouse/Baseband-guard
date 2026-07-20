#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/bbg-host-tests.XXXXXX")
partition_test_bin=$tmp_dir/partition-match-test.exe
blkdev_test_bin=$tmp_dir/blkdev-compat-test.exe
block_policy_test_bin=$tmp_dir/block-policy-test.exe
block_policy_compat32_test_bin=$tmp_dir/block-policy-compat32-test.exe
blkdev_legacy_test_bin=$tmp_dir/blkdev-compat-legacy-test.exe

cleanup()
{
	rm -rf "$tmp_dir"
}

cleanup_and_exit()
{
	status=$1
	trap - 0 HUP INT TERM
	cleanup
	exit "$status"
}

run_cc()
(
	set -f
	# These variables follow make-style whitespace-delimited word lists.
	${CC:-cc} ${CPPFLAGS:-} ${CFLAGS:-} "$@"
)

trap cleanup 0
trap 'cleanup_and_exit 129' HUP
trap 'cleanup_and_exit 130' INT
trap 'cleanup_and_exit 143' TERM

sh "$repo_dir/tests/detect-block-api-test.sh"
sh "$repo_dir/tests/detect-lsm-api-test.sh"
echo "PASS LSM API detector"
sh "$repo_dir/tests/baseband-guard-source-test.sh"

run_cc -DBBG_HOST_TEST -std=c11 -Wall -Wextra -Werror \
	-I"$repo_dir" \
	"$repo_dir/tests/partition_match_test.c" \
	"$repo_dir/partition_match.c" \
	-o "$partition_test_bin"
"$partition_test_bin"
echo "PASS partition matcher"

run_cc -std=c11 -Wall -Wextra -Werror \
	-I"$repo_dir/tests/compat_stubs" -I"$repo_dir" \
	"$repo_dir/tests/blkdev_compat_test.c" \
	-o "$blkdev_test_bin"
"$blkdev_test_bin"
echo "PASS block device compatibility"

run_cc -DBBG_HOST_TEST -std=c11 -Wall -Wextra -Werror \
	-I"$repo_dir/tests/policy_stubs" -I"$repo_dir" \
	"$repo_dir/tests/block_policy_test.c" \
	"$repo_dir/block_policy.c" \
	-o "$block_policy_test_bin"
"$block_policy_test_bin"
echo "PASS block access policy"

run_cc -DBBG_HOST_TEST -DBBG_TEST_NATIVE_IOCTL_TYPE=int \
	-std=c11 -Wall -Wextra -Werror \
	-I"$repo_dir/tests/policy_stubs" -I"$repo_dir" \
	"$repo_dir/tests/block_policy_test.c" \
	"$repo_dir/block_policy.c" \
	-o "$block_policy_compat32_test_bin"
"$block_policy_compat32_test_bin"
echo "PASS block access policy with 32-bit native ioctl aliases"

run_cc -std=c11 -Wall -Wextra -Werror \
	-I"$repo_dir/tests/compat_stubs" -I"$repo_dir" \
	"$repo_dir/tests/blkdev_compat_legacy_test.c" \
	-o "$blkdev_legacy_test_bin"
"$blkdev_legacy_test_bin"
echo "PASS legacy block device compatibility"
