#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
detector=$repo_dir/scripts/detect-lsm-api.sh
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/bbg-lsm-api-test.XXXXXX")

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
	${CC:-cc} ${CPPFLAGS:-} ${CFLAGS:-} "$@"
)

fail()
{
	printf 'FAIL %s\n' "$1" >&2
	exit 1
}

trap cleanup 0
trap 'cleanup_and_exit 129' HUP
trap 'cleanup_and_exit 130' INT
trap 'cleanup_and_exit 143' TERM

make_fixture()
{
	fixture=$tmp_dir/$1
	mkdir -p "$fixture/include/linux/io_uring"
	printf '%s\n' "$fixture"
}

run_detector_case()
{
	label=$1
	expected=$2
	fixture=$3
	actual=$(sh "$detector" "$fixture")
	if [ "$actual" != "$expected" ]; then
		printf 'FAIL %s: got <%s> expected <%s>\n' \
			"$label" "$actual" "$expected" >&2
		exit 1
	fi
	printf 'PASS %s\n' "$label"
}

fixture=$(make_fixture no-hook)
cat > "$fixture/include/linux/lsm_hook_defs.h" <<'EOF'
LSM_HOOK(int, 0, file_open, struct file *file)
EOF
run_detector_case no-hook '' "$fixture"
printf '\n' > "$tmp_dir/expected-empty-line"
sh "$detector" "$fixture" > "$tmp_dir/actual-empty-line"
cmp -s "$tmp_dir/expected-empty-line" "$tmp_dir/actual-empty-line" ||
	fail 'no-hook did not emit exactly one empty line'

if sh "$detector" > /dev/null 2>&1; then
	fail 'missing argument returned success'
else
	status=$?
	[ "$status" -eq 2 ] || fail "missing argument returned $status instead of 2"
fi
if sh "$detector" "$fixture" extra > /dev/null 2>&1; then
	fail 'extra argument returned success'
else
	status=$?
	[ "$status" -eq 2 ] || fail "extra argument returned $status instead of 2"
fi
printf 'PASS detector-arguments\n'

fixture=$(make_fixture legacy)
cat > "$fixture/include/linux/lsm_hook_defs.h" <<'EOF'
LSM_HOOK(int, 0, uring_cmd, struct io_uring_cmd *ioucmd)
EOF
cat > "$fixture/include/linux/io_uring.h" <<'EOF'
struct io_uring_cmd {
	struct file *file;
};
EOF
run_detector_case legacy \
	'-DBBG_HAS_URING_CMD -DBBG_URING_CMD_HEADER_LEGACY' "$fixture"

fixture=$(make_fixture cmd-header)
cat > "$fixture/include/linux/lsm_hook_defs.h" <<'EOF'
LSM_HOOK(int, 0, uring_cmd, struct io_uring_cmd *ioucmd)
EOF
cat > "$fixture/include/linux/io_uring/cmd.h" <<'EOF'
struct io_uring_cmd {
	struct file *file;
};
EOF
run_detector_case cmd-header \
	'-DBBG_HAS_URING_CMD -DBBG_URING_CMD_HEADER_CMD' "$fixture"

fixture=$(make_fixture comments-only)
cat > "$fixture/include/linux/lsm_hook_defs.h" <<'EOF'
// LSM_HOOK(int, 0, uring_cmd, struct io_uring_cmd *ioucmd)
// Continued comment hides the next physical line: \
LSM_HOOK(int, 0, uring_cmd, struct io_uring_cmd *ioucmd)
/*
 * LSM_HOOK(int, 0, uring_cmd,
 *          struct io_uring_cmd *ioucmd)
 */
LSM_HOOK(int, 0, file_open, struct file *file)
EOF
cat > "$fixture/include/linux/io_uring/cmd.h" <<'EOF'
struct io_uring_cmd {
	struct file *file;
};
EOF
run_detector_case comments-only '' "$fixture"

fixture=$(make_fixture prefixed-hook-token)
cat > "$fixture/include/linux/lsm_hook_defs.h" <<'EOF'
NOT_LSM_HOOK(int, 0, uring_cmd, struct io_uring_cmd *ioucmd)
EOF
cat > "$fixture/include/linux/io_uring/cmd.h" <<'EOF'
struct io_uring_cmd {
	struct file *file;
};
EOF
run_detector_case prefixed-hook-token '' "$fixture"

fixture=$(make_fixture prefixed-type-token)
cat > "$fixture/include/linux/lsm_hook_defs.h" <<'EOF'
LSM_HOOK(int, 0, uring_cmd, struct io_uring_cmd *ioucmd)
EOF
cat > "$fixture/include/linux/io_uring/cmd.h" <<'EOF'
mystruct io_uring_cmd {
	struct file *file;
};
EOF
run_detector_case prefixed-type-token '' "$fixture"

fixture=$(make_fixture named-nested-file)
cat > "$fixture/include/linux/lsm_hook_defs.h" <<'EOF'
LSM_HOOK(int, 0, uring_cmd, struct io_uring_cmd *ioucmd)
EOF
cat > "$fixture/include/linux/io_uring/cmd.h" <<'EOF'
struct io_uring_cmd {
	struct nested {
		struct file *file;
	} nested;
};
EOF
run_detector_case named-nested-file '' "$fixture"

fixture=$(make_fixture defs-take-priority)
cat > "$fixture/include/linux/lsm_hook_defs.h" <<'EOF'
LSM_HOOK(int, 0, file_open, struct file *file)
EOF
cat > "$fixture/include/linux/lsm_hooks.h" <<'EOF'
LSM_HOOK(int, 0, uring_cmd, struct io_uring_cmd *ioucmd)
EOF
cat > "$fixture/include/linux/io_uring/cmd.h" <<'EOF'
struct io_uring_cmd {
	struct file *file;
};
EOF
run_detector_case defs-take-priority '' "$fixture"

fixture=$(make_fixture incomplete-type)
cat > "$fixture/include/linux/lsm_hook_defs.h" <<'EOF'
LSM_HOOK(int, 0, uring_cmd, struct io_uring_cmd *ioucmd)
EOF
cat > "$fixture/include/linux/io_uring/cmd.h" <<'EOF'
struct io_uring_cmd;
EOF
cat > "$fixture/include/linux/io_uring.h" <<'EOF'
struct io_uring_cmd {
	unsigned int cmd_op;
};
EOF
run_detector_case incomplete-type '' "$fixture"

fixture=$(make_fixture hooks-fallback)
cat > "$fixture/include/linux/lsm_hooks.h" <<'EOF'
LSM_HOOK(int, 0, uring_cmd, struct io_uring_cmd *ioucmd)
EOF
cat > "$fixture/include/linux/io_uring.h" <<'EOF'
struct io_uring_cmd {
	struct file *file;
};
EOF
run_detector_case hooks-fallback \
	'-DBBG_HAS_URING_CMD -DBBG_URING_CMD_HEADER_LEGACY' "$fixture"

fixture=$(make_fixture multiline)
cat > "$fixture/include/linux/lsm_hook_defs.h" <<'EOF'
LSM_HOOK(
	int,
	0,
	uring_cmd,
	struct io_uring_cmd
		*ioucmd
)
EOF
cat > "$fixture/include/linux/io_uring/cmd.h" <<'EOF'
struct io_uring_cmd
{
	struct file
		*file;
};
EOF
run_detector_case multiline \
	'-DBBG_HAS_URING_CMD -DBBG_URING_CMD_HEADER_CMD' "$fixture"

fixture=$(make_fixture prefer-cmd)
cat > "$fixture/include/linux/lsm_hook_defs.h" <<'EOF'
LSM_HOOK(int, 0, uring_cmd, struct io_uring_cmd *ioucmd)
EOF
cat > "$fixture/include/linux/io_uring.h" <<'EOF'
struct io_uring_cmd {
	struct file *file;
};
EOF
cat > "$fixture/include/linux/io_uring/cmd.h" <<'EOF'
struct io_uring_cmd {
	union {
		struct file *file;
		void *ptr;
	};
};
EOF
run_detector_case prefer-cmd \
	'-DBBG_HAS_URING_CMD -DBBG_URING_CMD_HEADER_CMD' "$fixture"

source_fixture=$tmp_dir/source-guard
mkdir -p "$source_fixture/linux/io_uring" "$source_fixture/tracing"
cp "$repo_dir/baseband_guard.c" "$source_fixture/baseband_guard.c"

for header in module.h init.h security.h fs.h binfmts.h namei.h \
	blk_types.h slab.h string.h errno.h cred.h dcache.h ratelimit.h
do
	: > "$source_fixture/linux/$header"
done

cat > "$source_fixture/linux/version.h" <<'EOF'
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#define LINUX_VERSION_CODE KERNEL_VERSION(6, 12, 0)
EOF
cat > "$source_fixture/linux/io_uring.h" <<'EOF'
struct file;
struct io_uring_cmd { struct file *file; };
int bbg_test_legacy_header_marker;
EOF
cat > "$source_fixture/linux/io_uring/cmd.h" <<'EOF'
struct file;
struct io_uring_cmd { struct file *file; };
int bbg_test_cmd_header_marker;
EOF

for header in kernel_compat.h baseband_guard.h blkdev_helper.h block_policy.h
do
	: > "$source_fixture/$header"
done
: > "$source_fixture/tracing/tracing.h"

assert_contains()
{
	label=$1
	file=$2
	pattern=$3
	grep -Eq "$pattern" "$file" || fail "$label missing expected source"
}

assert_not_contains()
{
	label=$1
	file=$2
	pattern=$3
	if grep -Eq "$pattern" "$file"; then
		fail "$label exposed guarded source"
	fi
}

run_source_case()
{
	label=$1
	header=$2
	enabled=$3
	shift 3
	output=$tmp_dir/source-$label.i

	run_cc -E -I"$source_fixture" "$@" \
		"$source_fixture/baseband_guard.c" > "$output"

	case $header in
	legacy)
		assert_contains "$label" "$output" bbg_test_legacy_header_marker
		assert_not_contains "$label" "$output" bbg_test_cmd_header_marker
		;;
	cmd)
		assert_contains "$label" "$output" bbg_test_cmd_header_marker
		assert_not_contains "$label" "$output" bbg_test_legacy_header_marker
		;;
	none)
		assert_not_contains "$label" "$output" 'bbg_test_(legacy|cmd)_header_marker'
		;;
	*)
		fail "$label invalid header expectation"
		;;
	esac

	if [ "$enabled" = yes ]; then
		uring_source=$tmp_dir/source-$label-uring.c
		sed -n \
			'/static[[:space:]][[:space:]]*int[[:space:]][[:space:]]*bb_uring_cmd/,/static[[:space:]][[:space:]]*int[[:space:]][[:space:]]*bb_file_open/p' \
			"$output" > "$uring_source"
		assert_contains "$label" "$output" \
			'static[[:space:]]+int[[:space:]]+bb_uring_cmd'
		assert_contains "$label" "$output" \
			'LSM_HOOK_INIT[[:space:]]*\([[:space:]]*uring_cmd[[:space:]]*,[[:space:]]*bb_uring_cmd'
		assert_contains "$label" "$uring_source" \
			'ioucmd[[:space:]]*->[[:space:]]*file'
		assert_contains "$label" "$uring_source" \
			'current_process_trusted[[:space:]]*\('
		assert_contains "$label" "$uring_source" \
			'bbg_block_uring_allowed[[:space:]]*\([[:space:]]*false[[:space:]]*\)'
		assert_contains "$label" "$uring_source" \
			'deny[[:space:]]*\('
		assert_not_contains "$label" "$uring_source" \
			'is_allowed_block_device|is_zram_device|is_allowed_partition'
	else
		assert_not_contains "$label" "$output" bb_uring_cmd
	fi
	printf 'PASS source-%s\n' "$label"
}

run_source_case absent none no
run_source_case legacy legacy yes \
	-DBBG_HAS_URING_CMD -DCONFIG_IO_URING \
	-DBBG_URING_CMD_HEADER_LEGACY
run_source_case cmd cmd yes \
	-DBBG_HAS_URING_CMD -DCONFIG_IO_URING \
	-DBBG_URING_CMD_HEADER_CMD
run_source_case io-uring-disabled none no \
	-DBBG_HAS_URING_CMD -DBBG_URING_CMD_HEADER_CMD

if run_cc -E -I"$source_fixture" \
	-DBBG_HAS_URING_CMD -DCONFIG_IO_URING \
	-DBBG_URING_CMD_HEADER_CMD -DBBG_URING_CMD_HEADER_LEGACY \
	"$source_fixture/baseband_guard.c" > /dev/null 2>&1; then
	fail 'source-double-header-flags did not fail preprocessing'
fi
printf 'PASS source-double-header-flags\n'

if run_cc -E -I"$source_fixture" \
	-DBBG_HAS_URING_CMD -DCONFIG_IO_URING \
	"$source_fixture/baseband_guard.c" > /dev/null 2>&1; then
	fail 'source-missing-header-flag did not fail preprocessing'
fi
printf 'PASS source-missing-header-flag\n'
