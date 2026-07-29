#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
source_file=$repo_dir/baseband_guard.c
failures=0

fail()
{
	printf 'FAIL %s\n' "$1" >&2
	failures=$((failures + 1))
}

extract_function()
{
	signature=$1
	awk -v signature="$signature" '
		!found && index($0, signature) { found = 1 }
		found { print }
		found && /^}/ { exit }
		END { if (!found) exit 1 }
	' "$source_file"
}

strip_comments()
{
	awk '
	BEGIN { in_block = 0 }
	{
		line = $0
		out = ""
		for (i = 1; i <= length(line); i++) {
			c = substr(line, i, 1)
			next_c = i < length(line) ? substr(line, i + 1, 1) : ""
			if (in_block) {
				if (c == "*" && next_c == "/") {
					in_block = 0
					i++
				}
				continue
			}
			if (c == "/" && next_c == "*") {
				in_block = 1
				i++
				continue
			}
			if (c == "/" && next_c == "/")
				break
			out = out c
		}
		print out
	}
	'
}

get_cmdline_body=$(extract_function 'static int bbg_get_cmdline(' |
	strip_comments)
init_line=$(printf '%s\n' "$get_cmdline_body" |
	grep -nF "buf[0] = '\0';" | sed -n '1s/:.*//p')
call_line=$(printf '%s\n' "$get_cmdline_body" |
	grep -nF 'n = get_cmdline(current, buf, buflen);' |
	sed -n '1s/:.*//p')
if [ -z "$init_line" ] || [ -z "$call_line" ] ||
	[ "$init_line" -ge "$call_line" ]; then
	fail 'bbg_get_cmdline does not initialize buf before get_cmdline'
fi

deny_log_body=$(extract_function 'static void bbg_log_deny_detail(' |
	strip_comments)
deny_log_flat=$(printf '%s\n' "$deny_log_body" | tr '\n' ' ')
deny_log_ok=true
printf '%s\n' "$deny_log_body" |
	grep -Fq 'const char *cmdline = NULL;' || deny_log_ok=false
printf '%s\n' "$deny_log_flat" | grep -Eq \
	'if[[:space:]]*\([[:space:]]*cmdbuf[[:space:]]*&&[[:space:]]*bbg_get_cmdline[[:space:]]*\([[:space:]]*cmdbuf[[:space:]]*,[[:space:]]*CMD_BUFLEN[[:space:]]*\)[[:space:]]*>[[:space:]]*0[[:space:]]*\)[[:space:]]*(\{[[:space:]]*)?cmdline[[:space:]]*=[[:space:]]*cmdbuf[[:space:]]*;' ||
	deny_log_ok=false
printf '%s\n' "$deny_log_body" |
	grep -Fq 'cmdline ? cmdline : "?"' || deny_log_ok=false
assignment_count=$(printf '%s\n' "$deny_log_body" |
	grep -Fc 'cmdline = cmdbuf;' || true)
[ "$assignment_count" -eq 1 ] || deny_log_ok=false
if printf '%s\n' "$deny_log_body" |
	grep -Fq 'cmdbuf ? cmdbuf :'; then
	deny_log_ok=false
fi
if [ "$deny_log_ok" != true ]; then
	fail 'deny detail can print cmdbuf without a successful get_cmdline'
fi

native_body=$(extract_function 'static int bb_file_ioctl(' |
	strip_comments)
if printf '%s\n' "$native_body" |
	grep -Fq 'bbg_block_ioctl_compat_normalize'; then
	fail 'native ioctl normalizes compat commands'
fi

compat_body=$(extract_function 'static int bb_file_ioctl_compat(' |
	strip_comments)
compat_flat=$(printf '%s\n' "$compat_body" | tr '\n' ' ')
if ! printf '%s\n' "$compat_flat" | grep -Eq \
	'return[[:space:]]+bb_file_ioctl[[:space:]]*\([[:space:]]*file[[:space:]]*,[[:space:]]*bbg_block_ioctl_compat_normalize[[:space:]]*\([[:space:]]*cmd[[:space:]]*\)[[:space:]]*,[[:space:]]*arg[[:space:]]*\)[[:space:]]*;'; then
	fail 'compat ioctl does not normalize cmd before native policy'
fi

if [ "$failures" -ne 0 ]; then
	exit 1
fi
printf 'PASS baseband guard source invariants\n'
