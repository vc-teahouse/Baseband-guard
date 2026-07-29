#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
	exit 2
fi

kernel_root=$1
hook_header=$kernel_root/include/linux/lsm_hook_defs.h

if [ ! -f "$hook_header" ]; then
	hook_header=$kernel_root/include/linux/lsm_hooks.h
fi

strip_c_comments_and_flatten()
{
	awk '
	BEGIN {
		in_block = 0
		in_line = 0
		in_string = 0
		in_character = 0
		escaped = 0
		squote = sprintf("%c", 39)
	}
	{
		line = $0
		out = ""
		if (in_line) {
			in_line = substr(line, length(line), 1) == "\\"
			printf " "
			next
		}
		for (i = 1; i <= length(line); i++) {
			c = substr(line, i, 1)
			next_c = i < length(line) ? substr(line, i + 1, 1) : ""

			if (in_block) {
				if (c == "*" && next_c == "/") {
					in_block = 0
					out = out " "
					i++
				}
				continue
			}
			if (in_string) {
				if (escaped)
					escaped = 0
				else if (c == "\\")
					escaped = 1
				else if (c == "\"")
					in_string = 0
				out = out " "
				continue
			}
			if (in_character) {
				if (escaped)
					escaped = 0
				else if (c == "\\")
					escaped = 1
				else if (c == squote)
					in_character = 0
				out = out " "
				continue
			}
			if (c == "/" && next_c == "*") {
				in_block = 1
				out = out " "
				i++
				continue
			}
			if (c == "/" && next_c == "/") {
				in_line = substr(line, length(line), 1) == "\\"
				break
			}
			if (c == "\"") {
				in_string = 1
				out = out " "
				continue
			}
			if (c == squote) {
				in_character = 1
				out = out " "
				continue
			}
			if (c == "\\" && i == length(line))
				continue
			out = out c
		}
		printf "%s ", out
	}
	END {
		print ""
	}
	' "$1"
}

header_has_complete_uring_cmd()
{
	[ -f "$1" ] || return 1
	strip_c_comments_and_flatten "$1" | awk '
	function matching_brace(open_at, limit,    depth, i, c) {
		depth = 0
		for (i = open_at; i <= limit; i++) {
			c = substr(text, i, 1)
			if (c == "{")
				depth++
			else if (c == "}") {
				depth--
				if (depth == 0)
					return i
			}
		}
		return 0
	}
	function has_direct_file(open_at, close_at,
				 i, segment_at, c, nested_close, j,
				 prefix, suffix, declaration) {
		segment_at = open_at + 1
		for (i = segment_at; i < close_at; i++) {
			c = substr(text, i, 1)
			if (c == "{") {
				nested_close = matching_brace(i, close_at)
				if (!nested_close)
					return 0
				for (j = nested_close + 1;
				     j < close_at && substr(text, j, 1) != ";";
				     j++)
					;
				if (j >= close_at) {
					i = nested_close
					continue
				}

				prefix = substr(text, segment_at,
						i - segment_at)
				suffix = substr(text, nested_close + 1,
						j - nested_close - 1)
				if (prefix ~ /^[[:space:]]*(struct|union)[[:space:]]*$/ &&
				    suffix ~ /^[[:space:]]*$/ &&
				    has_direct_file(i, nested_close))
					return 1

				i = j
				segment_at = j + 1
				continue
			}
			if (c == ";") {
				declaration = substr(text, segment_at,
						     i - segment_at + 1)
				if (declaration ~ /^[[:space:]]*struct[[:space:]]+file[[:space:]]*\*[[:space:]]*file[[:space:]]*;[[:space:]]*$/)
					return 1
				segment_at = i + 1
			}
		}
		return 0
	}
	{
		text = $0
		search_at = 1
		while (search_at <= length(text)) {
			rest = substr(text, search_at)
			if (!match(rest,
			    /(^|[^[:alnum:]_])struct[[:space:]]+io_uring_cmd[[:space:]]*\{/))
				break

			open_at = search_at + RSTART + RLENGTH - 2
			close_at = matching_brace(open_at, length(text))
			if (!close_at)
				break

			after = substr(text, close_at + 1)
			if (after ~ /^[[:space:]]*;/ &&
			    has_direct_file(open_at, close_at)) {
				found = 1
				exit
			}
			search_at = close_at + 1
		}
	}
	END {
		exit found ? 0 : 1
	}
	'
}

if [ ! -f "$hook_header" ]; then
	printf '\n'
	exit 0
fi

hook_source=$(strip_c_comments_and_flatten "$hook_header")
hook_pattern='(^|[^[:alnum:]_])LSM_HOOK[[:space:]]*\([[:space:]]*int[[:space:]]*,[[:space:]]*0[[:space:]]*,[[:space:]]*uring_cmd[[:space:]]*,[[:space:]]*struct[[:space:]]+io_uring_cmd[[:space:]]*\*[[:space:]]*ioucmd[[:space:]]*\)'

if ! printf '%s\n' "$hook_source" | grep -Eq "$hook_pattern"; then
	printf '\n'
	exit 0
fi

cmd_header=$kernel_root/include/linux/io_uring/cmd.h
legacy_header=$kernel_root/include/linux/io_uring.h

if header_has_complete_uring_cmd "$cmd_header"; then
	printf '%s\n' '-DBBG_HAS_URING_CMD -DBBG_URING_CMD_HEADER_CMD'
elif header_has_complete_uring_cmd "$legacy_header"; then
	printf '%s\n' '-DBBG_HAS_URING_CMD -DBBG_URING_CMD_HEADER_LEGACY'
else
	printf '\n'
fi
