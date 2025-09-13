#!/bin/sh
#
# Baseband Guard integration helper
# Enhanced version: supports --branch, --no-update, local patch application, cleanup, etc.
#
# This script integrates the Baseband Guard LSM into a GKI kernel source tree.
# It clones or updates the Baseband Guard repository, creates necessary symlinks,
# and updates Makefile and Kconfig files.
#
set -eu
set -o pipefail 2>/dev/null || true

GKI_ROOT="$(pwd)"

REF=""
BRANCH=""
DO_CLEANUP=0
NO_UPDATE=0
LOCAL_PATCH_DIR=""

usage() {
    cat <<EOF
Usage: $0 [options] [<ref>]

Without arguments: clone/update Baseband-guard at 'main' (or master) and integrate.
<ref>              Specific commit or tag (implies checkout of that ref).

Options:
  --branch <name>       Force a branch checkout (instead of auto main/master).
  --no-update           Do not fetch/pull if repo already exists.
  --apply-local-patches <dir>
                        After clone/checkout, git am *.patch from <dir>.
  --cleanup             Remove symlink, Makefile & Kconfig additions, and local repo dir.
  -h | --help           Show this help.

Examples:
  $0
  $0 v1.2.3
  $0 --branch dev-testing
  $0 --apply-local-patches ../my_patches
  $0 --cleanup
EOF
}

err() { echo "[ERROR] $*" >&2; exit 1; }
info() { echo "[+] $*"; }
note() { echo " - $*"; }

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --cleanup) DO_CLEANUP=1 ;;
            -h|--help) usage; exit 0 ;;
            --branch) BRANCH="${2:-}"; [ -n "$BRANCH" ] || err "--branch requires value"; shift ;;
            --no-update) NO_UPDATE=1 ;;
            --apply-local-patches) LOCAL_PATCH_DIR="${2:-}"; [ -d "$LOCAL_PATCH_DIR" ] || err "Patch dir missing"; shift ;;
            --) shift; break ;;
            -*) err "Unknown option: $1" ;;
            *) REF="$1" ;;
        esac
        shift
    done
}

init_paths() {
    if [ -d "$GKI_ROOT/security" ]; then
        SECURITY_DIR="$GKI_ROOT/security"
    elif [ -d "$GKI_ROOT/common/security" ]; then
        SECURITY_DIR="$GKI_ROOT/common/security"
    else
        err '"security/" directory not found.'
    fi
    SECURITY_MAKEFILE="$SECURITY_DIR/Makefile"
    SECURITY_KCONFIG="$SECURITY_DIR/Kconfig"
    BBG_DIR="$GKI_ROOT/Baseband-guard"
    BBG_SYMLINK="$SECURITY_DIR/baseband-guard"
    BBG_REPO="https://github.com/vc-teahouse/Baseband-guard"
}

check_tools() {
    command -v git >/dev/null 2>&1 || err "git not found in PATH"
    command -v awk >/dev/null 2>&1 || err "awk not found"
}

cleanup() {
    info "Cleanup"
    if [ -L "$BBG_SYMLINK" ] || [ -e "$BBG_SYMLINK" ]; then
        rm -rf "$BBG_SYMLINK"
        note "removed $BBG_SYMLINK"
    fi
    if [ -f "$SECURITY_MAKEFILE" ] && grep -q 'baseband-guard/baseband_guard.o' "$SECURITY_MAKEFILE"; then
        sed -i '/baseband-guard\/baseband_guard.o/d' "$SECURITY_MAKEFILE"
        note "Makefile reverted"
    fi
    if [ -f "$SECURITY_KCONFIG" ] && grep -q 'security/baseband-guard/Kconfig' "$SECURITY_KCONFIG"; then
        sed -i '/security\/baseband-guard\/Kconfig/d' "$SECURITY_KCONFIG"
        note "Kconfig reverted"
    fi
    if [ -d "$BBG_DIR" ]; then
        rm -rf "$BBG_DIR"
        note "repo dir deleted"
    fi
    info "Done."
}

integrate_makefile() {
    grep -q 'baseband-guard/baseband_guard.o' "$SECURITY_MAKEFILE" 2>/dev/null || {
        printf '\nobj-$(CONFIG_SECURITY_BASEBAND_GUARD) += baseband-guard/baseband_guard.o\n' >> "$SECURITY_MAKEFILE"
        note "Makefile updated"
    }
}

integrate_kconfig() {
    grep -q 'security/baseband-guard/Kconfig' "$SECURITY_KCONFIG" 2>/dev/null && return 0
    if grep -n '^endmenu[[:space:]]*$' "$SECURITY_KCONFIG" >/dev/null 2>&1; then
        awk '
            { a[NR]=$0 }
            END {
                last=0
                for(i=1; i<=NR; i++) if(a[i] ~ /^endmenu[[:space:]]*$/) last=i
                for(i=1; i<=NR; i++) {
                    if(i==last) print "source \"security/baseband-guard/Kconfig\""
                    print a[i]
                }
            }' "$SECURITY_KCONFIG" > "$SECURITY_KCONFIG.tmp" && mv "$SECURITY_KCONFIG.tmp" "$SECURITY_KCONFIG"
    else
        printf '\nsource "security/baseband-guard/Kconfig"\n' >> "$SECURITY_KCONFIG"
    fi
    note "Kconfig updated"
}

apply_local
