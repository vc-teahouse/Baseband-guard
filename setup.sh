#!/bin/sh
set -eu

GKI_ROOT="$(pwd)"

display_usage() {
    echo "Usage: $0 [--cleanup | <commit-or-tag>]"
    echo "  --cleanup            Clean up modifications made by this script."
    echo "  -h, --help           Show this help."
    echo "  (no args)            Setup Baseband-guard to latest main."
}

initialize_variables() {
    if [ -d "$GKI_ROOT/security" ]; then
        SECURITY_DIR="$GKI_ROOT/security"
    elif [ -d "$GKI_ROOT/common/security" ]; then
        SECURITY_DIR="$GKI_ROOT/common/security"
    else
        echo '[ERROR] "security/" directory not found.'
        exit 127
    fi
    SECURITY_MAKEFILE="$SECURITY_DIR/Makefile"
    SECURITY_KCONFIG="$SECURITY_DIR/Kconfig"
    BBG_DIR="$GKI_ROOT/Baseband-guard"
    BBG_SYMLINK="$SECURITY_DIR/baseband-guard"
    BBG_REPO="https://github.com/vc-teahouse/Baseband-guard"
    SELINUX_MAKEFILE="$SECURITY_DIR/selinux/Makefile"
    PATCH_FILE="$BBG_DIR/sepatch.txt"
}

# Revert changes
perform_cleanup() {
    echo "[+] Cleaning up"
    [ -L "$BBG_SYMLINK" ] && rm -f "$BBG_SYMLINK" && echo " - symlink removed"
    if [ -f "$SECURITY_MAKEFILE" ] && grep -q 'baseband-guard' "$SECURITY_MAKEFILE"; then
        sed -i '/baseband-guard/d' "$SECURITY_MAKEFILE"; echo " - Makefile reverted"
    fi
    if [ -f "$SECURITY_KCONFIG" ] && grep -q 'security/baseband-guard/Kconfig' "$SECURITY_KCONFIG"; then
        sed -i '/security\/baseband-guard\/Kconfig/d' "$SECURITY_KCONFIG"; echo " - Kconfig reverted"
    fi
    if [ -f "${SELINUX_MAKEFILE}.bak" ]; then
        rm -f $SELINUX_MAKEFILE && mv "${SELINUX_MAKEFILE}.bak" "$SELINUX_MAKEFILE"; echo " - Selinux Makefile reverted"
    fi
    [ -d "$BBG_DIR" ] && rm -rf "$BBG_DIR" && echo " - Baseband-guard dir deleted"
}

# Setup / update
setup_baseband_guard() {
    ref="${1:-}"   # optional commit or tag
    echo "[+] Setting up Baseband-guard"

    if [ -d "$BBG_DIR/.git" ]; then
        ( cd "$BBG_DIR"
          git fetch origin +refs/heads/*:refs/remotes/origin/* >/dev/null 2>&1 || true
          if [ -n "$ref" ]; then
              git fetch origin "$ref" || true
              git checkout -q "$ref"
          else
              git checkout -q main || git checkout -q master || true
              git pull --ff-only || true
          fi
        )
    else
        if [ -n "$ref" ]; then
            git clone --branch "$ref" "$BBG_REPO" "$BBG_DIR"
        else
            git clone "$BBG_REPO" "$BBG_DIR"
        fi
        echo " - repo ready"
    fi

    # Symlink security/baseband-guard -> ../Baseband-guard
    (
      cd "$SECURITY_DIR"
      # prefer relative path; fall back to absolute if realpath --relative-to not available
      if command -v realpath >/dev/null 2>&1; then
          rel="$(realpath --relative-to="$SECURITY_DIR" "$BBG_DIR" 2>/dev/null || true)"
      else
          rel="$BBG_DIR"
      fi
      ln -sfn "$rel" "$BBG_SYMLINK"
    )
    echo " - symlink created"

    # Makefile entry (idempotent)
    if ! grep -q 'baseband-guard/baseband_guard.o' "$SECURITY_MAKEFILE"; then
        printf '\nobj-$(CONFIG_BBG) += baseband-guard/\n' >> "$SECURITY_MAKEFILE"
        echo " - Makefile updated"
    fi

    # Kconfig source (insert before last endmenu; fallback append)
    if ! grep -q 'security/baseband-guard/Kconfig' "$SECURITY_KCONFIG"; then
        if grep -n '^endmenu[[:space:]]*$' "$SECURITY_KCONFIG" >/dev/null 2>&1; then
            # insert before LAST endmenu
            awk '
              { a[NR]=$0 } END{
                last=0; for(i=1;i<=NR;i++) if(a[i] ~ /^endmenu[[:space:]]*$/) last=i;
                for(i=1;i<=NR;i++){
                  if(i==last) print "source \"security/baseband-guard/Kconfig\"";
                  print a[i];
                }
              }' "$SECURITY_KCONFIG" > "$SECURITY_KCONFIG.tmp" && mv "$SECURITY_KCONFIG.tmp" "$SECURITY_KCONFIG"
        else
            printf '\nsource "security/baseband-guard/Kconfig"\n' >> "$SECURITY_KCONFIG"
        fi
        echo " - Kconfig updated"
    fi
    
    # Selinux Makefile patch
    if [ ! -f "$SELINUX_MAKEFILE" ]; then
        echo "Error: '$SELINUX_MAKEFILE' not found!"
        exit 1
    fi

    if [ ! -f "$PATCH_FILE" ]; then
        echo "Error: patching code '$PATCH_FILE' not found! "
        exit 1
    fi

    cp $SELINUX_MAKEFILE ${SELINUX_MAKEFILE}.bak
    sed -i 's/selinuxfs.o //g' "$SELINUX_MAKEFILE"
    sed -i 's/hooks.o //g' "$SELINUX_MAKEFILE"
    cat "$PATCH_FILE" >> "$SELINUX_MAKEFILE"
    echo "Selinux Makefile patching done!"

    echo "[+] Done."
}

show_config_lsm_notice() {
    if awk '/^[[:space:]]*config[[:space:]]+LSM$/ { found=1; exit } END { exit !found }' $SECURITY_KCONFIG; then
        echo ""
        echo "Please manually set your defconfig, select one append to your defconfig:"
        echo ""
        awk '
        /^[[:space:]]*config[[:space:]]+LSM$/ { in_lsm=1; next }
        in_lsm && /^[[:space:]]*config[[:space:]]+/ { exit }
        in_lsm && /^[[:space:]]*default/ {
            match($0, /"([^"]+)"/, m)
            if ($0 ~ /if[[:space:]]+/) {
                sub(/.*if[[:space:]]+/, "", $0)
                cond = $0
                print "if " cond " enabled:"
            } else {
                print "else:"
            }
            if (m[1] != "") {
                print "CONFIG_LSM=" m[1] ",baseband_guard"
                print ""
            }
        }
        ' $SECURITY_KCONFIG
    fi
}

# Args
if [ "$#" -eq 0 ]; then
    initialize_variables
    setup_baseband_guard
    show_config_lsm_notice
elif [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    display_usage
elif [ "${1:-}" = "--cleanup" ]; then
    initialize_variables
    perform_cleanup
else
    initialize_variables
    setup_baseband_guard "$1"
    show_config_lsm_notice
fi
