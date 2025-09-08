#!/bin/sh
set -eu

GKI_ROOT=$(pwd)

display_usage() {
    echo "Usage: $0 [--cleanup | <commit-or-tag>]"
    echo "  --cleanup:              Cleans up previous modifications made by the script."
    echo "  -h, --help:             Displays this usage information."
    echo "  (no args):              Sets up the Baseband-guard environment to the latest commit."
}

initialize_variables() {
    if test -d "$GKI_ROOT/security"; then
         SECURITY_DIR="$GKI_ROOT/security"
    else
         echo '[ERROR] "security/" directory not found.'
         exit 127
    fi

    SECURITY_MAKEFILE=$SECURITY_DIR/Makefile
    SECURITY_KCONFIG=$SECURITY_DIR/Kconfig
}

# Reverts modifications made by this script
perform_cleanup() {
    echo "[+] Cleaning up..."
    [ -L "$SECURITY_DIR/baseband-guard" ] && rm "$SECURITY_DIR/baseband-guard" && echo "[-] Symlink removed."
    grep -q "baseband-guard" "$SECURITY_MAKEFILE" && sed -i '/baseband-guard/d' "$SECURITY_MAKEFILE" && echo "[-] Makefile reverted."
    grep -q "security/baseband-guard/Kconfig" "$SECURITY_KCONFIG" && sed -i '/security\/baseband-guard\/Kconfig/d' "$SECURITY_KCONFIG" && echo "[-] Kconfig reverted."
    if [ -d "$GKI_ROOT/Baseband-guard" ]; then
        rm -rf "$GKI_ROOT/Baseband-guard" && echo "[-] Baseband-guard directory deleted."
    fi
}

# Sets up or update Baseband-guard environment
setup_anti_format() {
    echo "[+] Setting up Baseband-guard..."
    test -d "$GKI_ROOT/Baseband-guard" || git clone https://github.com/vc-teahouse/Baseband-guard && echo "[+] Repository cloned."
    cd "$GKI_ROOT/Baseband-guard"
    cd "$SECURITY_DIR"
    ln -sf "$(realpath --relative-to="$SECURITY_DIR" "$GKI_ROOT/Baseband-guard")" "baseband-guard" && echo "[+] Symlink created."

    # Add entries in Makefile and Kconfig if not already existing
    grep -q "baseband-guard" "$SECURITY_MAKEFILE" || printf "\nobj-\$(CONFIG_SECURITY_BASEBAND_GUARD) += baseband-guard/baseband_guard.o\n" >> "$SECURITY_MAKEFILE" && echo "[+] Modified Makefile."
    grep -q "source \"security/baseband-guard/Kconfig\"" "$SECURITY_KCONFIG" || sed -i "/endmenu/i\source \"security/baseband-guard/Kconfig\"" "$SECURITY_KCONFIG" && echo "[+] Modified Kconfig."
    echo '[+] Done.'
}

# Process command-line arguments
if [ "$#" -eq 0 ]; then
    initialize_variables
    setup_anti_format
elif [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    display_usage
elif [ "$1" = "--cleanup" ]; then
    initialize_variables
    perform_cleanup
else
    initialize_variables
    setup_baseband-guard "$@"
fi
