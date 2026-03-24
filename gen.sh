#!/bin/bash

# Chromium Production Build & Run Script
# - Safe for production (no interactive dependency)
# - Supports menu and CLI parameters
# - Explicit run flags hook (no behavior change unless specified)

set -e

OUT_DIR="out/Default"
OUT_DIR_REL_X64="out/Release-x64"
TARGET="chrome"
BIN_NAME="Chromium"

print_usage() {
    cat <<EOF
Usage: $0 [compile|run|both|release-x64]

Commands:
  compile      Build Chromium using autoninja (Default)
  run          Run already-built Chromium (Default)
  both         Compile and then run (Default)
  release-x64  Generate and Build Release x64 (Intel Mac)

If no argument is provided, an interactive menu is shown.
EOF
}

compile_chrome() {
    local out=$1
    echo "[INFO] Compiling Chromium in $out"
    if ! command -v autoninja >/dev/null 2>&1; then
        echo "[ERROR] autoninja not found in PATH"
        exit 1
    fi

    autoninja -C "$out" "$TARGET"
}

gen_release_x64() {
    echo "[INFO] Generating Release x64 configuration in $OUT_DIR_REL_X64"
    gn gen "$OUT_DIR_REL_X64" --args='is_debug=false target_cpu="x64" symbol_level=0'
}

resolve_app_path() {
    local out=$1
    if [ -d "$out/Chromium.app" ]; then
        echo "$out/Chromium.app/Contents/MacOS/$BIN_NAME"
        return
    fi

    if [ -d "$out/Google Chrome.app" ]; then
        echo "$out/Google Chrome.app/Contents/MacOS/Google Chrome"
        return
    fi

    if [ -x "$out/$TARGET" ]; then
        echo "$out/$TARGET"
        return
    fi

    echo ""
}

run_chrome() {
    local out=$1
    echo "[INFO] Running Chromium from $out"

    BIN_PATH=$(resolve_app_path "$out")
    if [ -z "$BIN_PATH" ]; then
        echo "[ERROR] Chromium executable not found in $out"
        exit 1
    fi

    echo "[INFO] Launching: $BIN_PATH"

    "$BIN_PATH" \
        --enable-logging=stderr \
        --v=0 \
        "${@:2}" #&
}

interactive_menu() {
    echo "Select an option:"
    echo "1. Compile (Default)"
    echo "2. Run (Default)"
    echo "3. Compile and Run (Default)"
    echo "4. Build Release x64 (Intel Mac)"
    read -r -p "Enter choice [1-4]: " choice

    case "$choice" in
        1)
            compile_chrome "$OUT_DIR"
            ;;
        2)
            run_chrome "$OUT_DIR"
            ;;
        3)
            compile_chrome "$OUT_DIR"
            run_chrome "$OUT_DIR"
            ;;
        4)
            gen_release_x64
            compile_chrome "$OUT_DIR_REL_X64"
            ;;
        *)
            echo "Invalid option"
            exit 1
            ;;
    esac
}

# ---- Entry Point ----

if [ "$#" -eq 0 ]; then
    interactive_menu
    exit 0
fi

case "$1" in
    1|compile)
        compile_chrome "$OUT_DIR"
        ;;
    2|run)
        run_chrome "$OUT_DIR" "$@"
        ;;
    3|both)
        compile_chrome "$OUT_DIR"
        run_chrome "$OUT_DIR" "$@"
        ;;
    4|release-x64)
        gen_release_x64
        compile_chrome "$OUT_DIR_REL_X64"
        ;;
    -h|--help)
        print_usage
        ;;
    *)
        echo "[ERROR] Unknown command: $1"
        print_usage
        exit 1
        ;;
esac
