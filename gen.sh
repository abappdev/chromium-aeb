#!/bin/bash

# Chromium Production Build & Run Script
# - Safe for production (no interactive dependency)
# - Supports menu and CLI parameters
# - Explicit run flags hook (no behavior change unless specified)

set -e

OUT_DIR="out/Default"
TARGET="chrome"
BIN_NAME="Chromium"

print_usage() {
    cat <<EOF
Usage: $0 [compile|run|both]

Commands:
  compile   Build Chromium using autoninja
  run       Run already-built Chromium
  both      Compile and then run

If no argument is provided, an interactive menu is shown.
EOF
}

compile_chrome() {
    echo "[INFO] Compiling Chromium in $OUT_DIR"
    if ! command -v autoninja >/dev/null 2>&1; then
        echo "[ERROR] autoninja not found in PATH"
        exit 1
    fi

    autoninja -C "$OUT_DIR" "$TARGET"
}

resolve_app_path() {
    if [ -d "$OUT_DIR/Chromium.app" ]; then
        echo "$OUT_DIR/Chromium.app/Contents/MacOS/$BIN_NAME"
        return
    fi

    if [ -d "$OUT_DIR/Google Chrome.app" ]; then
        echo "$OUT_DIR/Google Chrome.app/Contents/MacOS/Google Chrome"
        return
    fi

    if [ -x "$OUT_DIR/$TARGET" ]; then
        echo "$OUT_DIR/$TARGET"
        return
    fi

    echo ""
}

run_chrome() {
    echo "[INFO] Running Chromium"

    BIN_PATH=$(resolve_app_path)
    if [ -z "$BIN_PATH" ]; then
        echo "[ERROR] Chromium executable not found in $OUT_DIR"
        exit 1
    fi

    echo "[INFO] Launching: $BIN_PATH"

    "$BIN_PATH" \
        --enable-logging=stderr \
        --v=0 \
        "$@" &
}

interactive_menu() {
    echo "Select an option:"
    echo "1. Compile"
    echo "2. Run"
    echo "3. Compile and Run"
    read -r -p "Enter choice [1-3]: " choice

    case "$choice" in
        1)
            compile_chrome
            ;;
        2)
            run_chrome
            ;;
        3)
            compile_chrome
            run_chrome
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
    1)
        compile_chrome
        ;;
    2)
        shift
        run_chrome "$@"
        ;;
    3)
        shift
        compile_chrome
        run_chrome "$@"
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
