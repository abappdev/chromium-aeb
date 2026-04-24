#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASEDIR_SRC="$SCRIPT_DIR"
INSTALLER_DIR="$BASEDIR_SRC/../installer/MAC"
SIGN_DIR="$INSTALLER_DIR/HyWorksInstaller/sign"
CLIENT_DIR="$INSTALLER_DIR/HyWorksInstaller/Client"
BUILD_DIR="$INSTALLER_DIR/build"
BUILDVER_FILE="$BASEDIR_SRC/buildver.h"
NOTARIZATION_LOG="/Users/accops/Documents/Repo/EDCClient/endpoint/installer/MAC/HyWorksInstaller/sign/notarization_log.json"

NIC_ENABLED=false
if [[ "${1:-}" == "NIC" ]]; then
  NIC_ENABLED=true
fi

PACKAGE_TYPES=(
  "Notarized"
  "JioSphereNotarized"
  "WindowsAppIntegrated"
  "PCOIP"
)

timestamp() {
  date "+%Y-%m-%d %H:%M:%S"
}

log() {
  echo "[$(timestamp)] [INFO] $*"
}

warn() {
  echo "[$(timestamp)] [WARN] $*" >&2
}

fail() {
  echo "[$(timestamp)] [ERROR] $*" >&2
  exit 1
}

run_cmd() {
  log "Running: $*"
  "$@"
}

get_version() {
  [[ -f "$BUILDVER_FILE" ]] || fail "buildver.h not found at $BUILDVER_FILE"
  grep 'INSTALLER_BUILD_NO' "$BUILDVER_FILE" | cut -d'"' -f2
}

get_package_types() {
  if [[ "$NIC_ENABLED" == true ]]; then
    echo "Notarized"
  else
    printf "%s\n" "${PACKAGE_TYPES[@]}"
  fi
}

package_output_dir() {
  local version="$1"
  local pkg_type="$2"

  if [[ "$NIC_ENABLED" == true && "$pkg_type" == "Notarized" ]]; then
    echo "$INSTALLER_DIR/AccopsWorkspace-NIC-$version"
  else
    echo "$INSTALLER_DIR/AccopsWorkspace-${pkg_type}-$version"
  fi
}

package_dmg_path() {
  local version="$1"
  local pkg_type="$2"
  local output_dir
  output_dir="$(package_output_dir "$version" "$pkg_type")"
  echo "${output_dir}.dmg"
}

sync_nic_frameworks_if_needed() {
  if [[ "$NIC_ENABLED" != true ]]; then
    return
  fi

  local nic_dir="$BASEDIR_SRC/../tools/mac_nic_frameworks_libs"
  [[ -d "$nic_dir" ]] || fail "NIC frameworks directory not found at $nic_dir"

  log "NIC mode enabled - syncing NIC frameworks"
  run_cmd cp -rf "$nic_dir"/. "$BASEDIR_SRC/macbuild/Frameworks/"
}

create_and_copy_zip() {
  local app_name="Accops Workspace"
  local zip_file="${app_name}.zip"
  local app_bundle="$BASEDIR_SRC/ui/release/${app_name}.app"

  log "Preparing application zip for signing"
  sync_nic_frameworks_if_needed

  pushd "$BASEDIR_SRC" >/dev/null
  run_cmd ./createbuild_macServer.sh
  [[ -d "$app_bundle" ]] || fail "App bundle not found at $app_bundle"

  run_cmd ditto -c -k --sequesterRsrc --keepParent \
    "$app_bundle" "$BASEDIR_SRC/ui/release/$zip_file"

  run_cmd rm -f "$SIGN_DIR"/*.zip
  run_cmd cp "$BASEDIR_SRC/ui/release/$zip_file" "$SIGN_DIR/"
  popd >/dev/null
}

sign_installer_zip() {
  [[ -d "$SIGN_DIR" ]] || fail "Sign directory not found at $SIGN_DIR"

  log "Signing installer zip"
  pushd "$SIGN_DIR" >/dev/null
  run_cmd ./step1.sh
  run_cmd ./step2.sh
  popd >/dev/null
}

prepare_client_zip() {
  local app_name="Accops Workspace"
  local signed_zip="$SIGN_DIR/${app_name}_.zip"
  local client_zip="$CLIENT_DIR/${app_name}.zip"

  [[ -f "$signed_zip" ]] || fail "Signed client zip not found at $signed_zip"

  log "Preparing client zip"
  run_cmd rm -f "$CLIENT_DIR"/"${app_name}"*.zip
  run_cmd /opt/homebrew/bin/md5sum "$signed_zip"
  run_cmd cp "$signed_zip" "$client_zip"
  run_cmd /opt/homebrew/bin/md5sum "$client_zip"
}

clean_build_dir() {
  log "Cleaning build directory"
  run_cmd rm -rf "$BUILD_DIR"
  run_cmd mkdir -p "$BUILD_DIR"
}

build_package_project() {
  local pkg_type="$1"
  local pkgproj_file="$INSTALLER_DIR/Installer_${pkg_type}.pkgproj"

  [[ -f "$pkgproj_file" ]] || {
    warn "Package project file missing for $pkg_type at $pkgproj_file. Skipping."
    return 1
  }

  log "Building package project for $pkg_type"
  run_cmd /usr/local/bin/packagesbuild -v "$pkgproj_file"
}

run_notarization_if_needed() {
  local pkg_type="$1"

  if [[ "$pkg_type" != *"Notarized"* ]]; then
    log "No notarization required for $pkg_type"
    return
  fi

  [[ -x "$INSTALLER_DIR/executeSigning.sh" ]] || fail \
    "executeSigning.sh not found or not executable at $INSTALLER_DIR/executeSigning.sh"

  log "Starting notarization/signing flow for $pkg_type"
  pushd "$INSTALLER_DIR" >/dev/null
  run_cmd ./executeSigning.sh
  popd >/dev/null

  if [[ -f "$NOTARIZATION_LOG" ]]; then
    log "Notarization log present: $NOTARIZATION_LOG"
  else
    warn "Notarization log not found at $NOTARIZATION_LOG after executeSigning.sh"
  fi

  log "Notarization/signing flow completed for $pkg_type"
}

stage_built_package() {
  local version="$1"
  local pkg_type="$2"
  local output_dir

  output_dir="$(package_output_dir "$version" "$pkg_type")"
  log "Staging package artifacts for $pkg_type into $output_dir"

  run_cmd rm -rf "$output_dir"
  run_cmd mkdir -p "$output_dir"

  if compgen -G "$BUILD_DIR/*" > /dev/null; then
    run_cmd mv -f "$BUILD_DIR"/* "$output_dir"/
  else
    fail "No build artifacts found in $BUILD_DIR for $pkg_type"
  fi
}

create_dmg_for_package() {
  local version="$1"
  local pkg_type="$2"
  local output_dir dmg_path dir_name

  output_dir="$(package_output_dir "$version" "$pkg_type")"
  dmg_path="$(package_dmg_path "$version" "$pkg_type")"
  dir_name="$(basename "$output_dir")"

  [[ -d "$output_dir" ]] || fail "Source folder for DMG not found at $output_dir"

  log "Creating DMG for $pkg_type from $output_dir"
  run_cmd hdiutil create -volname "$dir_name" -srcfolder "$output_dir" \
    -ov -format UDZO "$dmg_path"
  run_cmd /opt/homebrew/bin/md5sum "$dmg_path"
  log "DMG ready for $pkg_type: $dmg_path"
}

build_packages_and_dmgs() {
  local version="$1"
  local pkg_type

  while IFS= read -r pkg_type; do
    [[ -n "$pkg_type" ]] || continue

    log "=============================="
    log "Processing package type: $pkg_type"
    log "=============================="

    clean_build_dir

    if ! build_package_project "$pkg_type"; then
      continue
    fi

    run_notarization_if_needed "$pkg_type"
    stage_built_package "$version" "$pkg_type"
    create_dmg_for_package "$version" "$pkg_type"
  done < <(get_package_types)
}

copy_installer_to_qnap() {
  local version="$1"
  local base_dst_dir="/Volumes/Accops-Teams/QA Releases/HyDesk/Unified_LinuxMacRHEL/MacOS/MAC-$version"
  local dst_dir="$base_dst_dir"

  if [[ -d "$base_dst_dir" ]]; then
    local timestamp_suffix
    timestamp_suffix="$(date +"%Y%m%d-%H%M%S")"
    dst_dir="${base_dst_dir}-${timestamp_suffix}"
    warn "Destination already exists. Using $dst_dir"
  fi

  run_cmd mkdir -p "$dst_dir"
  log "Copying DMGs to $dst_dir"

  if [[ "$NIC_ENABLED" == true ]]; then
    run_cmd cp "$(package_dmg_path "$version" "Notarized")" "$dst_dir/"
  else
    local pkg_type
    while IFS= read -r pkg_type; do
      [[ -n "$pkg_type" ]] || continue
      run_cmd cp "$(package_dmg_path "$version" "$pkg_type")" "$dst_dir/"
    done < <(get_package_types)
  fi

  log "QNAP copy completed"
}

commit_generated_files() {
  if [[ "$NIC_ENABLED" == true ]]; then
    log "NIC mode enabled - skipping git commit/push"
    return
  fi

  log "Committing generated files"
  pushd "$BASEDIR_SRC" >/dev/null
  run_cmd git add macbuild/* maclib/* "$NOTARIZATION_LOG"
  run_cmd git commit -m "MAC CLIENT VERSIONS UPDATED AND FILES COMMITTED"
  run_cmd git push
  popd >/dev/null
}

main() {
  local start_time end_time duration version

  start_time="$(date +%s)"
  version="$(get_version)"

  clear
  log "Build script started"
  log "Base directory: $BASEDIR_SRC"
  log "Version: $version"
  if [[ "$NIC_ENABLED" == true ]]; then
    log "NIC mode enabled"
  fi

  create_and_copy_zip
  sign_installer_zip
  prepare_client_zip
  build_packages_and_dmgs "$version"
  copy_installer_to_qnap "$version"
  commit_generated_files

  end_time="$(date +%s)"
  duration="$((end_time - start_time))"

  log "Build script completed successfully"
  log "Total execution time: ${duration} seconds"
}

main "$@"
