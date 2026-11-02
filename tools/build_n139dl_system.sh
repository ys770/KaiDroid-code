#!/usr/bin/env bash
# Run on the separate Linux build host. Produces artifacts only; never flashes.
set -eo pipefail
if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 /absolute/path/to/synced/android11 [jobs]" >&2
  exit 2
fi
source_root=$(cd -- "$1" && pwd -P)
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
jobs=${2:-$(getconf _NPROCESSORS_ONLN)}
[[ $jobs =~ ^[1-9][0-9]*$ ]] || { echo 'jobs must be positive' >&2; exit 2; }
[[ -f $source_root/build/envsetup.sh && -d $source_root/.repo ]] || {
  echo 'Provide an already-synced complete AOSP repo checkout.' >&2; exit 2;
}
[[ -z $(git -C "$project_root" status --porcelain) ]] || {
  echo 'Commit KaiDroid changes before recording a reproducible build.' >&2; exit 2;
}
device_source=$project_root/device/nokia/n139dl
device_dest=$source_root/device/nokia/n139dl
if [[ -e $device_dest ]]; then
  diff -qr "$device_source" "$device_dest" || {
    echo 'Existing device tree differs; reconcile it explicitly before building.' >&2; exit 2;
  }
else
  mkdir -p -- "$(dirname -- "$device_dest")"
  cp -a -- "$device_source" "$device_dest"
fi
run_dir=$project_root/work/builds/$(date -u +%Y%m%dT%H%M%SZ)-$$
mkdir -p -- "$run_dir"
git -C "$project_root" rev-parse HEAD > "$run_dir/kaidroid-commit.txt"
cd -- "$source_root"
repo manifest -r -o "$run_dir/aosp-manifest.xml"
repo status > "$run_dir/aosp-status.txt"
# Local changes are recorded separately: a resolved manifest alone omits them.
repo forall -c 'git diff --exit-code HEAD -- >/dev/null && test -z "$(git ls-files --others --exclude-standard)"' || {
  echo 'AOSP contains local changes; use clean pinned sources for this build.' >&2; exit 2;
}
git -C build/make rev-parse HEAD > "$run_dir/platform-build-commit.txt"
# Source link-time encoding preserves normal APK alignment/signing. Originals
# and exact source hashes are retained alongside this run's evidence.
python3 "$project_root/tools/stage_resource_encoding.py" \
  --source "$source_root" --output "$run_dir/resource-encoding" --apply
# Opt-in until full platform/API checks and shared-window behavior are validated.
case ${KAIDROID_FRAMEWORK_STAGE:-0} in
  0) ;;
  1) python3 "$project_root/tools/stage_framework.py" \
       --source "$source_root/frameworks/base" \
       --report "$run_dir/framework-stage.json" --apply ;;
  *) echo 'KAIDROID_FRAMEWORK_STAGE must be 0 or 1' >&2; exit 2 ;;
esac
source build/envsetup.sh
lunch kaidroid_n139dl-eng
[[ $(get_build_var PLATFORM_VERSION) == 11 ]] || {
  echo 'This target is currently for Android 11 only.' >&2; exit 2;
}
for name in TARGET_ARCH TARGET_NO_RECOVERY TARGET_USES_64_BIT_BINDER BOARD_BUILD_SYSTEM_ROOT_IMAGE PRODUCT_SHIPPING_API_LEVEL \
  BOARD_SYSTEMIMAGE_PARTITION_SIZE PRODUCT_EXTRA_VNDK_VERSIONS TARGET_FLATTEN_APEX \
  PRODUCT_USE_DYNAMIC_PARTITIONS TARGET_COPY_OUT_PRODUCT TARGET_COPY_OUT_SYSTEM_EXT; do
  printf '%s=%s\n' "$name" "$(get_build_var "$name")"
done | tee "$run_dir/evaluated-config.txt"
[[ $(get_build_var BOARD_SYSTEMIMAGE_PARTITION_SIZE) == 834666496 ]] || exit 2
[[ $(get_build_var TARGET_ARCH) == arm ]] || exit 2
[[ $(get_build_var PRODUCT_SHIPPING_API_LEVEL) == 28 ]] || { echo 'Preserve the captured launch API 28' >&2; exit 2; }
[[ $(get_build_var TARGET_NO_RECOVERY) == true ]] || { echo "System-only target must not build recovery" >&2; exit 2; }
[[ $(get_build_var TARGET_USES_64_BIT_BINDER) == true ]] || exit 2
[[ $(get_build_var PRODUCT_USE_DYNAMIC_PARTITIONS) == false ]] || exit 2
[[ $(get_build_var BOARD_BUILD_SYSTEM_ROOT_IMAGE) == true ]] || exit 2
m -j"$jobs" systemimage 2>&1 | tee "$run_dir/build.log"
product_out=$(get_build_var PRODUCT_OUT)
[[ -f $product_out/system.img ]] || { echo 'No system image produced' >&2; exit 1; }
# Inspect the generated staging tree before reporting success. The eventual
# image-content audit remains required; do not import stock recovery rewriting.
[[ -d $product_out/system ]] || { echo "Missing system staging tree" >&2; exit 2; }
if find "$product_out/system" \( -name install-recovery.sh -o -name recovery-from-boot.p \) -print -quit | grep -q .; then
  echo 'Legacy recovery updater found in system staging tree; reject this build.' >&2
  exit 2
fi
sha256sum "$product_out/system.img" > "$run_dir/system-image.sha256"
printf 'Build completed: %s\nEvidence: %s\nNOT approved for flashing.\n' "$product_out/system.img" "$run_dir"
