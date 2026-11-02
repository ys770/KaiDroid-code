#!/usr/bin/env bash
# Build the diagnostic ARM32 bridge on a Linux host with an existing Android NDK.
set -euo pipefail
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 NDK_ROOT NEW_OUTPUT_DIRECTORY" >&2
  exit 2
fi
ndk=$(realpath "$1")
output=$2
compiler="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi30-clang"
test -x "$compiler"
test ! -e "$output"
mkdir "$output"
source_file=$(dirname "$(realpath "$0")")/n139dl_hall_bridge.c
"$compiler" -Wall -Wextra -Werror -O2 "$source_file" -o "$output/hall-bridge"
"$compiler" --version > "$output/compiler.txt"
sha256sum "$source_file" "$output/hall-bridge" > "$output/sha256.txt"
