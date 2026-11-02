#!/usr/bin/env bash
# Execute on your configured build host; sudo may request local authentication.
set -eo pipefail
root=/opt/kaidroid/kaidroid-build-20261023
stage="$root/sparse-lookup-build01"
test -f "$stage/build_sparse_lookup.sh"
test ! -e "$stage/container-id"
test ! -e "$stage/build.log"
if pgrep -x ninja >/dev/null || pgrep -x soong_build >/dev/null; then
  echo 'An AOSP build is already running; do not launch another.' >&2
  exit 1
fi
sudo docker image inspect kaidroid-build:20261023 --format '{{.Id}}' > "$stage/container-image-id"
sudo docker run -d --name kaidroid-sparse-lookup01 \
  -v "$root:/build" kaidroid-build:20261023 \
  bash /build/sparse-lookup-build01/build_sparse_lookup.sh > "$stage/container-id"
cat "$stage/container-id"
