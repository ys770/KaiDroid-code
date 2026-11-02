#!/usr/bin/env bash
# Run inside the dedicated container with the new workspace mounted at /build.
# Does not clean, reset, prune or delete existing checkouts.
set -euo pipefail
cd /build
export HOME=/build/container-home
mkdir -p "$HOME" logs
exec > >(tee -a logs/source-sync.log) 2>&1
trap 'code=$?; printf "%s\n" "$code" > /build/logs/source-sync.exit; exit "$code"' EXIT
date -u
free_kb=$(df -Pk /build | awk 'NR==2 {print $4}')
(( free_kb >= 400 * 1024 * 1024 )) || { echo 'Less than 400 GiB free; stop without deleting files.'; exit 2; }
if [[ ! -d repo-launcher ]]; then
    git clone --depth 1 --branch stable https://gerrit.googlesource.com/git-repo repo-launcher
fi
git -C repo-launcher rev-parse HEAD > logs/repo-launcher-revision.txt
export PATH=/build/repo-launcher:$PATH
git config --global user.name 'KaiDroid Build'
git config --global user.email 'kaidroid-build@localhost'
mkdir -p aosp
cd aosp
if [[ ! -f .repo/manifest.xml ]]; then
    repo init -u https://android.googlesource.com/platform/manifest \
        -b android-11.0.0_r1 --depth=1 --no-clone-bundle \
        --repo-url=https://gerrit.googlesource.com/git-repo --repo-rev=stable
fi
repo sync -c -j8 --no-tags --no-clone-bundle --fail-fast
repo manifest -r -o /build/logs/aosp-resolved-manifest.xml
date -u
echo 'Source sync completed. No build or device operation has run.'
