#!/usr/bin/env bash
# Read-only preflight; run on the intended Linux build host.
set -euo pipefail
build_path="${1:-$PWD}"
printf 'System: '; uname -srm
printf 'CPU threads: '; getconf _NPROCESSORS_ONLN
printf '\nMemory and swap:\n'; free -h
printf '\nBuild filesystem:\n'; df -hT "$build_path"
printf '\nDistribution:\n'; cat /etc/os-release
printf '\nTools:\n'
for tool in git python3 repo make gcc g++ java zip unzip curl; do
    command -v "$tool" || true
done
printf '\nPlanning target: x86_64 Linux, 64 GiB RAM, 400+ GB free SSD; 1 TB SSD preferred.\n'
printf 'Older Android requirements depend on the selected branch. No sources downloaded or packages installed.\n'
if grep -qi microsoft /proc/sys/kernel/osrelease; then
    printf 'WSL detected: also check Windows backing-volume free space; df can overstate usable capacity.\n'
fi
