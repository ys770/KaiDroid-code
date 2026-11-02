#!/system/bin/sh
# Bounded observational tracer; caller performs any adapter state changes.
# Usage: sh watch_bluetooth_hal.sh EXPECTED_BOOT OLD_HAL_PID NEW_CAPTURE_DIR
set -eu
[ "$#" -eq 3 ] || exit 2
[ "$(cat /proc/sys/kernel/random/boot_id)" = "$1" ] || exit 3
[ "$(getprop ro.kaidroid.image)" = 26 ] || exit 3
[ "$(id -u)" = 0 ] || exit 3
case "$2" in ''|*[!0-9]*) exit 2;; esac
case "$3" in /data/local/tmp/kaidroid-bt-*) ;; *) exit 2;; esac
[ ! -e "$3" ] || exit 4
mkdir "$3"
D=$3
seen=" $2 "
jobs=""
count=0
start=$(cut -d . -f 1 /proc/uptime)
echo WATCH_READY
while [ $(( $(cut -d . -f 1 /proc/uptime) - start )) -lt 60 ]; do
    for p in $(pidof android.hardware.bluetooth@1.0-service-qti-lazy || true); do
        case "$seen" in *" $p "*) continue;; esac
        seen="$seen$p "
        [ -r "/proc/$p/status" ] || continue
        traced=$(awk '/^TracerPid:/ {print $2}' "/proc/$p/status")
        [ "$traced" = 0 ] || { echo ALREADY_TRACED_$p; continue; }
        # pidof is exact, but retain the command line for postflight provenance.
        tr '\000' ' ' < "/proc/$p/cmdline" > "$D/cmdline-$p.txt" || continue
        cat /proc/tty/driver/msm_serial_hs > "$D/uart-before-$p.txt"
        echo ATTACH_$p
        timeout -s INT 40 strace -f -tt -T -xx -v -y -s 64 \
            -e trace=read,readv,write,writev,ioctl,openat,close -P /dev/ttyHS0 -p "$p" \
            > "$D/trace-$p.txt" 2>&1 &
        jobs="$jobs $!"
        count=$((count + 1))
        [ "$count" -lt 3 ] || break
    done
    [ "$count" -lt 3 ] || break
    sleep 0.05
done
# Every tracer has its own phone deadline; waiting does not restart anything.
for j in $jobs; do wait "$j" || true; done
cat /proc/tty/driver/msm_serial_hs > "$D/uart-after.txt"
echo WATCH_FINISHED
