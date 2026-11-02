#!/system/bin/sh
# Bounded runtime bind trial. Original vendor file is never overwritten.
set -eu
[ "$#" -eq 2 ] || exit 2
[ "$(id -u)" = 0 ] || exit 3
[ "$(getprop ro.serialno)" = DEVICE_SERIAL_REQUIRED ] || exit 3
[ "$(getprop ro.kaidroid.image)" = 26 ] || exit 3
[ "$(cat /proc/sys/kernel/random/boot_id)" = "$1" ] || exit 3
D=$2
case "$D" in /data/local/tmp/kaidroid-bt-settle-*) ;; *) exit 2;; esac
V=/vendor/lib/libbt-vendor-brt.so
C=/data/local/tmp/kaidroid-bt-settle-candidate.so
original=449114161c34d4ec5b69afa744dcc1d206e9407cc03aa09787d71936e459c35d
candidate=7b430074d1fa1025a31cb1948d1e509a7262e1cd0ef58ea983e6b2f52954dd0a
[ "$(sha256sum "$V" | cut -d' ' -f1)" = "$original" ] || exit 4
[ "$(sha256sum "$C" | cut -d' ' -f1)" = "$candidate" ] || exit 4
[ ! -e "$D" ] || exit 4
mkdir "$D"
dumpsys bluetooth_manager > "$D/before.txt"
grep -q 'state: ON' "$D/before.txt" || exit 5
grep -q 'ConnectionState: STATE_DISCONNECTED' "$D/before.txt" || exit 5
mounted=0
off() {
    svc bluetooth disable
    for n in 1 2 3 4 5 6 7 8 9 10; do
        dumpsys bluetooth_manager > "$D/off-latest.txt"
        if grep -q 'state: OFF' "$D/off-latest.txt" &&
           ! pidof android.hardware.bluetooth@1.0-service-qti-lazy >/dev/null; then return 0; fi
        sleep 2
    done
    return 1
}
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    set +e
    logcat -b crash -d > "$D/crash-at-cleanup.txt"
    dumpsys bluetooth_manager > "$D/state-at-cleanup.txt"
    off
    if [ "$mounted" = 1 ]; then umount "$V" || result=90; fi
    sha256sum "$V" > "$D/restored-hash.txt"
    [ "$(sha256sum "$V" | cut -d' ' -f1)" = "$original" ] || result=91
    svc bluetooth enable
    sleep 15
    dumpsys bluetooth_manager > "$D/restored-state.txt"
    cat /proc/tty/driver/msm_serial_hs > "$D/uart-restored.txt"
    logcat -b crash -d > "$D/crash-after-restore.txt"
    echo "TRIAL_FINISHED status=$result"
    exit "$result"
}
trap cleanup EXIT HUP INT TERM
off
chmod 644 "$C"
chcon u:object_r:vendor_file:s0 "$C"
mount -o bind "$C" "$V"
mounted=1
sha256sum "$V" > "$D/trial-hash.txt"
for n in 1 2 3; do
    cat /proc/tty/driver/msm_serial_hs > "$D/uart-before-$n.txt"
    svc bluetooth enable
    sleep 15
    dumpsys bluetooth_manager > "$D/after-$n.txt"
    cat /proc/tty/driver/msm_serial_hs > "$D/uart-after-$n.txt"
    grep -q 'state: ON' "$D/after-$n.txt" || exit 6
    echo "CYCLE_$n"
    off
done
logcat -b crash -d > "$D/crash.txt"
