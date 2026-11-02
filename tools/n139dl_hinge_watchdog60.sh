#!/system/bin/sh
# Finite device-side cleanup for one owner-created engineering hinge test.
# Arguments: existing private lease directory, exact boot UUID, 10..300 seconds.
set -eu
lease=$1
expected_boot=$2
seconds=$3
case "$lease" in /data/local/tmp/kaidroid-hinge-watchdog-*) ;; *) exit 2;; esac
case "$lease" in *..*|*[!a-zA-Z0-9/_-]*) exit 2;; esac
case "$seconds" in ''|*[!0-9]*) exit 2;; esac
test "$seconds" -ge 10 && test "$seconds" -le 300
test -d "$lease" && test ! -e "$lease/ready"
test "$(id -u)" = 0
test "$(getprop ro.kaidroid.image)" = 60
test "$(cat /proc/sys/kernel/random/boot_id)" = "$expected_boot"
test "$(settings get global lid_behavior)" = 0
printf '%s\n' "$$" > "$lease/pid"
cat /proc/uptime > "$lease/started-uptime"
printf 'armed\n' > "$lease/ready"
sleep "$seconds"
if test -e "$lease/cancelled"; then
    printf 'cancelled-after-host-cleanup\n' > "$lease/result"
    exit 0
fi
test "$(cat /proc/sys/kernel/random/boot_id)" = "$expected_boot"
test "$(getprop ro.kaidroid.image)" = 60
# A host may have already restored the same state. Repeating cleanup is safe.
timeout 20 settings put global lid_behavior 0
setprop ctl.stop kaidroid-hall
sleep 2
test "$(settings get global lid_behavior)" = 0
test "$(getprop init.svc.kaidroid-hall)" = stopped
if grep -q 'KaiDroid Nokia Lid' /proc/bus/input/devices; then exit 1; fi
cat /proc/uptime > "$lease/restored-uptime"
printf 'restored\n' > "$lease/result"
