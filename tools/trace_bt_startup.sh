#!/system/bin/sh
# One isolated clock for exact engineering UART settings, writes and BREAK path.
set -eu
[ "$#" -eq 2 ] || exit 2
[ "$(id -u)" = 0 ] || exit 3
[ "$(getprop ro.serialno)" = DEVICE_SERIAL_REQUIRED ] || exit 3
[ "$(getprop ro.kaidroid.image)" = 26 ] || exit 3
[ "$(cat /proc/sys/kernel/random/boot_id)" = "$1" ] || exit 3
[ "$(uname -r)" = '4.9.268+-ab00.2211.12.01' ] || exit 3
case "$2" in /data/local/tmp/kaidroid-tty-*) ;; *) exit 2;; esac
D=$2
T=/sys/kernel/debug/tracing
G=kaidroid_bt_startup
I=$T/instances/$G
[ ! -e "$D" ] && [ ! -e "$I" ] && [ ! -e "$T/events/$G" ] || exit 4
grep -q '^c0661f58 t uart_write$' /proc/kallsyms || exit 5
grep -q '^c066a490 t msm_hs_set_termios$' /proc/kallsyms || exit 5
grep -q '^c066b1a4 t msm_serial_hs_rx_work$' /proc/kallsyms || exit 5
mkdir "$D"
created=''
instance=0
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    set +e
    if [ "$instance" = 1 ]; then
        echo 0 > "$I/tracing_on"
        for e in $created; do echo 0 > "$I/events/$G/$e/enable"; done
        cat "$I/trace" > "$D/trace.txt"
    fi
    cat "$T/kprobe_profile" > "$D/probe-profile.txt"
    for e in $created; do echo "-:$G/$e" >> "$T/kprobe_events"; done
    [ "$instance" = 0 ] || rmdir "$I"
    cat "$T/kprobe_events" > "$D/probes-after.txt"
    cat /proc/tty/driver/msm_serial_hs > "$D/uart-after.txt"
    dumpsys bluetooth_manager > "$D/bluetooth-after.txt"
    logcat -b crash -d > "$D/crash-after.txt"
    if [ -e "$I" ] || [ -e "$T/events/$G" ]; then exit 90; fi
    exit "$result"
}
trap cleanup EXIT HUP INT TERM
cat "$T/kprobe_events" > "$D/probes-before.txt"
cat /proc/tty/driver/msm_serial_hs > "$D/uart-before.txt"
dumpsys bluetooth_manager > "$D/bluetooth-before.txt"
mkdir "$I"
instance=1
echo "p:$G/tx uart_write tty=%r0 count=%r2 first=+0(%r1):u8" >> "$T/kprobe_events"
created='tx'
echo "p:$G/settings msm_hs_set_termios port=%r0 iflag=+0(%r1):u32 cflag=+8(%r1):u32" >> "$T/kprobe_events"
created='tx settings'
echo "p:$G/break_path msm_serial_hs_rx_work+0x438 port=%r4 mask=+88(%r4):u32" >> "$T/kprobe_events"
created='tx settings break_path'
for e in $created; do
    cat "$T/events/$G/$e/format" > "$D/format-$e.txt"
    echo 1 > "$I/events/$G/$e/enable"
done
echo 1 > "$I/tracing_on"
echo STARTUP_TRACE_READY
sleep 60
echo STARTUP_TRACE_FINISHED
