#!/system/bin/sh
# Exact engineering UART termios entry probe; reads only the supplied termios fields.
# No UART read/write, radio toggle, global tracing switch or existing trace clear.
set -eu
[ "$#" -eq 2 ] || [ "$#" -eq 3 ] || exit 2
duration=${3:-20}
case "$duration" in ''|*[!0-9]*) exit 2;; esac
[ "$duration" -ge 1 ] && [ "$duration" -le 90 ] || exit 2
[ "$(cat /proc/sys/kernel/random/boot_id)" = "$1" ] || exit 3
[ "$(getprop ro.kaidroid.image)" = 26 ] || exit 3
case "$2" in /data/local/tmp/kaidroid-tty-*) ;; *) exit 2;; esac
D=$2
T=/sys/kernel/debug/tracing
I=$T/instances/kaidroid_bt_termios
E=kaidroid_bt_termios/settings
[ ! -e "$D" ] && [ ! -e "$I" ] && [ ! -e "$T/events/$E" ] || exit 4
[ "$(uname -r)" = '4.9.268+-ab00.2211.12.01' ] || exit 5
[ "$(id -u)" = 0 ] || exit 5
[ "$(getprop ro.serialno)" = DEVICE_SERIAL_REQUIRED ] || exit 5
grep -q '^c066a490 t msm_hs_set_termios$' /proc/kallsyms || exit 5
mkdir "$D"
made_instance=0
made_probe=0
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    set +e
    if [ "$made_instance" = 1 ]; then
        echo 0 > "$I/tracing_on"
        [ ! -e "$I/events/$E/enable" ] || echo 0 > "$I/events/$E/enable"
        cat "$I/trace" > "$D/trace.txt"
    fi
    if [ "$made_probe" = 1 ]; then echo "-:$E" >> "$T/kprobe_events"; fi
    if [ "$made_instance" = 1 ]; then rmdir "$I"; fi
    cat "$T/kprobe_events" > "$D/kprobe-events-after.txt"
    cat /proc/tty/driver/msm_serial_hs > "$D/uart-after.txt"
    if [ -e "$I" ] || [ -e "$T/events/$E" ]; then
        echo CLEANUP_INCOMPLETE
        exit 90
    fi
    exit "$result"
}
trap cleanup EXIT HUP INT TERM
cat "$T/kprobe_events" > "$D/kprobe-events-before.txt"
cat /proc/tty/driver/msm_serial_hs > "$D/uart-before.txt"
mkdir "$I"
made_instance=1
echo "p:$E msm_hs_set_termios iflag=+0(%r1):u32 cflag=+8(%r1):u32" >> "$T/kprobe_events"
made_probe=1
cat "$T/events/$E/format" > "$D/event-format.txt"
echo 1 > "$I/events/$E/enable"
echo 1 > "$I/tracing_on"
echo TTY_TRACE_READY
sleep "$duration"
cat "$T/kprobe_profile" > "$D/probe-profile.txt"
echo TTY_TRACE_FINISHED
