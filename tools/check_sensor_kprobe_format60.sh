#!/system/bin/sh
# Register a DISABLED event, read its format, then remove only this owned event.
set -eu
[ "$(getprop ro.serialno)" = DEVICE_SERIAL_REQUIRED ]
[ "$(getprop ro.kaidroid.image)" = 60 ]
[ "$(cat /proc/sys/kernel/random/boot_id)" = 00000000-0000-0000-0000-000000000007 ]
[ "$(pidof surfaceflinger system_server com.android.systemui)" = '538 1166 1339' ]
[ "$(getenforce)" = Enforcing ]
T=/sys/kernel/debug/tracing
P=/data/local/tmp/kaidroid-sensor-kprobe-format60-01
E=kaidroid_sensor_format60/result
[ ! -e "$T/events/$E" ]
mkdir "$P"
cat "$T/kprobe_events" > "$P/before"
[ ! -s "$P/before" ]
cleanup() {
 if [ -d "$T/events/$E" ]; then
  echo 0 > "$T/events/$E/enable"
  echo '-:kaidroid_sensor_format60/result' >> "$T/kprobe_events"
 fi
}
trap cleanup EXIT
# Independent cleanup only; this script never enables the event or starts a sensor.
nohup sh -c 'sleep 15; T=/sys/kernel/debug/tracing; if [ -d "$T/events/kaidroid_sensor_format60/result" ]; then echo 0 > "$T/events/kaidroid_sensor_format60/result/enable"; echo "-:kaidroid_sensor_format60/result" >> "$T/kprobe_events"; fi; echo finished > /data/local/tmp/kaidroid-sensor-kprobe-format60-01/deadline' </dev/null >"$P/watchdog.log" 2>&1 &
# cmp r7,#0 follows the context result load in the exact hash-bound kernel.
echo 'p:kaidroid_sensor_format60/result fastrpc_internal_invoke+0x1df0 result=%r7:s32' >> "$T/kprobe_events"
[ "$(cat "$T/events/$E/enable")" = 0 ]
cat "$T/events/$E/format" > "$P/format"
cat "$T/kprobe_events" > "$P/registered"
cleanup
cat "$T/kprobe_events" > "$P/after"
cmp "$P/before" "$P/after"
[ "$(cat /proc/sys/kernel/random/boot_id)" = 00000000-0000-0000-0000-000000000007 ]
[ "$(pidof surfaceflinger system_server com.android.systemui)" = '538 1166 1339' ]
echo passed > "$P/result"
cat "$P/format"
