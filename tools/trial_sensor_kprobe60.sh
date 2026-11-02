#!/system/bin/sh
set -eu
P=/data/local/tmp/kaidroid-sensor-kprobe60-01
T=/sys/kernel/debug/tracing
I=$T/instances/kaidroid_sensor60_01
E=kaidroid_sensor60_01/result
cleanup() {
 if [ -d "$I" ]; then
  echo 0 > "$I/tracing_on"
  if [ -e "$I/events/$E/enable" ]; then echo 0 > "$I/events/$E/enable"; fi
 fi
 if [ -e "$T/events/$E/enable" ]; then
  echo 0 > "$T/events/$E/enable"
  echo '-:kaidroid_sensor60_01/result' >> "$T/kprobe_events"
 fi
}
if [ "${1:-}" = watchdog ]; then
 sleep 35
 cleanup
 echo finished > "$P/deadline"
 exit
fi
[ "$(getprop ro.serialno)" = DEVICE_SERIAL_REQUIRED ]
[ "$(getprop ro.kaidroid.image)" = 60 ]
[ "$(cat /proc/sys/kernel/random/boot_id)" = 00000000-0000-0000-0000-000000000007 ]
[ "$(pidof surfaceflinger system_server com.android.systemui)" = '538 1166 1339' ]
[ "$(getenforce)" = Enforcing ]
[ ! -e "$I" ]
[ ! -e "$P/started" ]
[ ! -e "$T/events/$E" ]
cat "$T/kprobe_events" > "$P/events-before"
[ ! -s "$P/events-before" ]
touch "$P/started"
trap cleanup EXIT
nohup sh "$P/worker.sh" watchdog </dev/null >"$P/watchdog.log" 2>&1 &
mkdir "$I"
echo 0 > "$I/tracing_on"
echo 32 > "$I/buffer_size_kb"
echo boot > "$I/trace_clock"
echo 'p:kaidroid_sensor60_01/result fastrpc_internal_invoke+0x1df0 result=%r7:s32' >> "$T/kprobe_events"
cat "$I/events/$E/format" > "$P/format"
"$P/trial" > "$P/trial.stdout" 2> "$P/trial.stderr" &
supervisor=$!
echo "$supervisor" > "$P/supervisor.pid"
n=0
child=
while [ "$n" -lt 50 ]; do
 child=$(sed -n 's/.*"supervised_host_pid":\([0-9]*\).*/\1/p' "$P/trial.stdout")
 if [ -n "$child" ] && [ -r "/proc/$child/status" ] && grep -q '^State:.*T' "/proc/$child/status"; then break; fi
 n=$((n+1)); sleep 0.1
done
[ -n "$child" ]
grep -q '^State:.*T' "/proc/$child/status"
cat "/proc/$child/stat" > "$P/child-before.stat"
echo "common_pid == $child" > "$I/events/$E/filter"
cat "$I/events/$E/filter" > "$P/filter"
echo 1 > "$I/events/$E/enable"
echo 1 > "$I/tracing_on"
cat /proc/uptime > "$P/start"
kill -CONT "$child"
set +e
wait "$supervisor"
status=$?
set -e
echo "$status" > "$P/trial.exit"
echo 0 > "$I/tracing_on"
echo 0 > "$I/events/$E/enable"
cat "$I/trace" > "$P/trace"
for f in "$I"/per_cpu/cpu*/stats; do echo "$f"; cat "$f"; done > "$P/stats"
dmesg > "$P/kernel"
cleanup
cat "$T/kprobe_events" > "$P/events-after"
cmp "$P/events-before" "$P/events-after"
[ "$(pidof surfaceflinger system_server com.android.systemui)" = '538 1166 1339' ]
[ "$(cat /proc/sys/kernel/random/boot_id)" = 00000000-0000-0000-0000-000000000007 ]
echo finished > "$P/finished"
cat "$P/trial.exit" "$P/trial.stderr" "$P/trace"
