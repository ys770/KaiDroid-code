#!/system/bin/sh
# Generated constants precede this body. Only the fresh owned instance is writable.
set -eu
root=/sys/kernel/tracing
alias=/sys/kernel/debug/tracing
inst="$root/instances/$name"
events='oom/oom_score_adj_update sched/sched_process_fork sched/sched_process_exec sched/sched_process_exit'
created=0
root_inode=''
instance_inode=''
timer_started=0
timer_joined=0
identity() {
  [ "$(getprop ro.kaidroid.image)" = 59 ] &&
  [ "$(cat /proc/sys/kernel/random/boot_id)" = "$boot" ] && [ "$(id -u)" = 0 ]
}
owned() {
  identity && [ "$created" = 1 ] &&
  [ "$(stat -c '%d:%i' "$root")" = "$root_inode" ] &&
  [ "$(stat -c '%d:%i' "$inst")" = "$instance_inode" ]
}
stop_owned() {
  owned || return 1
  printf '0\n' > "$inst/tracing_on" || return 1
  for ev in $events; do printf '0\n' > "$inst/events/$ev/enable" || return 1; done
  [ "$(cat "$inst/tracing_on")" = 0 ] || return 1
  for ev in $events; do [ "$(cat "$inst/events/$ev/enable")" = 0 ] || return 1; done
}
protected() {
  # No trace contents are read here. Snapshot metadata of root and all pre-existing instances.
  for base in "$root" "$alias"; do
    printf 'root=%s inode=%s\n' "$base" "$(stat -c '%d:%i' "$base")"
    count=0
    for scope in "$base" "$base"/instances/*; do
      [ -d "$scope" ] || continue
      if [ "$created" = 1 ] && [ "$(stat -c '%d:%i' "$scope")" = "$instance_inode" ]; then continue; fi
      count=$((count+1)); [ "$count" -le 9 ] || return 1
      printf 'scope=%s\n' "$scope"
      for f in tracing_on current_tracer trace_clock buffer_size_kb buffer_total_size_kb events/enable; do
        printf 'file=%s\n' "$f"; cat "$scope/$f" || return 1
      done
      for ev in $events; do
        for f in enable filter; do
          printf 'event=%s file=%s\n' "$ev" "$f"; cat "$scope/events/$ev/$f" || return 1
        done
      done
    done
  done
}
finish() {
  supervisor_rc=$?
  trap - EXIT HUP INT TERM
  # Stop first. Evidence writes and protected-state reads cannot postpone this stop.
  if [ "$created" = 1 ]; then
    printf 'stop\n' > "$work/stop.request" || :
    if stop_owned; then
      if [ "$timer_started" = 1 ] && [ "$timer_joined" != 1 ]; then
        printf 'stopped_at_cleanup_deadline_child_not_joined_recheck_required\n' > "$work/cleanup.txt"
      else printf 'instance_retained_stopped\n' > "$work/cleanup.txt"; fi
    else
      printf 'ownership_identity_or_stop_verification_failed\n' > "$work/cleanup.txt"
    fi
  else
    printf 'no_instance_created\n' > "$work/cleanup.txt"
  fi
  if identity && protected > "$work/protected-after.txt"; then
    if cmp -s "$work/protected-before.txt" "$work/protected-after.txt"; then
      printf 'equal\n' > "$work/protected-comparison.txt"
    else printf 'changed_not_restored\n' > "$work/protected-comparison.txt"; fi
  else printf 'unknown\n' > "$work/protected-comparison.txt"; fi
  printf '%s\n' "$supervisor_rc" > "$work/supervisor-exit.txt"
  printf 'finished\n' > "$work/finished.txt"
}
trap finish EXIT
trap 'exit 92' HUP INT TERM
identity
for cmd in stat cat head grep cmp sleep date wc; do command -v "$cmd" >/dev/null; done
date +%s.%N | grep -Eq '^[0-9]+\.[0-9]{9}$'
root_inode=$(stat -c '%d:%i' "$root")
[ "$(stat -c '%d:%i' "$alias")" = "$root_inode" ]
# The inspected four-CPU device is the only supported target. Fail before allocation on drift.
[ "$(cat /sys/devices/system/cpu/possible)" = 0-3 ]
[ "$(cat "$root/tracing_on")" = 0 ]
[ "$(cat "$root/current_tracer")" = nop ]
[ "$(cat "$root/events/enable")" = 0 ]
[ "$(cat "$root/instances/wifi/tracing_on")" = 0 ]
[ "$(cat "$root/instances/wifi/current_tracer")" = nop ]
[ "$(cat "$root/instances/wifi/events/enable")" = X ]
protected > "$work/protected-before.txt"
cmp -s "$root/events/oom/oom_score_adj_update/format" "$work/expected-oom-format.txt"
# Atomic mkdir is the ownership boundary. A collision never authorizes control writes.
mkdir "$inst"
created=1
instance_inode=$(stat -c '%d:%i' "$inst")
printf '%s\n' "$instance_inode" > "$work/instance-inode.txt"
printf '%s\n' "$root_inode" > "$work/root-inode.txt"
printf '0\n' > "$inst/tracing_on"
[ "$(cat "$inst/current_tracer")" = nop ]
[ "$(cat "$inst/events/enable")" = 0 ]
printf '64\n' > "$inst/buffer_size_kb"
[ "$(cat "$inst/buffer_total_size_kb")" = 256 ]
printf 'boot\n' > "$inst/trace_clock"
grep -F '[boot]' "$inst/trace_clock" > "$work/trace-clock.txt"
i=0
for ev in $events; do
  [ "$(cat "$inst/events/$ev/filter")" = none ]
  # Save the actual runtime schema, including all sched offsets and print formats.
  head -c 16385 "$inst/events/$ev/format" > "$work/format-$i.txt"
  [ "$(wc -c < "$work/format-$i.txt")" -le 16384 ]
  i=$((i+1))
done
cmp -s "$work/format-0.txt" "$work/expected-oom-format.txt"
grep -q 'field:.* parent_pid;' "$work/format-1.txt"
grep -q 'field:.* child_pid;' "$work/format-1.txt"
grep -q 'field:.* old_pid;' "$work/format-2.txt"
grep -q 'field:.* pid;' "$work/format-2.txt"
grep -q 'field:.*filename' "$work/format-2.txt"
grep -q 'field:.* pid;' "$work/format-3.txt"
for ev in $events; do printf '1\n' > "$inst/events/$ev/enable"; done
for ev in $events; do [ "$(cat "$inst/events/$ev/enable")" = 1 ]; done
for ev in $events; do [ "$(cat "$inst/events/$ev/filter")" = none ]; done
protected > "$work/protected-prearm.txt"
cmp -s "$work/protected-before.txt" "$work/protected-prearm.txt"
# Child arms and owns its deadline; parent/ADB loss cannot leave it waiting for a host stop.
(
  trap 'stop_owned' EXIT
  trap 'exit 93' HUP INT TERM
  [ ! -e "$work/stop.request" ]
  owned
  printf '1\n' > "$inst/tracing_on"
  if [ -e "$work/stop.request" ]; then exit 94; fi
  sleep "$seconds"
  stop_owned
  printf 'deadline_stopped\n' > "$work/deadline.txt"
) &
timer_pid=$!
timer_started=1
# Bound readiness waiting independently of host. No app is launched by this tool.
n=0
while [ "$(cat "$inst/tracing_on")" != 1 ]; do
  n=$((n+1)); [ "$n" -le 30 ]; sleep 0.1
done
# A boot-clock trace marker brackets realtime to permit explicit correlation uncertainty.
date +%s.%N > "$work/realtime-before.txt"
cat /proc/uptime > "$work/uptime.txt"
printf 'KAIDROID_PRIORITY_ARM_%s\n' "$name" > "$inst/trace_marker"
date +%s.%N > "$work/realtime-after.txt"
if [ "$(cat "$inst/tracing_on")" = 1 ]; then
  printf 'armed\n' > "$work/armed.txt"
fi
if wait "$timer_pid"; then
  timer_joined=1
  printf '0\n' > "$work/timer-exit.txt"
else
  timer_joined=1
  printf 'failed\n' > "$work/timer-exit.txt"; exit 95
fi
stop_owned
date +%s.%N > "$work/stopped-realtime.txt"
# Read only the owned, stopped buffer. Retain it and the instance after capture.
head -c 4194305 "$inst/trace" > "$work/trace.txt"
if [ "$(wc -c < "$work/trace.txt")" -gt 4194304 ]; then
  printf 'possibly_truncated\n' > "$work/trace-bound.txt"
else printf 'within_4MiB_bound\n' > "$work/trace-bound.txt"; fi
: > "$work/loss-stats.txt"
for cpu in "$inst"/per_cpu/cpu*; do
  [ -d "$cpu" ] || continue
  printf '%s\n' "${cpu##*/}" >> "$work/loss-stats.txt"
  cat "$cpu/stats" >> "$work/loss-stats.txt" || printf 'unreadable\n' >> "$work/loss-stats.txt"
done
