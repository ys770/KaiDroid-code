#!/system/bin/sh
# Constants are prepended offline. No test mode or environment override exists.
set -eu
record_key=iorapd.perfetto.enable
job_id=@@JOB_ID@@
worker_pid=''
worker_start=''
work_inode=''
helper_shell=sh

ticks() {
  typeset raw tail
  raw=$(cat "/proc/$1/stat") || return 1
  tail=${raw##*) }
  set -- $tail
  [ "$#" -ge 20 ] || return 1
  printf '%s\n' "${20}"
}
same_boot() {
  [ "$(id -u)" = 0 ] && [ "$(getprop ro.serialno)" = "$serial" ] &&
  [ "$(getprop ro.kaidroid.image)" = 60 ] &&
  [ "$(cat /proc/sys/kernel/random/boot_id)" = "$boot" ]
}
guard() {
  typeset process pid start
  same_boot && [ "$(getenforce)" = Enforcing ] || return 1
  while read -r process pid start; do
    [ "$(pidof "$process")" = "$pid" ] && [ "$(ticks "$pid")" = "$start" ] || return 1
  done < "$stage/identities.txt"
  [ "$(readlink /proc/$iorap_pid/exe)" = /system/bin/iorapd ]
}
owned() {
  same_boot && [ -n "$work_inode" ] &&
  [ "$(stat -c '%d:%i' "$work")" = "$work_inode" ] &&
  [ "$(cat "$work/owner")" = "$nonce" ]
}
now() { typeset seconds rest; read -r seconds rest < /proc/uptime; printf '%s\n' "${seconds%.*}"; }
run() {
  typeset label
  label=$1; shift
  # Timeout is device-side; output overflow/status/stderr invalidate the command.
  (ulimit -f 1024; exec timeout -s KILL 3 "$@") > "$work/$label.out" 2> "$work/$label.err" || return 1
  [ ! -s "$work/$label.err" ] && [ "$(wc -c < "$work/$label.out")" -le 524288 ]
}
config() {
  typeset dir key
  dir=$1
  mkdir "$work/$dir" || return 1
  for key in ro.iorapd.enable persist.traced.enable ro.config.low_ram \
      iorapd.readahead.enable iorapd.perfetto.buffer_size \
      iorapd.perfetto.trace_duration_ms iorapd.perfetto.timeout \
      iorapd.perfetto.max_traces iorapd.maintenance.min_traces \
      iorapd.blacklist_packages iorapd.root.dir iorapd.db.location \
      persist.device_config.attempted_boot_count device_config.reset_performed; do
    getprop "$key" > "$work/$dir/$key" || return 1
  done
  for key in iorap_perfetto_enable iorap_readahead_enable iorap_blacklisted_packages; do
    run "$dir/server-$key" cmd device_config get runtime_native_boot "$key" || return 1
  done
}
same_config() {
  typeset left right original
  left=$1; right=$2
  for original in "$work/$left/"*; do
    [ -f "$original" ] || return 1
    cmp -s "$original" "$work/$right/${original##*/}" || return 1
  done
}
effective() {
  # Exact complete native refresh response, no duplicate/unknown lines accepted.
  # The blacklist is NOT printed by native code; raw inputs are captured separately.
  awk '
    NR==1 { if ($0!="iorapd.perfetto.enable = true" && $0!="iorapd.perfetto.enable = false") exit 1 }
    NR==2 { if ($0!="iorapd.readahead.enable = true" && $0!="iorapd.readahead.enable = false") exit 1 }
    NR==3 { if ($0 !~ /^iorapd.maintenance.min_traces = [0-9]+$/) exit 1 }
    NR==4 { if ($0!="System properties refreshed.") exit 1 }
    END { if (NR!=4) exit 1 }
  ' "$1"
}
quiet() {
  typeset label
  label=$1
  guard || return 1
  run "$label-dump" dumpsys -t 2 iorapd || return 1
  # The try-lock failure is not an idle receipt. Require the exact empty list.
  awk '
    /possible deadlock/ { bad=1 }
    /^Perfetto consumer state:$/ { sections++ }
    /^  In-flight handles:$/ { getline; if ($0=="    (None)") empty++; else bad=1 }
    END { if (bad || sections!=1 || empty!=1) exit 1 }
  ' "$work/$label-dump.out" || return 1
  run "$label-job" cmd jobscheduler get-job-state android "$job_id" || return 1
  # Unknown/missing/active/pending/ready is rejected, never cancelled or forced.
  [ "$(cat "$work/$label-job.out")" = waiting ] || return 1
  run "$label-power" dumpsys -t 2 power || return 1
  grep -q '^  mWakefulness=Awake$' "$work/$label-power.out" || return 1
  run "$label-idle" dumpsys -t 2 deviceidle || return 1
  grep -q 'mState=ACTIVE' "$work/$label-idle.out" || return 1
  run "$label-jobs-log" logcat -d -t 500 -b main -b system -v brief -s IorapForwardingService:D '*:S' || return 1
  # Logs are retained evidence, not an idle gate. Current native counters and
  # scheduler waiting do NOT exclude orphan native maintenance. This short
  # control-API pilot is not a benchmark or a full-quiescence validation.
  guard
}
helper_alive() {
  [ -n "$worker_pid" ] && [ "$(ticks "$worker_pid" 2>/dev/null)" = "$worker_start" ]
}
validate_helper() {
  typeset candidate_pid candidate_start raw tail actual expected
  candidate_pid=$1; candidate_start=$2
  case "$candidate_pid:$candidate_start" in *[!0-9:]*|:*|*:) return 1;; esac
  raw=$(cat "/proc/$candidate_pid/stat" 2>/dev/null) || return 1
  tail=${raw##*) }; set -- $tail
  [ "$#" -ge 20 ] && [ "$1" != Z ] && [ "${20}" = "$candidate_start" ] &&
    [ "$3" = "$candidate_pid" ] && [ "$4" = "$candidate_pid" ] || return 1
  actual=$(tr '\000' '\n' < "/proc/$candidate_pid/cmdline") || return 1
  expected=$(printf '%s\n%s' "$helper_shell" "$stage/step.sh")
  [ "$actual" = "$expected" ]
}
bind_helper() {
  typeset candidate_nonce candidate_pid candidate_start extra
  read -r candidate_nonce candidate_pid candidate_start extra < "$work/helper-ready.txt" || return 1
  [ "$candidate_nonce" = "$nonce" ] && [ -z "$extra" ] && guard || return 1
  validate_helper "$candidate_pid" "$candidate_start" || return 1
  # Only now publish signal authority; an invalid receipt never binds a PID.
  worker_pid=$candidate_pid
  worker_start=$candidate_start
  printf '%s %s\n' "$worker_pid" "$worker_start" > "$work/helper-identity.txt"
}
helper_running() {
  typeset raw tail
  helper_alive || return 1
  raw=$(cat "/proc/$worker_pid/stat" 2>/dev/null) || return 1
  tail=${raw##*) }; set -- $tail
  [ "$1" != Z ]
}
stop_helper() {
  typeset raw tail n
  # This is an independently created session/process group, never an ADB group.
  # Validate leader lifetime AND group/session before signalling any group.
  if ! helper_alive; then return 0; fi
  raw=$(cat "/proc/$worker_pid/stat" 2>/dev/null) || { helper_alive && return 1; return 0; }
  tail=${raw##*) }; set -- $tail
  [ "$3" = "$worker_pid" ] && [ "$4" = "$worker_pid" ] || return 1
  kill -STOP -"$worker_pid" 2>/dev/null || { helper_alive && return 1; return 0; }
  kill -KILL -"$worker_pid" 2>/dev/null || { helper_alive && return 1; return 0; }
  n=0
  while helper_alive; do
    raw=$(cat "/proc/$worker_pid/stat" 2>/dev/null) || break
    tail=${raw##*) }; set -- $tail
    [ "$1" = Z ] && break
    n=$((n+1)); [ "$n" -le 10 ] || return 1
    sleep 0.1
  done
}
restore() {
  typeset original current stopped
  # Every exit after arming routes through here, including timeout/host loss.
  trap - EXIT HUP INT TERM
  stop_helper > "$work/helper-stop.out" 2> "$work/helper-stop.err" && stopped=yes || stopped=no
  owned || { printf 'identity_or_owner_lost; manual_review_required\n' > "$work/restoration.txt"; return 1; }
  original=$(cat "$work/original-property.out") || return 1
  current=$(getprop "$record_key") || return 1
  if [ ! -f "$work/refresh-intent.txt" ]; then
    # No helper got as far as a control operation. Never introduce one in cleanup.
    [ "$stopped" = yes ] && [ "$current" = "$original" ] && guard || return 1
    printf 'no_control_operation_started\n' > "$work/restoration.txt"
    now > "$work/restored-uptime.txt"
    return 0
  fi
  if [ "$current" != false ] && [ "$current" != "$original" ]; then
    printf 'third_party_value_conflict; manual_review_required\n' > "$work/restoration.txt"; return 1
  fi
  # Empty stays an explicit empty argument. No property deletion/resetprop is used.
  run restore-property setprop "$record_key" "$original" || return 1
  getprop "$record_key" > "$work/restored-property.out" || return 1
  cmp -s "$work/original-property.out" "$work/restored-property.out" || return 1
  guard || { printf 'property_restored_native_identity_changed\n' > "$work/restoration.txt"; return 1; }
  run restore-refresh dumpsys -t 2 iorapd --refresh-properties || return 1
  effective "$work/restore-refresh.out" || return 1
  now > "$work/restored-uptime.txt" || return 1
  [ "$(cat "$work/restored-uptime.txt")" -le "$(cat "$work/restoration-deadline-uptime.txt")" ] || return 1
  config restored-config || return 1
  same_config original-config restored-config || return 1
  guard || return 1
  [ "$stopped" = yes ] || return 1
  if [ ! -f "$work/baseline-refresh.out" ]; then
    printf 'property_restored_original_effective_receipt_unavailable\n' > "$work/restoration.txt"
    return 1
  fi
  effective "$work/baseline-refresh.out" || return 1
  cmp -s "$work/baseline-refresh.out" "$work/restore-refresh.out" || return 1
  printf 'observable_property_and_refreshed_baseline_restored\n' > "$work/restoration.txt"
  quiet restored || return 1
  now > "$work/audit-complete-uptime.txt"
}
