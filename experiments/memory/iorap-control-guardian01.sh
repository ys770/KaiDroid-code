#!/system/bin/sh
set -eu
. "@@STAGE@@/common.sh"
mkdir "$work"
chmod 700 "$work"
work_inode=$(stat -c '%d:%i' "$work")
printf '%s\n' "$nonce" > "$work/owner"
printf '%s\n' "$work_inode" > "$work/owner-inode.txt"
printf 'not_armed\n' > "$work/restoration.txt"
guard
for tool in timeout setsid awk cmp stat logcat cmd dumpsys sha256sum; do command -v "$tool" >/dev/null; done
# Check timeout/setsid support before any refresh/property operation.
run timeout-check sh -c 'exit 0'
[ "$(sha256sum /system/bin/iorapd | awk '{print $1}')" = fd3f4b8dfeeb2f78ce1b00fa87c22d5c9f0e9196cc97f2860d7b1986e85ae542 ]
getprop "$record_key" > "$work/original-property.out"
case "$(cat "$work/original-property.out")" in ''|true|false) ;; *) exit 71;; esac
config original-config
quiet prestate
guard
printf '%s %s\n' "$$" "$(ticks "$$")" > "$work/guardian-identity.txt"
now > "$work/start-uptime.txt"
deadline=$(( $(now) + 25 ))
printf '%s\n' "$deadline" > "$work/helper-deadline-uptime.txt"
printf '%s\n' "$((deadline+10))" > "$work/restoration-deadline-uptime.txt"
printf 'armed_restore_pending\n' > "$work/restoration.txt"
finish() {
  rc=$?
  if restore; then restored=yes; else restored=no; fi
  printf 'supervisor_status=%s\nrestoration_verified=%s\n' "$rc" "$restored" > "$work/finished.txt"
  [ "$rc" = 0 ] && [ "$restored" = yes ]
}
trap finish EXIT
trap 'exit 92' HUP INT TERM
# The guardian remains detached from the host and is the sole restoration writer.
setsid sh "$stage/step.sh" </dev/null > "$work/step.log" 2>&1 &
launcher_pid=$!
launcher_start=$(ticks "$launcher_pid" 2>/dev/null || printf absent)
printf '%s %s\n' "$launcher_pid" "$launcher_start" > "$work/launcher-identity.txt"
# Wait only for the helper's independently created session receipt; no mutation yet.
# Android setsid can fork: launcher exit is not evidence of helper exit.
n=0
while [ ! -f "$work/helper-ready.txt" ]; do
  [ "$(now)" -lt "$deadline" ] || exit 73
  n=$((n+1)); [ "$n" -le 30 ] || exit 75
  sleep 0.1
done
bind_helper
printf '%s %s %s\n' "$nonce" "$worker_pid" "$worker_start" > "$work/helper-go.tmp"
mv "$work/helper-go.tmp" "$work/helper-go.txt"
while [ ! -f "$work/helper-done.txt" ]; do
  if [ "$(now)" -ge "$deadline" ]; then printf 'deadline\n' > "$work/reason.txt"; exit 76; fi
  helper_running || {
    # Completion can race a procfs read; a vanished leader alone is not failure.
    [ -f "$work/helper-done.txt" ] || { printf 'helper_lost\n' > "$work/reason.txt"; exit 77; }
  }
  sleep 0.2
done
[ "$(cat "$work/helper-done.txt")" = pass ] || exit 78
# No OFF holding window is needed. Restore as soon as OFF response is retained.
printf 'control_response_captured\n' > "$work/reason.txt"
