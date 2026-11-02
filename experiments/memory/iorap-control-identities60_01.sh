#!/system/bin/sh
# Read-only identity probe. Execute from a parent-owned pushed file, never sh -s.
set -eu
check() {
  [ "$(getprop ro.serialno)" = DEVICE_SERIAL_REQUIRED ] &&
  [ "$(getprop ro.kaidroid.image)" = 60 ] &&
  [ "$(cat /proc/sys/kernel/random/boot_id)" = 00000000-0000-0000-0000-000000000007 ] &&
  [ "$(id -u)" = 0 ] && [ "$(getenforce)" = Enforcing ]
}
capture() {
  typeset process pid raw tail start sep expected
  sep=''
  for process in surfaceflinger system_server com.android.systemui iorapd; do
    pid=$(pidof "$process") || return 1
    case "$pid" in ''|*[!0-9]*) return 1;; esac
    case "$process" in
      surfaceflinger) expected=538;; system_server) expected=1166;;
      com.android.systemui) expected=1339;; iorapd) expected=$pid;;
    esac
    [ "$pid" = "$expected" ] || return 1
    raw=$(cat "/proc/$pid/stat") || return 1
    tail=${raw##*) }; set -- $tail
    [ "$#" -ge 20 ] || return 1
    start=${20}
    case "$start" in ''|*[!0-9]*) return 1;; esac
    printf '%s"%s":{"pid":%s,"start_ticks":%s}' "$sep" "$process" "$pid" "$start"
    sep=,
  done
}
check
first=$(capture)
second=$(capture)
[ "$first" = "$second" ]
check
printf '{"image":60,"boot":"00000000-0000-0000-0000-000000000007","serial":"DEVICE_SERIAL_REQUIRED","processes":{%s}}\n' "$first"
