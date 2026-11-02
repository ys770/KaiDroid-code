#!/system/bin/sh
set -eu
. "@@STAGE@@/common.sh"
helper_start=$(ticks "$$")
guard
validate_helper "$$" "$helper_start"
printf '%s %s %s\n' "$nonce" "$$" "$helper_start" > "$work/helper-ready.tmp"
mv "$work/helper-ready.tmp" "$work/helper-ready.txt"
n=0
while [ ! -f "$work/helper-go.txt" ]; do
  n=$((n+1)); [ "$n" -le 40 ]; sleep 0.1
done
[ "$(cat "$work/helper-go.txt")" = "$(printf '%s %s %s' "$nonce" "$$" "$helper_start")" ]
guard
# Deliberate baseline conditioning: ordinary dump cannot expose existing flags.
printf 'intent\n' > "$work/refresh-intent.txt"
run baseline-refresh dumpsys -t 2 iorapd --refresh-properties
effective "$work/baseline-refresh.out"
grep -qx 'iorapd.perfetto.enable = true' "$work/baseline-refresh.out"
quiet baseline
config baseline-config
same_config original-config baseline-config
getprop "$record_key" > "$work/baseline-property.out"
cmp -s "$work/original-property.out" "$work/baseline-property.out"
guard
run off-property setprop "$record_key" false
getprop "$record_key" > "$work/off-property-readback.out"
[ "$(cat "$work/off-property-readback.out")" = false ]
run off-refresh dumpsys -t 2 iorapd --refresh-properties
effective "$work/off-refresh.out"
grep -qx 'iorapd.perfetto.enable = false' "$work/off-refresh.out"
tail -n +2 "$work/baseline-refresh.out" > "$work/baseline-unchanged-flags.out"
tail -n +2 "$work/off-refresh.out" > "$work/off-unchanged-flags.out"
cmp -s "$work/baseline-unchanged-flags.out" "$work/off-unchanged-flags.out"
config off-config
same_config original-config off-config
quiet off
guard
printf 'pass\n' > "$work/helper-done.txt"
