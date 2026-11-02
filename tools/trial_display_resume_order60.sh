#!/system/bin/sh
set -eu
# Arguments are the freshly verified image60 boot and core process IDs.
boot=$1
sf=$2
ss=$3
ui=$4
[ "$(getprop ro.serialno)" = DEVICE_SERIAL_REQUIRED ]
[ "$(getprop ro.kaidroid.image)" = 60 ]
[ "$(getprop ro.kaidroid.frame_backlight)" = true ]
[ "$(getenforce)" = Enforcing ]
[ "$(pidof surfaceflinger)" = "$sf" ]
[ "$(cat /proc/sys/kernel/random/boot_id)" = "$boot" ]
[ "$(pidof system_server)" = "$ss" ]
[ "$(pidof com.android.systemui)" = "$ui" ]
D=/sys/kernel/debug/dynamic_debug/control
P=/data/local/tmp/kaidroid-display-order60-01
mkdir "$P"
grep -E 'mdss_spi_display_kickoff |mdss_spi_panel_on |mdss_fb_set_backlight ' "$D" > "$P/before"
[ "$(wc -l < "$P/before")" = 6 ]
[ "$(grep -c ' =_ ' "$P/before")" = 6 ]
restore() {
 echo 'func mdss_spi_display_kickoff -p' > "$D"
 echo 'func mdss_spi_panel_on -p' > "$D"
 echo 'func mdss_fb_set_backlight -p' > "$D"
}
trap restore EXIT
# Independent device-side deadline restores exactly the initially disabled sites.
nohup sh -c 'sleep 15; echo "func mdss_spi_display_kickoff -p" > /sys/kernel/debug/dynamic_debug/control; echo "func mdss_spi_panel_on -p" > /sys/kernel/debug/dynamic_debug/control; echo "func mdss_fb_set_backlight -p" > /sys/kernel/debug/dynamic_debug/control; input keyevent 224; echo deadline-done > /data/local/tmp/kaidroid-display-order60-01/deadline' </dev/null >"$P/watchdog.log" 2>&1 &
echo 'func mdss_spi_display_kickoff +p' > "$D"
echo 'func mdss_spi_panel_on +p' > "$D"
echo 'func mdss_fb_set_backlight +p' > "$D"
cat /proc/uptime > "$P/start"
input keyevent 223
sleep 2
input keyevent 224
sleep 3
restore
dmesg > "$P/kernel"
grep -E 'mdss_spi_display_kickoff |mdss_spi_panel_on |mdss_fb_set_backlight ' "$D" > "$P/after"
cmp "$P/before" "$P/after"
pidof surfaceflinger system_server com.android.systemui > "$P/core-after"
[ "$(pidof surfaceflinger)" = "$sf" ]
[ "$(pidof system_server)" = "$ss" ]
[ "$(pidof com.android.systemui)" = "$ui" ]
[ "$(cat /proc/sys/kernel/random/boot_id)" = "$boot" ]
logcat -d -s 'SurfaceFlinger:I' > "$P/surfaceflinger-log"
echo completed
