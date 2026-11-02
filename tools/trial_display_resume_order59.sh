#!/system/bin/sh
set -eu
[ "$(getprop ro.kaidroid.image)" = 59 ]
[ "$(cat /proc/sys/kernel/random/boot_id)" = 00000000-0000-0000-0000-000000000002 ]
[ "$(pidof system_server)" = 1155 ]
[ "$(pidof com.android.systemui)" = 1367 ]
D=/sys/kernel/debug/dynamic_debug/control
P=/data/local/tmp/kaidroid-display-order02
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
nohup sh -c 'sleep 15; echo "func mdss_spi_display_kickoff -p" > /sys/kernel/debug/dynamic_debug/control; echo "func mdss_spi_panel_on -p" > /sys/kernel/debug/dynamic_debug/control; echo "func mdss_fb_set_backlight -p" > /sys/kernel/debug/dynamic_debug/control; input keyevent 224; echo deadline-done > /data/local/tmp/kaidroid-display-order02/deadline' </dev/null >"$P/watchdog.log" 2>&1 &
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
pidof system_server com.android.systemui > "$P/core-after"
echo completed
