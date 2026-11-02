"""Exact hardware-reported image60 boot/core-process guard, without lease acquisition."""
from trial_tcl_media_navigation_image59 import require, SERIAL

BOOT = '00000000-0000-0000-0000-000000000007'
EXPECTED = [SERIAL, '60', BOOT, '0', 'Enforcing', '1', '1166', '1339', '538']


class Image60Guard:
    def identity(self):
        require(self.a.boot == BOOT, 'Only reviewed image60 boot is bound')
        actual = self.shell('identity60',
                            'getprop ro.serialno; getprop ro.kaidroid.image; '
                            'cat /proc/sys/kernel/random/boot_id; id -u; getenforce; '
                            'getprop sys.boot_completed; pidof system_server; '
                            'pidof com.android.systemui; pidof surfaceflinger').splitlines()
        require(actual == EXPECTED, 'Image60 identity/boot/core process changed; no input')
