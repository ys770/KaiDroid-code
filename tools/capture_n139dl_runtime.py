"""Passive, serial/build-bound N139DL runtime evidence; no reboot or writes.

Outputs contain private identifiers and belong in ignored artifacts/. A root
ADB shell must already exist; this tool does not obtain or restart root.
Individual unavailable reads are recorded, not silently treated as evidence.
"""
import argparse
import hashlib
import json
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path


READS = {
    'properties.txt': 'getprop',
    'cmdline.txt': 'cat /proc/cmdline',
    'memory.txt': 'cat /proc/meminfo',
    'input-devices.txt': 'cat /proc/bus/input/devices',
    'mounts.txt': 'cat /proc/mounts',
    'processes.txt': 'ps -A',
    'sound-cards.txt': 'cat /proc/asound/cards',
    'sound-pcm.txt': 'cat /proc/asound/pcm',
    'soc.txt': 'for f in /sys/devices/soc0/{machine,family,soc_id,revision}; do echo "$f"; cat "$f"; done',
    'display.txt': 'for f in /sys/class/graphics/fb0/{name,modes,virtual_size,bits_per_pixel}; do echo "$f"; cat "$f"; done',
    'input-sysfs.txt': 'for d in /sys/class/input/input*; do echo "$d"; cat "$d/name" "$d/phys" "$d/capabilities/key" "$d/capabilities/sw"; done',
    'dt-model.bin': 'cat /sys/firmware/devicetree/base/model',
    'dt-compatible.bin': 'cat /sys/firmware/devicetree/base/compatible',
    'active-fdt.dtb': 'cat /sys/firmware/fdt',
    'device-tree.tar': 'tar -C /sys/firmware/devicetree/base -cf - .',
    'hal-services.txt': 'lshal',
}

# Fixed, read-only identification commands. No mixer IOCTLs, log clearing,
# service restarts or firmware/calibration reads are part of this profile.
AUDIO_READS = {
    'audio-selection-identity.txt': 'getprop ro.boot.hardware.revision; sha256sum /vendor/lib/hw/audio.primary.msm8937.so /system/lib/vndk-29/libaudioroute.so /vendor/etc/mixer_paths_mtp.xml',
    'sound-cards.txt': 'cat /proc/asound/cards',
    'sound-pcm.txt': 'cat /proc/asound/pcm',
    'audio-processes.txt': 'ps -A | grep -E "audioserver|android.hardware.audio"',
    'audio-maps.txt': 'for name in audioserver android.hardware.audio@2.0-service; do for p in $(pidof "$name"); do echo "PROCESS $name PID $p"; readlink /proc/$p/exe; cat /proc/$p/maps; done; done',
    'sound-links.txt': 'for d in /sys/class/sound/card*; do test -e "$d" || continue; echo "CARD $d"; readlink -f "$d/device"; readlink -f "$d/device/driver"; done',
    'codec-driver-links.txt': 'for d in /sys/bus/platform/devices/*; do case "$d" in *sound*|*codec*|*wcd*) echo "DEVICE $d"; if test -L "$d/driver"; then readlink -f "$d/driver"; else echo NO_DRIVER_LINK; fi;; esac; done',
    'audio-modules.txt': 'cat /proc/modules',
    'hal-services.txt': 'lshal',
}


WIRELESS_READS = {
    'modules.txt': 'cat /proc/modules',
    'sdio.txt': 'for d in /sys/bus/sdio/devices/*; do test -e "$d" || continue; echo "DEVICE $d"; readlink -f "$d"; for f in vendor device class modalias; do echo "$f"; cat "$d/$f"; done; if test -L "$d/driver"; then readlink -f "$d/driver"; else echo NO_DRIVER_LINK; fi; done',
    'wlan-links.txt': 'for d in /sys/class/net/wlan*; do test -e "$d" || continue; echo "INTERFACE $d"; readlink -f "$d/device"; if test -L "$d/device/driver"; then readlink -f "$d/device/driver"; else echo NO_DRIVER_LINK; fi; cat "$d/operstate"; done',
    'wireless-processes.txt': 'ps -A | grep -E "bluetooth|wpa_supplicant|hostapd|hardware.wifi"',
    'bluetooth-transport.txt': 'for d in /sys/class/tty/ttyHS0 /sys/class/rfkill/rfkill*; do test -e "$d" || continue; echo "DEVICE $d"; readlink -f "$d/device"; if test -L "$d/device/driver"; then readlink -f "$d/device/driver"; fi; for f in name type state; do if test -f "$d/$f"; then echo "$f"; cat "$d/$f"; fi; done; done; ls -l /dev/ttyHS0',
    'hal-services.txt': 'lshal',
}


BOOT_PARTITIONS = ('aboot', 'boot', 'recovery', 'vbmeta', 'dtbo', 'devinfo')
BOOT_HASH_COMMAND = 'sha256sum ' + ' '.join(
    '/dev/block/bootdevice/by-name/' + name for name in BOOT_PARTITIONS)
BOOT_READS = {
    'hashes-before.txt': BOOT_HASH_COMMAND,
    'sizes.txt': 'for n in ' + ' '.join(BOOT_PARTITIONS) + '; do echo "$n"; blockdev --getsize64 /dev/block/bootdevice/by-name/$n; done',
    **{name + '.img': 'cat /dev/block/bootdevice/by-name/' + name for name in BOOT_PARTITIONS},
    'hashes-after.txt': BOOT_HASH_COMMAND,
    'boot-properties.txt': 'getprop ro.boot.flash.locked; getprop ro.boot.verifiedbootstate; getprop ro.boot.vbmeta.device_state; getprop ro.boot.veritymode',
}

BOOT_STATE_READS = {
    'cmdline.txt': 'cat /proc/cmdline',
    'mounts.txt': 'cat /proc/mounts',
    'system-identity.txt': 'readlink -f /dev/block/bootdevice/by-name/system; cat /sys/class/block/mmcblk0p16/uevent',
    'boot-properties.txt': BOOT_READS['boot-properties.txt'],
}

POLICY_READS = {
    'plat_sepolicy.cil': 'cat /system/etc/selinux/plat_sepolicy.cil',
    '29.0.cil': 'cat /system/etc/selinux/mapping/29.0.cil',
    'plat_pub_versioned.cil': 'cat /vendor/etc/selinux/plat_pub_versioned.cil',
    'vendor_sepolicy.cil': 'cat /vendor/etc/selinux/vendor_sepolicy.cil',
    'policy-hashes.txt': 'sha256sum /system/etc/selinux/plat_sepolicy.cil /system/etc/selinux/mapping/29.0.cil /vendor/etc/selinux/plat_pub_versioned.cil /vendor/etc/selinux/vendor_sepolicy.cil',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', required=True)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--fingerprint', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--profile', choices=('baseline', 'audio', 'wireless', 'boot-chain', 'boot-state', 'policy'), default='baseline')
    parser.add_argument('--read-timeout', type=float, default=30,
                        help='Per-read timeout in seconds (1..600); increase for large partition hashes')
    args = parser.parse_args()
    if not 1 <= args.read_timeout <= 600:
        parser.error('--read-timeout must be between 1 and 600 seconds')
    if args.output.exists():
        raise ValueError('Output already exists')
    base = [args.adb, '-s', args.serial, 'exec-out']

    def read(command):
        # Legacy adbd exec-out may report transport success even when cat fails.
        # Append a unique shell-status trailer and strip it from binary evidence.
        marker = '\nKAIDROID_EXIT_' + uuid.uuid4().hex + ':'
        wrapped = '( ' + command + ' ); kaidroid_read_status=$?; printf "\\n' + marker[1:] + '%s\\n" "$kaidroid_read_status"'
        proc = subprocess.run(base + [wrapped], capture_output=True, timeout=args.read_timeout)
        if proc.returncode:
            return proc
        payload, separator, status = proc.stdout.rpartition(marker.encode())
        if not separator or not status.endswith(b'\n') or not status[:-1].isdigit():
            raise ValueError('Missing or malformed remote exit-status trailer')
        code = int(status[:-1])
        if not 0 <= code <= 255:
            raise ValueError('Invalid remote exit status')
        return subprocess.CompletedProcess(base + [command], code, payload, proc.stderr)

    def identity():
        result = {}
        for key, command in {
            'fingerprint': 'getprop ro.build.fingerprint',
            'model': 'getprop ro.product.model',
            'boot_id': 'cat /proc/sys/kernel/random/boot_id',
            'uid': 'id -u',
        }.items():
            proc = read(command)
            proc.check_returncode()
            result[key] = proc.stdout.decode().strip()
        if (result['fingerprint'] != args.fingerprint or result['model'] != 'N139DL'
                or result['uid'] != '0' or not result['boot_id']):
            raise ValueError('Identity/root gate failed')
        return result

    before = identity()
    probe = read(r"printf 'A\nB\r\nC\000D'")
    if probe.returncode or probe.stdout != b'A\nB\r\nC\0D':
        raise ValueError('Binary transport gate failed')
    args.output.mkdir(parents=True)
    manifest = {'serial': args.serial, 'before': before, 'profile': args.profile,
                'started_utc': datetime.now(timezone.utc).isoformat(), 'reads': []}

    def save():
        (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')

    save()
    profiles = {'baseline': READS, 'audio': AUDIO_READS, 'wireless': WIRELESS_READS,
                'boot-chain': BOOT_READS, 'boot-state': BOOT_STATE_READS, 'policy': POLICY_READS}
    for name, command in profiles[args.profile].items():
        entry = {'file': name, 'command': command}
        try:
            proc = read(command)
            (args.output / name).write_bytes(proc.stdout)
            (args.output / (name + '.stderr')).write_bytes(proc.stderr)
            entry.update(returncode=proc.returncode, bytes=len(proc.stdout),
                         sha256=hashlib.sha256(proc.stdout).hexdigest(),
                         stderr_bytes=len(proc.stderr))
        except subprocess.TimeoutExpired:
            entry['error'] = 'timeout; remote termination not established'
            manifest['reads'].append(entry)
            save()
            raise  # Do not continue or restart an ambiguously live command.
        manifest['reads'].append(entry)
        save()
    manifest['after'] = identity()
    manifest['same_identity_and_boot'] = manifest['after'] == before
    manifest['finished_utc'] = datetime.now(timezone.utc).isoformat()
    save()
    if not manifest['same_identity_and_boot']:
        raise ValueError('Postflight identity/boot changed')
    print(json.dumps({'reads': len(manifest['reads']), 'same_identity_and_boot': True,
                      'failed_reads': [r['file'] for r in manifest['reads'] if r['returncode']]}))


if __name__ == '__main__':
    main()
