"""Freeze battery presentation with installed SystemUI fixes; local preparation only."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile

BATTERY = '9eed70d9c64605767074b9022b6c14ee09db614632bb6812299fdb6607221c07'
FRAMEWORK = '3d056c413cb31381e71b63f77544c519efda90367ced4025c4585c183fe423e5'
SYSTEMUI = '5baff8afce1704ce8ed72301ebe7422ccf41d6ef8eaf540aa25556136a15d708'
RETAINED = {
    'AccessPointControllerImpl.java': ('src/com/android/systemui/statusbar/policy/AccessPointControllerImpl.java',
                                    'fe9b1542b7013a082db6070927c69b5097eb4a600277b1932d2219dcd28bdea5'),
    'BubbleDataRepository.kt': ('src/com/android/systemui/bubbles/BubbleDataRepository.kt',
                              '1dabead7099acf7536275df2a81b7f753cd3f303da95195b9934e904e5acd51c'),
    'SystemUI.proguard.flags': ('proguard.flags',
                              '457e4098fa25ee5bb88b51eb5f7670994fc30efe08473acd36a609439c5c68e5'),
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(files):
    return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def checked_files(contract, key, digest, overlay):
    spec = json.loads(contract.read_text())
    files = spec['files']
    if spec[key] != digest or canonical(files) != digest:
        raise ValueError('Wrong frozen contract: '+str(contract))
    for name, expected in files.items():
        if name.startswith('/') or '\\' in name or '..' in Path(name).parts:
            raise ValueError('Invalid overlay path')
        path = overlay/name
        if path.is_symlink() or sha(path) != expected:
            raise ValueError('Changed overlay: '+name)
    actual = {p.relative_to(overlay).as_posix() for p in overlay.rglob('*') if p.is_file()}
    if actual != set(files):
        raise ValueError('Unexpected overlay files')
    return files


def prepare(battery_overlay, battery_contract, retained, framework_overlay, framework_contract, output):
    if output.exists():
        raise FileExistsError(output)
    battery = checked_files(battery_contract, 'overlay_sha256', BATTERY, battery_overlay)
    framework = checked_files(framework_contract, 'canonical_sha256', FRAMEWORK, framework_overlay)
    if len(battery) != 29 or len(framework) != 3:
        raise ValueError('Unexpected source closure')
    systemui = dict(battery)
    for name, (target, expected) in RETAINED.items():
        if target in systemui or sha(retained/name) != expected:
            raise ValueError('Wrong retained startup fix: '+name)
        systemui[target] = expected
    output.mkdir(parents=True)
    for files, source, prefix in ((battery, battery_overlay, 'systemui-overlay'),
                                  (framework, framework_overlay, 'framework-overlay')):
        for name in files:
            target = output/prefix/name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source/name, target)
    for name, (target, _) in RETAINED.items():
        path = output/'systemui-overlay'/target
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(retained/name, path)
    all_files = {'systemui-overlay/'+n: d for n, d in systemui.items()}
    all_files.update({'framework-overlay/'+n: d for n, d in framework.items()})
    archive = output/'overlays.tar.gz'
    with archive.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as zipped, \
            tarfile.open(fileobj=zipped, mode='w|') as tar:
        for name in sorted(all_files):
            data = (output/name).read_bytes()
            if hashlib.sha256(data).hexdigest() != all_files[name]:
                raise ValueError('Copied overlay changed')
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            tar.addfile(info, io.BytesIO(data))
    report = dict(systemui_files=systemui, framework_files=framework,
                  systemui_canonical_sha256=canonical(systemui), framework_canonical_sha256=FRAMEWORK,
                  all_files_canonical_sha256=canonical(all_files), archive_sha256=sha(archive),
                  installed_systemui_baseline_sha256=SYSTEMUI,
                  retained_startup_fixes=['lazy Wi-Fi access controller', 'synchronized lazy bubble scopes',
                                          'NetworkController erased callback bridges retained by optimizer'],
                  battery_overlay_sha256=BATTERY, source_files=len(all_files),
                  required_build_scope='New isolated output with all35 files present in correct source roots; regenerate Java/resource inputs. Preserve chooser45 framework dependency. Export signed SystemUI APK only.',
                  platform_compiled=False, staged_on_build_host=False, installed=False,
                  scope='Reproducible source closure only; not SystemUI ABI, full app UI, runtime or complete battery-state parity proof')
    (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(dict(source_files=len(all_files), archive_sha256=sha(archive), platform_compiled=False)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('battery-overlay', 'battery-contract', 'retained', 'framework-overlay', 'framework-contract', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    a = parser.parse_args()
    prepare(a.battery_overlay, a.battery_contract, a.retained, a.framework_overlay, a.framework_contract, a.output)
