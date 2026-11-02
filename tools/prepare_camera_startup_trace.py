"""Prepare logging-only startRecord instrumentation from the pinned fixed30 tree."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

SOURCE = 'e3caa05f9d1079b0d1eb6e439f482d8bba91f58585edead24e73e49e3d83d6b9'
FILE = 'smali/com/tcl/camera/module/video/AutoVideoModule.smali'


def prepare(decoded, output):
    raw = (decoded / FILE).read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE:
        raise ValueError('Expected reviewed fixed30 module')
    if output.exists():
        raise ValueError('Output must be fresh')
    text = raw.decode().replace('\r\n', '\n')
    start = text.index('.method public startRecord()V')
    end = text.index('.end method', start)
    original = text[start:end]
    method = original.replace('    .locals 4', '    .locals 6', 1)
    # New scratch registers never alias v0..v3. p0 remains a symbolic parameter.
    if 'v4' in original or 'v5' in original:
        raise ValueError('Unexpected explicit parameter-register alias')
    blocks = []
    def marker(name):
        block = ('    const-string v4, "KaiCameraStartup"\n'
                 f'    const-string v5, "{name}"\n'
                 '    invoke-static {v4, v5}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I\n')
        blocks.append(block)
        return block
    calls = [
        ('repeat', '    invoke-interface {v1, v2, v3}, Lcom/tcl/camera/device/camera/ICameraCaptureSession;->setRepeatingRequest(Landroid/hardware/camera2/CaptureRequest;Lcom/tcl/camera/device/camera/ICameraCaptureSession$CaptureCallback;)V\n'),
        ('recorder', '    invoke-virtual {v1}, Landroid/media/MediaRecorder;->start()V\n'),
    ]
    for name, call in calls:
        if method.count(call) != 1:
            raise ValueError('Unexpected call anchor: ' + name)
        method = method.replace(call, marker(name + '_enter') + call + marker(name + '_return'))
    restored = method
    for block in blocks:
        restored = restored.replace(block, '')
    if restored.replace('    .locals 6', '    .locals 4', 1) != original:
        raise ValueError('Non-instrumentation change')
    shutil.copytree(decoded, output, ignore=shutil.ignore_patterns('build', 'dist'))
    (output / FILE).write_text(text[:start] + method + text[end:], encoding='utf-8', newline='\n')
    return {'source_sha256': SOURCE,
            'candidate_module_sha256': hashlib.sha256((output / FILE).read_bytes()).hexdigest(),
            'changed_method': 'AutoVideoModule.startRecord()V',
            'markers': ['repeat_enter', 'repeat_return', 'recorder_enter', 'recorder_return'],
            'original_instructions_preserved': True, 'installed': False,
            'limitation': 'Logging has overhead. No change to call order, AE range or recording policy.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--decoded', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.decoded, args.output), indent=2))
