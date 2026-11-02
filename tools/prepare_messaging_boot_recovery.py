"""Build a pinned, boot-only Messaging lifecycle adapter; never install it."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import zipfile
from compress_apk_dex import is_signature

APK_SHA = 'c6694b2340793d4f5bd4fab80aa0d5b81aa7f97a3dc370bd96ed675cb391a82b'
PIN = {
    'BootReceiver': 'dac0b274e1a5101de8a746fd28d2b5fe2dcfbded46c9cc4e5f47d0537f39c83c',
    'TransactionService': '2a164c375b9c6932a4ae3187cbd4834ef0d4c814db3c10db7f5df64227549530',
    'SmsReceiverService': 'e94800d49342484852c498380d4dc557c4336856356165eb13d3365ac26af029',
    'SmsReceiver': 'b0c4b783ba6347245df98a2102bf56bf4423507390ae0794273f9a6399cbdf90',
    'MmsJobService': '4a524f9f03897c01be0cb8d3fa79a963a368a792b795ca03a991ad0df5654000',
    'TransactionService$ServiceHandler': 'a009fb51b6c42d4786b900cf4534bf6cd8f72198c993ff6f2aae92d5bf21e087',
}
PREFIX = 'smali/com/android/mms/transaction/'
HELPER = 'Lcom/android/mms/transaction/KaiBootRecovery;'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Unexpected patch anchor: ' + old[:90])
    return text.replace(old, new)


def patch(name, text):
    if name == 'BootReceiver':
        # Keep notification refresh and original SMSC preference handling in place.
        begin = text.index('    .line 43\n')
        end = text.index('    .line 45\n', begin)
        text = text[:begin] + text[end:]
        begin = text.index('    .line 55\n')
        end = text.index('    :cond_1\n', begin)
        text = text[:begin] + ('    :cond_0\n    invoke-static {p1}, ' + HELPER +
            '->schedule(Landroid/content/Context;)V\n\n') + text[end:]
    elif name in ('TransactionService', 'SmsReceiverService'):
        begin = text.index('.method public onBind(Landroid/content/Intent;)Landroid/os/IBinder;')
        end = text.index('.end method', begin)
        text = text[:begin] + '''.method public onBind(Landroid/content/Intent;)Landroid/os/IBinder;
    .locals 0
    invoke-static {p0, p1}, HELPER->binder(Landroid/app/Service;Landroid/content/Intent;)Landroid/os/IBinder;
    move-result-object p0
    return-object p0
'''.replace('HELPER', HELPER) + text[end:]
        if name == 'TransactionService':
            text = once(text, '.source "TransactionService.java"',
                        '.source "TransactionService.java"\n.implements ' + HELPER[:-1] + '$MmsWorker;')
            anchor = '    .line 341\n    iget-object p2, p0, Lcom/android/mms/transaction/TransactionService;->mServiceHandler:'
            text = once(text, anchor, '    invoke-static {p0}, ' + HELPER +
                        '->mmsCommandQueued(Landroid/app/Service;)V\n\n' + anchor)
            pattern = r'invoke-virtual \{([^}]+)\}, Lcom/android/mms/transaction/TransactionService;->stopSelf\(I\)V'
            text, count = re.subn(pattern, r'invoke-static {\1}, ' + HELPER +
                                 '->stopMms(Landroid/app/Service;I)V', text)
            if count != 2:
                raise ValueError('Unexpected MMS completion sites')
            text += '''
.method public kaiBootIsIdle()Z
    .locals 2
    invoke-static {p0}, Lcom/android/mms/MmsConfig;->isSmsEnabled(Landroid/content/Context;)Z
    move-result v0
    if-nez v0, :kai_role_present
    const/4 v0, 0x1
    return v0
    :kai_role_present
    iget-object v0, p0, Lcom/android/mms/transaction/TransactionService;->mProcessing:Ljava/util/ArrayList;
    monitor-enter v0
    :kai_try_start
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z
    move-result v1
    if-eqz v1, :kai_idle_result
    iget-object v1, p0, Lcom/android/mms/transaction/TransactionService;->mPending:Ljava/util/ArrayList;
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z
    move-result v1
    :kai_idle_result
    :kai_try_end
    monitor-exit v0
    return v1
    :kai_catch
    move-exception v1
    monitor-exit v0
    throw v1
    .catchall {:kai_try_start .. :kai_try_end} :kai_catch
.end method
'''
    elif name == 'TransactionService$ServiceHandler':
        text = once(text,
            'invoke-virtual {p0, v0, p1}, Lcom/android/mms/transaction/TransactionService;->onNewIntent(Landroid/content/Intent;I)V',
            'invoke-static {p0, v0, p1}, ' + HELPER + '->dispatchMms(Landroid/app/Service;Landroid/content/Intent;I)V')
    elif name == 'SmsReceiver':
        anchor = '.method public static finishStartingService(Landroid/app/Service;I)V\n    .locals 2\n'
        text = once(text, anchor, anchor + '''
    invoke-static {p0, p1}, HELPER->finishSms(Landroid/app/Service;I)Z
    move-result v0
    if-eqz v0, :kai_normal_start
    return-void
    :kai_normal_start
'''.replace('HELPER', HELPER))
    elif name == 'MmsJobService':
        for method, action, result in [('onStartJob', 'start', 1), ('onStopJob', 'stop', 1)]:
            anchor = f'.method public {method}(Landroid/app/job/JobParameters;)Z\n    .locals '
            begin = text.index(anchor) + len(anchor)
            end = text.index('\n', begin)
            text = text[:end] + f'''

    invoke-static {{p1}}, {HELPER}->isBootJob(Landroid/app/job/JobParameters;)Z
    move-result v0
    if-eqz v0, :kai_original_job
    invoke-static {{p0, p1}}, {HELPER}->{action}(Landroid/app/job/JobService;Landroid/app/job/JobParameters;)V
    const/4 v0, 0x{result}
    return v0
    :kai_original_job
''' + text[end:]
    return text


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'apk', 'output', 'sdk', 'jdk', 'apktool'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    if sha(a.apk) != APK_SHA:
        raise ValueError('Wrong Messaging input APK')
    changes = {}
    for name, expected in PIN.items():
        path = a.source / (PREFIX + name + '.smali')
        if sha(path) != expected:
            raise ValueError('Wrong decoded source: ' + name)
        changes[name] = patch(name, path.read_text(encoding='utf-8'))
    root = Path(__file__).resolve().parents[1]
    helper = root / 'framework/apps/Messaging/src/com/android/mms/transaction/KaiBootRecovery.java'
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    decoded = out / 'decoded'
    shutil.copytree(a.source, decoded, ignore=shutil.ignore_patterns('build', 'dist'))
    for name, text in changes.items():
        (decoded / (PREFIX + name + '.smali')).write_text(text, encoding='utf-8', newline='\n')
    jdk = a.jdk.resolve(); bt = a.sdk.resolve() / 'build-tools/35.0.0'
    android = a.sdk.resolve() / 'platforms/android-30/android.jar'
    suffix = '.exe' if os.name == 'nt' else ''
    env = os.environ.copy(); env['JAVA_HOME'] = str(jdk)
    env['PATH'] = str(jdk/'bin') + os.pathsep + env.get('PATH', '')
    def run(args):
        args = list(map(str, args))
        r = subprocess.run(args, capture_output=True, text=True, env=env, timeout=180)
        with (out/'build.log').open('a', encoding='utf-8') as log:
            log.write(json.dumps(args) + '\n' + r.stdout + r.stderr)
        r.check_returncode()
    for name in ('classes', 'dex'):
        (out/name).mkdir()
    run([jdk/('bin/javac'+suffix), '--release', '8', '-classpath', android,
         '-d', out/'classes', helper])
    run([jdk/('bin/java'+suffix), '-cp', bt/'lib/d8.jar', 'com.android.tools.r8.D8',
         '--min-api', '30', '--lib', android, '--output', out/'dex',
         *sorted((out/'classes').rglob('*.class'))])
    run([jdk/('bin/java'+suffix), '-jar', a.apktool.resolve(), 'b', decoded,
         '-o', out/'rebuilt.apk'])
    candidate = out/'Messaging-boot-recovery-unsigned.apk'
    with zipfile.ZipFile(a.apk) as src, zipfile.ZipFile(out/'rebuilt.apk') as built:
        if any(n == 'classes2.dex' for n in src.namelist()):
            raise ValueError('Unexpected secondary DEX')
        with zipfile.ZipFile(candidate, 'x') as dst:
            for info in src.infolist():
                if not is_signature(info.filename):
                    data = built.read('classes.dex') if info.filename == 'classes.dex' else src.read(info.filename)
                    dst.writestr(copy.copy(info), data)
            dst.writestr('classes2.dex', (out/'dex/classes.dex').read_bytes(), compress_type=zipfile.ZIP_DEFLATED)
        with zipfile.ZipFile(candidate) as dst:
            original = {n for n in src.namelist() if not is_signature(n)}
            assert set(dst.namelist()) == original | {'classes2.dex'}
            assert [n for n in original if src.read(n) != dst.read(n)] == ['classes.dex']
            assert dst.testzip() is None
    report = dict(source_sha256=APK_SHA, sha256=sha(candidate), helper_sha256=sha(helper),
        changed_payload=['classes.dex'], added_payload=['classes2.dex'],
        source_smali_sha256=PIN, changed_smali_sha256={n:sha(decoded/(PREFIX+n+'.smali')) for n in PIN},
        manifest_resources_unchanged=True, installed=False,
        validation='Build and ZIP identity only; method audit and runtime lifecycle tests required')
    (out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
