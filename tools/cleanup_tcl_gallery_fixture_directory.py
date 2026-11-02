"""Remove only the new empty donor fixture directory AFTER Gallery deletes its image."""
import argparse
import json
from pathlib import Path
import subprocess
from capture_tcl_ui_reference import SERIAL,FINGERPRINT
from stage_tcl_gallery_fixture import DIR,FILE,SHA


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('adb','stage','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--remove-empty-directory',action='store_true')
    a=p.parse_args();stage=json.loads((a.stage/'report.json').read_text())
    if not (stage.get('complete') and stage.get('owned_file_verified') and stage.get('stage_requested')
            and stage.get('fixture_sha256')==SHA and stage.get('remote_directory')==DIR
            and stage.get('remote_file')==FILE and stage.get('phase')=='scan_requested'
            and (a.stage/'absent-path.stdout').read_text().strip()=='ABSENT'):
        raise ValueError('Need exact successful owned-fixture staging evidence')
    a.output.mkdir(parents=True,exist_ok=False)
    report=dict(remove_empty_directory_requested=a.remove_empty_directory,
                remote_directory=DIR,remote_file=FILE,complete=False)
    def shell(label,command):
        try:r=subprocess.run([str(a.adb),'-s',SERIAL,'shell',command],capture_output=True,timeout=40)
        except subprocess.TimeoutExpired:
            report['timed_out_command']=label;raise
        (a.output/(label+'.stdout')).write_bytes(r.stdout);(a.output/(label+'.stderr')).write_bytes(r.stderr)
        r.check_returncode();return r.stdout.decode().strip()
    try:
        if shell('identity','getprop ro.build.fingerprint')!=FINGERPRINT:raise ValueError('Wrong donor')
        if shell('boot-before','cat /proc/sys/kernel/random/boot_id')!=stage['boot_id']:raise ValueError('Boot changed')
        if shell('file-absent','if [ -e '+FILE+' ]; then echo EXISTS; else echo ABSENT; fi')!='ABSENT':
            raise ValueError('Fixture still exists; this tool NEVER deletes files')
        if shell('directory-contents','ls -A '+DIR):raise ValueError('Directory is not empty; preserve all contents')
        if a.remove_empty_directory:
            shell('rmdir','rmdir '+DIR)
            if shell('directory-absent','if [ -e '+DIR+' ]; then echo EXISTS; else echo ABSENT; fi')!='ABSENT':raise ValueError('Directory still exists')
        if shell('boot-after','cat /proc/sys/kernel/random/boot_id')!=stage['boot_id']:raise ValueError('Boot changed')
        report['complete']=True
    except Exception as error:
        report['error']=str(error);raise
    finally:(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__=='__main__':main()
