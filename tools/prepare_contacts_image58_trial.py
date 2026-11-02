"""Rebind the proven Contacts restoration trial to58 offline; never runs adb."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

PINS={
 'ContactsPermissionState.java':'d3736686a8dca3581c649c7f6f972be4a9c55227e7f01efc530ce0d21ccf4dbe',
 'smoke_contacts_permission_state.py':'ea7dd863b459e02a3da43f8d5028e6221076954dc5e4b9a4a06a5e734d94cad5',
 'trial_contacts_list.py':'76dd0d2858f67bfe20050d57274136a13ac73def2e6f0bc38db759c5d003b7b9',
 'build_contacts_permission_state.py':'16a79fb097705a52aead4788571cb7a09aaad94fbff7dffcb37387622dbc6729',
 'trial_contacts_one_permission.py':'29f867c2ca660d4862eb6a263f1549ad02202c07bae2532bbb9a4599cc813998',
}
OLD_HELPER='d530faeb678a60191320fcf468e8f8a4f5c14a2d194c0938ecfecb26a730fd52'


def sha(data):return hashlib.sha256(data).hexdigest()


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('jdk','sdk','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();root=Path(__file__).resolve().parent;out=a.output.resolve()
 names=set(PINS)|{'ContactsPermissionStateHostTest.java','compare_runtime_permissions.py',
  'trial_contacts_one_permission.py','test_trial_contacts_one_permission.py',
  'test_trial_contacts_list.py','test_smoke_contacts_permission_state.py',
  'test_contacts_settings_navigation.py','contacts_settings_navigation.py'}
 original={name:(root/name).read_bytes() for name in names}
 for name,pin in PINS.items():
  if sha(original[name])!=pin:raise ValueError('Original guarded trial changed: '+name)
 out.mkdir(parents=True,exist_ok=False)
 def rebind(text,name):
  changed=text.replace('"36"','"58"').replace("'36'","'58'").replace('image36','image58')
  if name=='trial_contacts_one_permission.py':
   old="('image', 'getprop ro.kaidroid.image', '31')"
   if changed.count(old)!=1:raise ValueError('Historical one-choice image guard differs')
   changed=changed.replace(old,"('image', 'getprop ro.kaidroid.image', '58')")
  return changed
 for name,data in original.items():
  text=data.decode().replace('\r\n','\n')
  (out/name).write_bytes(rebind(text,name).encode())
 def run(label,argv):
  result=subprocess.run(list(map(str,argv)),cwd=out,capture_output=True,timeout=120)
  (out/(label+'.stdout')).write_bytes(result.stdout);(out/(label+'.stderr')).write_bytes(result.stderr)
  result.check_returncode();return result
 run('build',[sys.executable,'-X','utf8',out/'build_contacts_permission_state.py',
              '--sdk',a.sdk.resolve(),'--jdk',a.jdk.resolve(),'--output',out/'helper'])
 built=json.loads((out/'helper/build.json').read_text())
 if built.get('mutation_eligibility_assertions')!=124 or built.get('streaming_hash_cases')!=6:
  raise ValueError('Permission helper host controls absent')
 helper=built['jar_sha256']
 smoke=out/'smoke_contacts_permission_state.py';text=smoke.read_text()
 if text.count(OLD_HELPER)!=1:raise ValueError('Unexpected prior helper pin')
 smoke.write_bytes(text.replace(OLD_HELPER,helper).encode())
 # The same-directory copied modules/tests bind to the generated helper. Do
 # not add the repository tools directory to PYTHONPATH for these controls.
 run('tests',[sys.executable,'-X','utf8','-m','unittest','discover','-s',str(out),'-p','test_*.py'])
 for name,data in original.items():
  expected=rebind(data.decode().replace('\r\n','\n'),name)
  if name=='smoke_contacts_permission_state.py':expected=expected.replace(OLD_HELPER,helper)
  if (out/name).read_bytes()!=expected.encode():raise ValueError('Unrelated generated trial delta: '+name)
 result=dict(scope='Offline image58-only rebind; no permission or phone operation',
  source_inputs={n:sha(b) for n,b in sorted(original.items())},
  generated_inputs={n:sha((out/n).read_bytes()) for n in sorted(names)},
  helper_sha256=helper,image=58,candidate_apk_sha256='20358b8548494b4486d2020635197addc393f3a948675c2543932c939e320248',
  source_changes='Only historical image31/36 to58 guards/documentation and newly built helper hash',
  mutation_eligibility_assertions=124,streaming_hash_cases=6,python_guard_controls_passed=True,
  old_trial_unchanged=True,runtime_verified=False,retained_permission_choices_authorized_by_tool=False)
 (out/'result.json').write_bytes((json.dumps(result,indent=2)+'\n').encode());print(json.dumps(result))


if __name__=='__main__':main()
