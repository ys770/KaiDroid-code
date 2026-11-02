"""Read fixed Nokia Contacts DB/WAL files, then compare typed logical rows locally."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import sqlite3
import struct
import subprocess
import uuid

SERIAL='DEVICE_SERIAL_REQUIRED'
FRAMEWORK='a0f05ced9933a272a3b7f46f99818325ead8ee706eaf9e8138e4ab20b0f94054'
PREFIX='/data/user/0/com.android.providers.contacts/databases/'
FILES=('contacts2.db','contacts2.db-wal','profile.db','profile.db-wal')
JOURNALS=('contacts2.db-journal','profile.db-journal')
PROFILE='n139dl-image58-contacts01'
ALGORITHM='sqlite-typed-row-multisets-with-rowid01'
def digest(data):return hashlib.sha256(data).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def write_new(path,value):
 with path.open('x',encoding='utf-8',newline='\n') as stream:json.dump(value,stream,indent=2);stream.write('\n')
def inventory(shell):
 result={}
 for name in JOURNALS+FILES:
  path=shlex.quote(PREFIX+name)
  response=shell('inventory-'+name,'if test -L '+path+'; then echo invalid; elif test -f '+path+"; then stat -c '%s %u %g %a %Y' "+path+'; sha256sum '+path+'; elif test -e '+path+'; then echo invalid; else echo absent; fi')
  if response=='absent':continue
  lines=response.splitlines()
  if len(lines)!=2 or not re.fullmatch(r'\d+ 10045 10045 [0-7]{3,4} \d+',lines[0]) or not re.fullmatch('[0-9a-f]{64}  '+re.escape(PREFIX+name),lines[1]):raise ValueError('Unexpected provider file identity: '+name)
  size,uid,gid,mode,mtime=lines[0].split()
  if name in JOURNALS and (int(size)!=0 or lines[1].split()[0]!=digest(b'')):raise ValueError('Nonempty rollback journal; cannot accept bare database snapshot: '+name)
  if int(size)>64*1024**2:raise ValueError('Provider file exceeds bounded64MiB capture')
  result[name]=dict(size=int(size),uid=int(uid),gid=int(gid),mode=mode,mtime=int(mtime),sha256=lines[1].split()[0])
 if not {'contacts2.db','profile.db'}<=result.keys():raise ValueError('Both provider databases must exist')
 return result
def capture(adb,boot,apk_sha,output):
 if str(uuid.UUID(boot))!=boot or not re.fullmatch('[0-9a-f]{64}',apk_sha):raise ValueError('Require canonical boot and exact APK hash')
 output.mkdir(parents=True,exist_ok=False);(output/'files').mkdir();seq=0
 def run(label,args):
  nonlocal seq
  seq+=1
  try:r=subprocess.run([str(adb),'-s',SERIAL]+args,capture_output=True,timeout=45)
  except subprocess.TimeoutExpired as error:
   (output/(str(seq)+'-'+label+'.timeout')).write_bytes((error.stdout or b'')+(error.stderr or b''));raise
  # DB contents live only in fixed named files, never console output.
  if label.startswith('db-'):
   (output/'files'/label[3:]).write_bytes(r.stdout)
  else:(output/(str(seq)+'-'+label+'.stdout')).write_bytes(r.stdout)
  (output/(str(seq)+'-'+label+'.stderr')).write_bytes(r.stderr);r.check_returncode();return r.stdout
 def shell(label,text):return run(label,['shell',text]).decode().replace('\r\n','\n').strip()
 def guard():
  if shell('identity','getprop ro.serialno; getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getenforce').splitlines()!=[SERIAL,'58',boot,'0','Enforcing']:raise ValueError('Wrong Nokia image/boot/root/SELinux')
  if shell('framework','sha256sum /system/framework/framework.jar').split()[0]!=FRAMEWORK:raise ValueError('Framework changed')
  paths=shell('contacts-path','pm path com.android.contacts').splitlines()
  if len(paths)!=1 or not paths[0].startswith('package:'):raise ValueError('Ambiguous Contacts path')
  path=paths[0][8:]
  if not re.fullmatch(r'/(?:data/app|system)/[A-Za-z0-9_+=~./-]+\.apk',path) or '..' in Path(path).parts:raise ValueError('Unknown APK path')
  if shell('contacts-hash','sha256sum '+shlex.quote(path)).split()[0]!=apk_sha:raise ValueError('Contacts APK changed')
  provider=shell('provider-package','dumpsys package com.android.providers.contacts')
  if set(re.findall(r'^\s*userId=(\d+)\s*$',provider,re.M))!={'10045'}:raise ValueError('Provider UID changed')
 report=dict(profile=PROFILE,serial=SERIAL,image=58,boot=boot,contacts_apk_sha256=apk_sha,framework_sha256=FRAMEWORK,complete=False,device_mutation=False,logical_verified=False)
 try:
  guard();shell('active-processes','ps -A -o PID,NAME');before=inventory(shell)
  for name,row in before.items():
   data=run('db-'+name,['exec-out','cat',PREFIX+name])
   if len(data)!=row['size'] or digest(data)!=row['sha256']:raise ValueError('Provider changed during read: '+name)
  after=inventory(shell);guard()
  if before!=after:raise ValueError('Provider snapshot not stable; retain attempt, do not claim equality')
  report.update(files=before,stable_before_read_after=True,rollback_journals_absent_or_empty_before_and_after=True,complete=True,shm_copied=False)
 except Exception as error:report['error']=str(error);raise
 finally:write_new(output/'snapshot.json',report)
 return report
def q(value):return '"'+value.replace('"','""')+'"'
def database(path):
 connection=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True);connection.text_factory=bytes
 try:
  connection.execute('PRAGMA query_only=ON')
  schema=connection.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name').fetchall()
  schema_hash=digest(canonical([[v.hex() if isinstance(v,bytes) else v for v in row] for row in schema]))
  rowid_flags={r[1].decode('utf-8'):r[4] for r in connection.execute('PRAGMA table_list') if r[0]==b'main'}
  tables={}
  for kind,rawname,_,_ in schema:
   if kind!=b'table':continue
   name=rawname.decode('utf-8');info=list(connection.execute('PRAGMA table_xinfo('+q(name)+')'));all_columns=[row[1].decode('utf-8') for row in info];columns=[row[1].decode('utf-8') for row in info if row[6]!=1]
   if name not in rowid_flags:raise ValueError('SQLite cannot classify table rowid semantics')
   has_rowid=rowid_flags[name]==0
   if has_rowid:
    alias=next((n for n in ('_rowid_','rowid','oid') if n not in {c.lower() for c in all_columns}),None)
    if alias is None:raise ValueError('All observable rowid aliases shadowed')
    columns=[alias]+columns
   terms=','.join(q(c)+',typeof('+q(c)+')' for c in columns)
   hashes=[]
   for row in connection.execute('SELECT '+terms+' FROM '+q(name)):
    values=[]
    for i in range(0,len(row),2):
     value,kind=row[i:i+2]
     if isinstance(value,bytes):value=value.hex()
     elif isinstance(value,float):value=struct.pack('>d',value).hex()
     values.append([kind.decode('ascii'),value])
    hashes.append(digest(canonical(values)))
    if len(hashes)>1000000:raise ValueError('Table exceeds bounded row comparison')
   tables[name]=dict(rows=len(hashes),implicit_rowid_included=has_rowid,typed_row_multiset_sha256=digest(canonical(sorted(hashes))))
  return dict(schema_sha256=schema_hash,user_version=connection.execute('PRAGMA user_version').fetchone()[0],application_id=connection.execute('PRAGMA application_id').fetchone()[0],tables=tables)
 finally:connection.close()
def analyze(snapshot,output):
 source=json.loads((snapshot/'snapshot.json').read_text())
 if source.get('profile')!=PROFILE or source.get('complete') is not True or source.get('stable_before_read_after') is not True or source.get('rollback_journals_absent_or_empty_before_and_after') is not True or not {'contacts2.db','profile.db'}<=set(source['files'])<=set(FILES+JOURNALS):raise ValueError('Incomplete or unknown snapshot profile')
 for name in set(source['files'])&set(JOURNALS):
  row=source['files'][name]
  if row.get('size')!=0 or row.get('sha256')!=digest(b'') or (row.get('uid'),row.get('gid'))!=(10045,10045):raise ValueError('Rollback journal evidence is not empty/owned')
 if {p.name for p in (snapshot/'files').iterdir()}!=set(source['files']):raise ValueError('Snapshot file coverage changed')
 if source.get('serial')!=SERIAL or source.get('image')!=58 or source.get('framework_sha256')!=FRAMEWORK or str(uuid.UUID(source['boot']))!=source['boot'] or not re.fullmatch('[0-9a-f]{64}',source.get('contacts_apk_sha256','')):raise ValueError('Snapshot context differs from profile')
 output.mkdir(parents=True,exist_ok=False);working=output/'working';working.mkdir()
 for name,row in source['files'].items():
  path=snapshot/'files'/name
  if path.is_symlink() or len(path.read_bytes())!=row['size'] or digest(path.read_bytes())!=row['sha256']:raise ValueError('Captured file changed: '+name)
  shutil.copyfile(path,working/name)
 result=dict(profile=PROFILE,algorithm=ALGORITHM,context={k:source[k] for k in ('serial','image','boot','framework_sha256','contacts_apk_sha256')},snapshot_sha256=digest((snapshot/'snapshot.json').read_bytes()),databases={},query_only_on_local_copies=True,original_snapshot_modified=False,device_commands_issued=False)
 try:
  for name in ('contacts2.db','profile.db'):result['databases'][name]=database(working/name)
  result.update(complete=True,logical_sha256=digest(canonical(result['databases'])))
 except Exception as error:result.update(complete=False,error=str(error));raise
 finally:write_new(output/'analysis.json',result)
 return result
def compare(before,after):
 if any(x.get('profile')!=PROFILE or x.get('algorithm')!=ALGORITHM or x.get('complete') is not True or x.get('logical_sha256')!=digest(canonical(x.get('databases'))) for x in (before,after)):raise ValueError('Incomplete/unbound logical analysis')
 if any(before.get('context',{}).get(k)!=after.get('context',{}).get(k) or before.get('context',{}).get(k) is None for k in ('serial','image','boot','framework_sha256')):raise ValueError('Before/after device context changed')
 a,b=before['databases'],after['databases'];changes={n:dict(before=a.get(n),after=b.get(n)) for n in a.keys()|b.keys() if a.get(n)!=b.get(n)}
 return dict(profile=PROFILE,logical_database_states_equal=not changes,changed_databases=changes,apk_transition=dict(before=before['context'].get('contacts_apk_sha256'),after=after['context'].get('contacts_apk_sha256')),contact_values_printed=False,physical_file_equality_not_implied=True,full_parity=False)
def main():
 p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='mode',required=True)
 cap=sub.add_parser('capture')
 for n in ('adb','output'):cap.add_argument('--'+n,type=Path,required=True)
 for n in ('boot','apk-sha256'):cap.add_argument('--'+n,required=True)
 local=sub.add_parser('analyze');local.add_argument('--snapshot',type=Path,required=True);local.add_argument('--output',type=Path,required=True)
 diff=sub.add_parser('compare')
 for n in ('before','after','output'):diff.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args()
 if a.mode=='capture':r=capture(a.adb,a.boot,a.apk_sha256,a.output);print(json.dumps(dict(complete=r['complete'],files=len(r['files']),device_mutation=False)))
 elif a.mode=='analyze':r=analyze(a.snapshot,a.output);print(json.dumps(dict(complete=r['complete'],databases=len(r['databases']),contact_values_printed=False)))
 else:r=compare(json.loads(a.before.read_text()),json.loads(a.after.read_text()));write_new(a.output,r);print(json.dumps(dict(logical_database_states_equal=r['logical_database_states_equal'],changed_databases=list(r['changed_databases']))))
if __name__=='__main__':main()
