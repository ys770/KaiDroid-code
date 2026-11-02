from pathlib import Path
import subprocess,json,hashlib
import argparse
p = argparse.ArgumentParser(description='Offline compile validation for the image26 Bluetooth mount policy; never loads policy')
p.add_argument('--build-root', type=Path, required=True)
root=p.parse_args().build_root.resolve(strict=True)
base=root/'engineering-display-stage-26/compact-system'
out=root/'bt-overlay-policy-build01'
out.mkdir()
p=base/'etc/selinux'
inputs=[p/'plat_sepolicy.cil',p/'mapping/29.0.cil',p/'kaidroid/29.0.compat.cil',p/'kaidroid/plat_pub_versioned.cil',p/'kaidroid/vendor_sepolicy.cil',base/'system_ext/etc/selinux/system_ext_sepolicy.cil']
extra=out/'overlay.cil'
extra.write_text('(allow init vendor_file (file (mounton)))\n')
compiler=root/'out-eng-02/host/linux-x86/bin/secilc'
rows=[]
for name,paths in [('baseline',inputs),('candidate',inputs+[extra])]:
 dest=out/name;dest.mkdir()
 cmd=[str(compiler),'-m','-M','true','-G','-c','30',*[str(p) for p in paths],'-o',str(dest/'policy.30'),'-f',str(dest/'file_contexts')]
 r=subprocess.run(cmd,capture_output=True)
 (dest/'stdout.txt').write_bytes(r.stdout);(dest/'stderr.txt').write_bytes(r.stderr)
 rows.append(dict(name=name,exit_code=r.returncode,inputs={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}))
 print(name,r.returncode,r.stderr.decode(errors='replace')[:1500])
(out/'result.json').write_text(json.dumps(rows,indent=2)+'\n')
