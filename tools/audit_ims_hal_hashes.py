"""Compare generated IMS Stub hash constants with a captured live HAL chain."""
from pathlib import Path
import argparse,hashlib,json,re
p=argparse.ArgumentParser();p.add_argument('--smali',type=Path,required=True);p.add_argument('--runtime',type=Path,required=True);p.add_argument('--current',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
log=json.loads(a.runtime.read_text())['stdout'];block=log.split('CLIENT V1_4 ')[1];names=re.search(r'CHAIN \[(.*?)\]',block).group(1).split(', ');values=re.findall(r'^HASH ([0-9a-f]{64})',block,re.M);assert len(names)==len(values)==8;remote=dict(zip(names,values));rows=[];files={}
for version in range(5):
 path=a.smali/('V1_'+str(version))/'IImsRadio$Stub.smali';s=path.read_text();files[str(path)]=hashlib.sha256(path.read_bytes()).hexdigest();method=s.split('.method public final getHashChain()Ljava/util/ArrayList;')[1].split('.end method')[0]
 arrays=re.findall(r'(:array_\w+)\s+\.array-data 1\s+(.*?)\.end array-data',method,re.S);hashes={label:bytes(int(v[:-1],0)&255 for v in data.split()).hex() for label,data in arrays};assert all(len(v)==64 for v in hashes.values())
 chain=s.split('.method public final interfaceChain()Ljava/util/ArrayList;')[1].split('.end method')[0];interfaces=re.findall(r'const-string v\d+, "([^"]+)"',chain);order=re.findall(r'fill-array-data v\d+, (:array_\w+)',method);assert len(order)==len(interfaces)==version+2
 # Confirm each filled byte array is stored in the next chain position.
 placements=re.findall(r'fill-array-data (v\d+), (:array_\w+)\s+const/\w+ (v\d+), (0x[0-9a-f]+)\s+aput-object \1, v\d+, \3',method);assert [int(x[3],16) for x in placements]==list(range(len(order)));assert [x[1] for x in placements]==order
 for name,label in zip(interfaces,order):rows.append({'client':'1.'+str(version),'interface':name,'candidate':hashes[label],'remote':remote[name],'match':hashes[label]==remote[name]})
current=a.current.read_text();mismatches=[r for r in rows if not r['match']];assert all(r['interface']=='android.hidl.base@1.0::IBase' for r in mismatches)
for r in mismatches:assert r['candidate']+' '+r['interface'] in current and r['remote']+' '+r['interface'] in current
report={'rows':rows,'qti_versions_match':list(range(5)),'ibase_exact_match':False,'both_ibase_hashes_in_aosp_current':True,'smali_hashes':files,'runtime_sha256':hashlib.sha256(a.runtime.read_bytes()).hexdigest(),'aosp_current_sha256':hashlib.sha256(a.current.read_bytes()).hexdigest(),'limits':['Hash identity is not actual radio transaction, callback, registration or call validation','Inputs are decoded candidate Stub constants and previously captured HAL replies']}
with a.output.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
print('PASS five Qualcomm version hashes; IBase differs but both are AOSP-listed')
