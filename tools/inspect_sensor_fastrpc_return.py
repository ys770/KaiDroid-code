"""Hash-bound offline FastRPC return-path landmarks; never accesses a handset."""
import argparse,hashlib,json
from pathlib import Path
from inspect_engineering_uart_kernel import inspect
SYMBOLS='a5aa3100ceb9d9d46902d201656f5764ace591c797c5e392b005999bc3d88808'
LANDMARKS={
 'fastrpc_glink_notify_rx':{'c069e15c':'080093e5','c069e160':'180081e5','c069e164':'080081e2','c069e16c':'b39eebea'},
 'fastrpc_internal_invoke':{'c0697254':'0000e0e3','c069725c':'180084e5','c069897c':'187094e5','c0698988':'000057e3','c069898c':'8f00001a','c0698c9c':'6870a013','c0698d48':'0700a001'},
 'fastrpc_device_ioctl':{'c069ba8c':'010205e3','c069ba94':'0c004ce3','c069ba9c':'b300000a','c069bdf0':'68ebffeb','c069bdf4':'0060a0e1','c069bdf8':'c70400ea','c069d128':'0600a001'},
}
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('kernel','symbols','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();assert hashlib.sha256(a.symbols.read_bytes()).hexdigest()==SYMBOLS
 inspect(a.kernel,a.symbols,a.output,tuple(LANDMARKS))
 found={}
 for name,points in LANDMARKS.items():
  lines=(a.output/(name+'.asm')).read_text().splitlines();found[name]={}
  for address,code in points.items():
   matches=[s for s in lines if s.startswith(address+': '+code+' ')]
   assert len(matches)==1,(name,address);found[name][address]=matches[0]
 r={'landmarks':found,'interpretation':'GLINK response word at +8 is copied to matched context +0x18 and completion signaled; invoke loads that context field as its result. Nonzero result follows cleanup and returns unless restart comparison overrides it. ioctl 0xc00c5201 passes invoke result through unchanged.','limits':['Offline control-flow evidence, not a trace of the failed image57 invocation.','Context result is initially -1; local paths can also return -1.','Observed userspace errno1 does not alone distinguish local failure from a transported negative result.','No permission/policy change or sensor-support acceptance follows.'],'runtime_origin_resolved':False,'device_operations':False}
 (a.output/'return-path.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8')
if __name__=='__main__':main()
