"""Execute only the actual packet shell's harmless option preamble."""
import os,subprocess

MARKER=b'KAIDROID_PACKET_PREAMBLE_OK\n'


def canonical(data):
 result=data.replace(b'\r\n',b'\n')
 if b'\r' in result or result.startswith(b'\xef\xbb\xbf'):raise ValueError('Shell contains bare CR or BOM')
 return result


def smoke(data,bash):
 if canonical(data)!=data:raise ValueError('Packet executable is not canonical LF')
 lines=data.splitlines(keepends=True)
 preamble=[]
 for line in lines:
  preamble.append(line)
  if line==b'set -euo pipefail\n':break
  if line.strip() and not line.startswith(b'#'):raise ValueError('Unexpected command before shell option preamble')
 else:raise ValueError('Exact executable option preamble absent')
 # No stage assignments, filesystem commands or image tools are executed.
 program=b''.join(preamble)+b"printf '%s\\n' KAIDROID_PACKET_PREAMBLE_OK\n"
 env={k:v for k,v in os.environ.items() if k not in ('BASH_ENV','ENV','BASHOPTS','SHELLOPTS') and not k.startswith('BASH_FUNC_')}
 result=subprocess.run([str(bash),'--noprofile','--norc','-s'],input=program,capture_output=True,timeout=10,env=env)
 if result.returncode or result.stdout!=MARKER or result.stderr:raise ValueError('Actual packet shell preamble execution failed: '+repr(result.stderr))
 syntax=subprocess.run([str(bash),'--noprofile','--norc','-n','-s'],input=data,capture_output=True,timeout=10,env=env)
 if syntax.returncode or syntax.stderr:raise ValueError('Actual complete packet shell syntax failed: '+repr(syntax.stderr))
 return dict(canonical_lf=True,preamble_executed=True,whole_shell_syntax_passed=True,no_image_or_filesystem_commands_executed=True)
