"""Predict the seven added private APIs through the unchanged native10 generator."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from prepare_tcl_dialog_hiddenapi_candidate import SIGNATURES, rows
from audit_tcl_dialog_hiddenapi10 import GENERATOR

BASE = "9926fe86df5b86b04e9b4eae065d2aa5a1b65f3e640f20e46210e265ff70716c"
ADDED = {
 "Landroid/inputmethodservice/InputMethodService;->mTclSymbolsShown:Z",
 "Landroid/inputmethodservice/TclImeFooterLayout;->KIKA:Ljava/lang/String;",
 "Landroid/inputmethodservice/TclImeFooterLayout;->FOOTER:I",
 "Landroid/inputmethodservice/TclImeFooterLayout;-><init>()V",
 "Landroid/inputmethodservice/TclImeFooterLayout;->reserveFooter(Ljava/lang/String;Landroid/view/View;)Z",
 "Landroid/inputmethodservice/TclImeFooterLayout;->updateSymbolsShown(Ljava/lang/String;Landroid/widget/FrameLayout;Z)Z",
 "Landroid/inputmethodservice/TclImeFooterLayout;->adjustedTop(Ljava/lang/String;IZ)I",
}


def sha(data): return hashlib.sha256(data).hexdigest()


def predict(data):
 if sha(data) != BASE: raise ValueError("Require exact native10 Linux CSV")
 old = rows(data)
 if ADDED & old.keys(): raise ValueError("New private API already exists")
 if any(old.get(n) != ["test-api", "whitelist"] for n in SIGNATURES):
  raise ValueError("Accepted Calendar classifications changed")
 return b"".join(line + b"\n" for line in sorted(data.splitlines() +
                    [n.encode() + b",blacklist" for n in ADDED]))


def validate(before, after):
 old, new = rows(before), rows(after)
 if old.keys() - new.keys() or new.keys() - old.keys() != ADDED or any(new[n] != old[n] for n in old) or any(new[n] != ["blacklist"] for n in ADDED):
  raise ValueError("CSV differs beyond seven new blacklisted private APIs")
 if after != predict(before): raise ValueError("CSV bytes/order/newlines differ from prediction")
 return {"retained_rows":len(old), "added_rows":len(ADDED), "total_rows":len(new),
         "old_classifications_unchanged":True, "added_private_apis":sorted(ADDED)}


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ("flags", "generator", "output"): p.add_argument("--"+n,type=Path,required=True)
 a=p.parse_args(); before=a.flags.read_bytes(); expected=predict(before)
 if sha(a.generator.read_bytes()) != GENERATOR: raise ValueError("Require unchanged native10 generator")
 a.output.mkdir(parents=True,exist_ok=False)
 unassigned=[]
 for line in before.splitlines():
  unassigned.append(line.split(b",",1)[0] if line.split(b",",1)[0].decode() in SIGNATURES else line)
 unassigned += [n.encode() for n in ADDED]
 source=a.output/"pre-default.csv"; source.write_bytes(b"".join(n+b"\n" for n in sorted(unassigned)))
 raw=a.output/"generated-host.csv"
 run=subprocess.run([sys.executable,str(a.generator),"--csv",str(source),"--output",str(raw)],capture_output=True,timeout=120)
 (a.output/"generator.log").write_bytes(run.stdout+run.stderr);run.check_returncode()
 linux=raw.read_bytes().replace(b"\r\n",b"\n")
 delta=validate(before,linux)
 if linux!=expected: raise ValueError("Source generator differs from prediction")
 (a.output/"expected-linux-flags.csv").write_bytes(linux)
 report=dict(scope="Offline complete-CSV source simulation; native generation still required",baseline_sha256=BASE,
   generator_sha256=GENERATOR,expected_linux_sha256=sha(linux),delta=delta,
   simulation_note="Retained final labels supplied; only two Calendar APIs made unassigned for their existing exact generator rule, and seven new private APIs supplied unassigned",
   compiled=False,installed=False,full_parity=False)
 (a.output/"result.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
 print(json.dumps(report))


if __name__=="__main__":main()
