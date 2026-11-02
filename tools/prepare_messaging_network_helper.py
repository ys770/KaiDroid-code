"""Prepare isolated queue-aware MMS work helpers; leave accepted production source unchanged."""
import argparse
import hashlib
import json
from pathlib import Path

BASE='372fe9dd6b3acc2d10225b5e5b402d06626ca6c8a168aedf87c91ef7d0ca54a2'


def sha(data):return hashlib.sha256(data).hexdigest()


def source(data):
 if sha(data)!=BASE:raise ValueError('Not exact accepted boot helper source')
 text=data.decode('utf-8').replace('\r\n','\n')
 edits={
  '    private KaiBootRecovery() {}':'''    private KaiBootRecovery() {}

    /** Share the existing negative-ID sequence with isolated MMS work jobs. */
    public static int reserveWorkStartId() {
        int value = NEXT_START_ID.getAndIncrement();
        if (value >= 0) throw new IllegalStateException("Reserved MMS start IDs exhausted");
        return value;
    }

    public static Service boundWorker(IBinder binder) {
        return binder instanceof WorkerBinder ? ((WorkerBinder) binder).service : null;
    }''',
  '        if (startId >= 0 || (session != null && session.startId == startId)) {':
  '        if (startId >= 0 || (session != null && session.startId == startId)\n                || KaiMmsWork.acceptCompletion(service, startId)) {',
  '        if (session == null) return;\n        MAIN.post(() -> {\n            if (active != session || session.connections[0].worker != worker) return;':
  '''        MAIN.post(() -> {
            boolean bootWatching = session != null && active == session && session.connections[0].worker == worker;
            if (!bootWatching && !KaiMmsWork.watching(worker)) return;''',
  '            session.complete(worker);\n        });\n    }\n\n    /** Reserved dispatch':
  '            if (bootWatching && active == session) session.complete(worker);\n            KaiMmsWork.idle(worker);\n        });\n    }\n\n    /** Reserved dispatch',
 }
 for old,new in edits.items():
  if text.count(old)!=1:raise ValueError('Accepted queue/idle helper shape changed')
  text=text.replace(old,new)
 return text.encode('utf-8')


def main():
 p=argparse.ArgumentParser(description=__doc__);root=Path(__file__).resolve().parents[1]
 p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 original=root/'framework/apps/Messaging/src/com/android/mms/transaction/KaiBootRecovery.java'
 work=root/'experiments/messaging/network-work01/KaiMmsWork.java'
 files={'KaiBootRecovery.java':source(original.read_bytes()),'KaiMmsWork.java':work.read_bytes()}
 a.output.mkdir(parents=True,exist_ok=False)
 for name,data in files.items():(a.output/name).write_bytes(data)
 report=dict(accepted_boot_source_sha256=BASE,files={n:sha(b) for n,b in files.items()},
  scope='Isolated candidate; preserve original queued/running/revision/real-idle checks and boot/SMS path; add separate MMS JobWorkItem lifecycle',
  production_source_unchanged=sha(original.read_bytes())==BASE,compiled=False,installed=False,full_parity=False)
 (a.output/'contract.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()
