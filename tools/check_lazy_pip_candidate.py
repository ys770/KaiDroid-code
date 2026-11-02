"""Run pinned full PipUI source bodies against explicit host-only API models."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from prepare_lazy_pip_candidate import SOURCE, candidate

MODEL = r'''
import java.io.FileDescriptor;
import java.io.PrintWriter;
public class PipHost {
 interface Lazy<T> { T get(); }
 static class Configuration {}
 interface IPinnedStackAnimationListener {}
 static class PackageManager {
  static final String FEATURE_PICTURE_IN_PICTURE="android.software.picture_in_picture";
  boolean supported;
  boolean hasSystemFeature(String feature) { check(feature.equals(FEATURE_PICTURE_IN_PICTURE)); return supported; }
 }
 static final String FEATURE_PICTURE_IN_PICTURE=PackageManager.FEATURE_PICTURE_IN_PICTURE;
 static class Context {
  PackageManager pm=new PackageManager(); int user;
  PackageManager getPackageManager(){return pm;}
 }
 static class UserHandle { static final int USER_SYSTEM=0; }
 static class UserManager {
  Context context; UserManager(Context c){context=c;}
  static UserManager get(Context c){return new UserManager(c);}
  int getUserHandle(){return context.user;}
 }
 static class SystemUI {
  Context mContext; SystemUI(Context c){mContext=c;}
  public void start(){}
  protected void onConfigurationChanged(Configuration c){}
  public void dump(FileDescriptor f,PrintWriter p,String[] a){}
 }
 static class CommandQueue {
  interface Callbacks { void showPictureInPictureMenu(); }
  int callbacks; void addCallback(Callbacks c){callbacks++;}
 }
 static class BasePipManager {
  int calls;
  void showPictureInPictureMenu(){calls++;} void expandPip(){calls++;}
  void hidePipMenu(Runnable a,Runnable b){calls++;}
  void onConfigurationChanged(Configuration c){calls++;}
  void setShelfHeight(boolean b,int h){calls++;}
  void setPinnedStackAnimationType(int a){calls++;}
  void setPinnedStackAnimationListener(IPinnedStackAnimationListener l){calls++;}
  void dump(PrintWriter p){calls++;}
 }
 static class Provider implements Lazy<BasePipManager> {
  int gets; BasePipManager manager=new BasePipManager();
  public BasePipManager get(){gets++;return manager;}
 }
 @BODY@
 static void check(boolean value){if(!value)throw new AssertionError();}
 static PipUI create(Context c,CommandQueue q,Provider p){return new PipUI(c,q,@ARGUMENT@);}
 static void forward(PipUI p){
  p.showPictureInPictureMenu();p.expandPip();p.hidePipMenu(null,null);
  p.onConfigurationChanged(new Configuration());p.setShelfHeight(true,10);
  p.setPinnedStackAnimationType(1);p.setPinnedStackAnimationListener(null);p.dump(null,null,null);
 }
 public static void main(String[] args){
  boolean candidate=@CANDIDATE@;
  Context c=new Context();CommandQueue q=new CommandQueue();Provider provider=new Provider();
  PipUI p=create(c,q,provider);check(provider.gets==(candidate?0:1));
  p.start();check(q.callbacks==0);forward(p);
  check(provider.gets==(candidate?0:1));check(provider.manager.calls==(candidate?0:8));
  System.out.println("unsupported construction/start/forward/config/dump PASS");
  c=new Context();c.pm.supported=true;q=new CommandQueue();provider=new Provider();p=create(c,q,provider);
  check(provider.gets==1);forward(p);check(provider.manager.calls==8);
  p.start();check(q.callbacks==1);forward(p);check(provider.manager.calls==16);check(provider.gets==1);
  System.out.println("supported eager/prestart/forward/callbacks PASS");
  c=new Context();c.pm.supported=true;c.user=10;q=new CommandQueue();provider=new Provider();p=create(c,q,provider);
  boolean threw=false;try{p.start();}catch(IllegalStateException expected){threw=true;}
  check(threw);check(provider.gets==1);check(q.callbacks==0);
  System.out.println("supported secondary-user rejection PASS");
 }
}
'''


def run(source_root, output):
    raw = (source_root / SOURCE).read_bytes()
    changed = candidate(raw)
    output.mkdir(parents=True, exist_ok=False)
    reports = []
    for label, text in [('baseline', raw.decode()), ('candidate', changed)]:
        body = text[text.index('public class PipUI'):].replace('public class PipUI', 'public static class PipUI', 1)
        body = body.replace('    @Inject\n', '')
        source = MODEL.replace('@BODY@', body).replace('@ARGUMENT@', 'p' if label == 'candidate' else 'p.get()').replace('@CANDIDATE@', str(label == 'candidate').lower())
        folder = output / label; folder.mkdir()
        path = folder / 'PipHost.java'; path.write_text(source)
        compile_result = subprocess.run(['javac', '-source', '8', '-target', '8', '-d', str(folder), str(path)], capture_output=True, text=True)
        (folder / 'javac.stderr').write_text(compile_result.stderr)
        compile_result.check_returncode()
        result = subprocess.run(['java', '-cp', str(folder), 'PipHost'], capture_output=True, text=True)
        (folder / 'run.stdout').write_text(result.stdout); (folder / 'run.stderr').write_text(result.stderr)
        result.check_returncode()
        if result.stderr or result.stdout.count('PASS') != 3: raise ValueError('Incomplete host cases')
        reports.append(dict(label=label, full_source_body_sha256=hashlib.sha256(body.encode()).hexdigest(),
                            fixture_sha256=hashlib.sha256(source.encode()).hexdigest(), compile_exit=0, run_exit=0, stdout=result.stdout,
                            javac_stderr=compile_result.stderr))
    return dict(runs=reports, limits=['Host API models only; no Android runtime, Dagger regeneration, Binder callbacks, device feature state or memory saving is verified.',
        'Supported construction remains eager. Unsupported forwarding/configuration/dump becomes a no-op with no manager. Dynamic feature changes during process lifetime are not modeled.'])


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    result = run(a.source, a.output)
    (a.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
