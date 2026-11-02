"""Execute candidate Java methods with host stand-ins; not an Android/audio test."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def method(source, signature):
    if source.count(signature) != 1:
        raise ValueError('Nonunique method: ' + signature)
    start = source.index(signature)
    pos = source.index('{', start)
    depth = 1
    end = pos + 1
    # These four methods contain no braces inside comments or string literals.
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--candidate', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--jdk', type=Path, required=True)
    a = p.parse_args()
    text = (a.candidate / 'TextView.java').read_text()
    root = (a.candidate / 'ViewRootImpl.java').read_text()
    methods = [method(text, 'public void setPlaySoundEffectEnable('),
               method(text, 'public boolean onKeyPreIme('),
               method(root, 'public void setPlayClickSound('),
               method(root, 'public void playSoundEffect(')]
    a.output.mkdir(parents=True)
    audio = a.output / 'android/media/AudioManager.java'
    audio.parent.mkdir(parents=True)
    audio.write_text('''package android.media;
public class AudioManager {
 public static final int FX_KEY_CLICK=0, FX_FOCUS_NAVIGATION_DOWN=4,
 FX_FOCUS_NAVIGATION_LEFT=1, FX_FOCUS_NAVIGATION_RIGHT=3, FX_FOCUS_NAVIGATION_UP=2;
 public int calls; public void playSoundEffect(int effect) { calls++; }
}
''')
    harness = '''import android.media.AudioManager;
public class SoundBehavior {
 static int checks;
 static void check(boolean b) { checks++; if (!b) throw new AssertionError("check " + checks); }
 static class KeyEvent {
  static final int KEYCODE_0=7, KEYCODE_DPAD_UP=19, KEYCODE_DPAD_CENTER=23,
    KEYCODE_BACK=4, ACTION_DOWN=0;
  int action; KeyEvent(int a) { action=a; } int getAction() { return action; }
 }
 static class Context {
  static final String AUDIO_SERVICE="audio";
  AudioManager audio=new AudioManager(); Object getSystemService(String s) { return audio; }
 }
 static class Parent { public boolean onKeyPreIme(int k, KeyEvent e) { return false; } }
 static class Text extends Parent {
  boolean mKaidroidPlaySoundEffectEnable=true, focused=true, editable=true,
    selectable=false, spannable=true, editor=false, backHandled=false;
  AudioManager mKaidroidAudioManager;
  Object mMovement=new Object(), mLayout=new Object();
  Context context=new Context(); Root root=new Root(context.audio);
  boolean onCheckIsTextEditor(){return editor;} boolean hasSpannableText(){return spannable;}
  boolean isTextEditable(){return editable;} boolean isTextSelectable(){return selectable;}
  boolean isFocused(){return focused;} Context getContext(){return context;}
  Root getViewRootImpl(){return root;}
  boolean handleBackInTextActionModeIfNeeded(KeyEvent e){return backHandled;}
  TEXT_METHODS
 }
 static class SoundEffectConstants {
  static final int CLICK=0,NAVIGATION_DOWN=4,NAVIGATION_LEFT=1,NAVIGATION_RIGHT=3,NAVIGATION_UP=2;
 }
 static class Log { static void e(String tag,String msg) {} }
 static class Root {
  boolean mKaidroidPlayClickSound=true; String mTag="test"; AudioManager audio;
  Root(AudioManager a){audio=a;} void checkThread(){} AudioManager getAudioManager(){return audio;}
  ROOT_METHODS
 }
 public static void main(String[] args) {
  for (boolean enabled:new boolean[]{true,false}) for(int action=0;action<2;action++)
   for(int key=0;key<=30;key++) {
    Text t=new Text();t.setPlaySoundEffectEnable(enabled);
    check(!t.onKeyPreIme(key,new KeyEvent(action)));
    boolean expected=action==0 && key>=7 && key<=22 && (enabled || key>=19);
    check(t.context.audio.calls==(expected?1:0));
    check(t.root.mKaidroidPlayClickSound!=expected);
   }
  for(int gate=0;gate<5;gate++) {
   Text t=new Text();
   if(gate==0)t.focused=false;if(gate==1)t.spannable=false;
   if(gate==2)t.mLayout=null;if(gate==3)t.editable=false;if(gate==4)t.mMovement=null;
   t.onKeyPreIme(7,new KeyEvent(0));check(t.context.audio.calls==0);
  }
  Text selectable=new Text();selectable.editable=false;selectable.selectable=true;
  selectable.onKeyPreIme(7,new KeyEvent(0));check(selectable.context.audio.calls==1);
  Text editor=new Text();editor.mMovement=null;editor.editor=true;
  editor.onKeyPreIme(7,new KeyEvent(0));check(editor.context.audio.calls==1);
  Text detached=new Text();detached.root=null;
  detached.onKeyPreIme(7,new KeyEvent(0));check(detached.context.audio.calls==1);
  Text back=new Text();back.backHandled=true;check(back.onKeyPreIme(4,new KeyEvent(0)));
  check(back.context.audio.calls==0);
  Text t=new Text();t.onKeyPreIme(7,new KeyEvent(0));
  t.root.playSoundEffect(0);check(t.context.audio.calls==1);
  t.root.playSoundEffect(0);check(t.context.audio.calls==2);
  t.root.setPlayClickSound(false);t.root.playSoundEffect(4);
  check(t.context.audio.calls==3);check(!t.root.mKaidroidPlayClickSound);
  t.root.playSoundEffect(0);check(t.context.audio.calls==3);
  t.root.playSoundEffect(0);check(t.context.audio.calls==4);
  boolean invalid=false;try{t.root.playSoundEffect(99);}catch(IllegalArgumentException e){invalid=true;}
  check(invalid);System.out.println(checks+" host behavior assertions passed");
 }
}
'''.replace('TEXT_METHODS', '\n'.join(methods[:2])).replace('ROOT_METHODS', '\n'.join(methods[2:]))
    java = a.output / 'SoundBehavior.java'
    java.write_text(harness)
    subprocess.run([str(a.jdk / 'bin/javac'), '-d', str(a.output), str(audio), str(java)], check=True)
    run = subprocess.run([str(a.jdk / 'bin/java'), '-cp', str(a.output), 'SoundBehavior'],
                         check=True, capture_output=True, text=True)
    report = dict(scope=__doc__, result=run.stdout.strip(),
                  candidate_sha256={n: hashlib.sha256((a.candidate / n).read_bytes()).hexdigest()
                                    for n in ('TextView.java', 'ViewRootImpl.java')},
                  harness_sha256=hashlib.sha256(java.read_bytes()).hexdigest(),
                  physical_parity=False)
    (a.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
