"""Compile and exercise the actual generated handler against narrow service fakes.

Does not model Android's upstream preprocessing, real telecom, timers or display.
"""
import argparse
import subprocess
from pathlib import Path
from prepare_power_endcall import HANDLER

PREFIX = r'''
public class PowerPolicyBranchTest {
 static class KeyEvent {
  static final int FLAG_FALLBACK=1024;
  int flags; long getDownTime(){return 100;} long getEventTime(){return 200;}
  int getFlags(){return flags;}
 }
 static class AudioManager { static final int FX_KEY_CLICK=0; void playSoundEffect(int n){} }
 static class Context { <T> T getSystemService(Class<T> c){return c.cast(new AudioManager());} }
 static class TelecomManager { boolean hangup; int attempts; boolean endCall(){attempts++;return hangup;} }
 static class Settings { static class System { static final int END_BUTTON_BEHAVIOR_HOME=1,END_BUTTON_BEHAVIOR_SLEEP=2;} }
 static class PowerManager {static final int GO_TO_SLEEP_REASON_POWER_BUTTON=4;}
 static class Handler {
  Runnable pending; long delay; int removed;
  void postDelayed(Runnable r,long d){pending=r;delay=d;}
  void removeCallbacks(Runnable r){if(pending==r)pending=null;removed++;}
 }
 final Context mContext=new Context(); final Handler mHandler=new Handler();
 TelecomManager telecom=new TelecomManager();
 boolean mEndCallKeyHandled,mPowerKeyHandled,mScreenshotChordPowerKeyTriggered;
 boolean mScreenshotChordVolumeDownKeyTriggered,mA11yShortcutChordVolumeUpKeyTriggered;
 long mScreenshotChordPowerKeyTime; int mEndcallBehavior=1,homes,sleeps,menus,chords;
 boolean screenOn=true,homeResult=true;
 final Runnable mEndCallLongPress=()->{mEndCallKeyHandled=true;menus++;};
 TelecomManager getTelecommService(){return telecom;}
 boolean isScreenOn(){return screenOn;}
 boolean goHome(){homes++;return homeResult;}
 void goToSleep(long t,int r,int flags){sleeps++;}
 void interceptScreenshotChord(){chords++;}
 static final int ACTION_PASS_TO_USER=1;
 boolean dispatch(boolean down,boolean interactive,boolean canceled,KeyEvent event){
  boolean kaiDroidPowerEndCall=true,isWakeKey=false;int result=1;
  switch(6){case 6:{
'''
SUFFIX = r'''
  }} return isWakeKey;
 }
 static int assertions;
 static void check(boolean v,String message){assertions++;if(!v)throw new AssertionError(message);}
 public static void main(String[] a){
  KeyEvent e=new KeyEvent();
  PowerPolicyBranchTest p=new PowerPolicyBranchTest();
  p.dispatch(true,true,false,e);check(p.mHandler.delay==2500,"2500ms timer");
  p.dispatch(false,true,false,e);check(p.homes==1&&p.sleeps==0,"short release home");
  check(p.mHandler.pending==null&&!p.mScreenshotChordPowerKeyTriggered,"release cleanup");
  p=new PowerPolicyBranchTest();p.dispatch(true,true,false,e);p.dispatch(false,true,true,e);
  check(p.homes==0&&p.sleeps==0&&p.mHandler.pending==null,"canceled release");
  p=new PowerPolicyBranchTest();p.telecom.hangup=true;p.dispatch(true,true,false,e);p.dispatch(false,true,false,e);
  check(p.telecom.attempts==1&&p.homes==0&&p.sleeps==0,"call ended without home or sleep");
  p=new PowerPolicyBranchTest();p.dispatch(true,true,false,e);p.mHandler.pending.run();p.dispatch(false,true,false,e);
  check(p.menus==1&&p.homes==0,"long press menu consumes release");
  p=new PowerPolicyBranchTest();p.screenOn=false;check(p.dispatch(true,false,false,e),"offscreen wake");
  p.dispatch(false,true,false,e);check(p.homes==0&&p.mHandler.pending==null,"wake release no home");
  p=new PowerPolicyBranchTest();p.mScreenshotChordVolumeDownKeyTriggered=true;p.dispatch(true,true,false,e);p.dispatch(false,true,false,e);
  check(p.telecom.attempts==0&&p.homes==0,"screenshot suppresses hangup and home");
  p=new PowerPolicyBranchTest();p.mA11yShortcutChordVolumeUpKeyTriggered=true;p.dispatch(true,true,false,e);p.dispatch(false,true,false,e);
  check(p.homes==0,"accessibility handled release");
  p=new PowerPolicyBranchTest();e.flags=1024;p.dispatch(true,true,false,e);check(p.chords==0,"fallback does not latch screenshot");e.flags=0;
  p=new PowerPolicyBranchTest();p.mEndcallBehavior=2;p.dispatch(true,true,false,e);p.dispatch(false,true,false,e);check(p.sleeps==1&&p.homes==0,"sleep bit remains explicit");
  p=new PowerPolicyBranchTest();p.mEndcallBehavior=3;p.dispatch(true,true,false,e);p.dispatch(false,true,false,e);check(p.homes==1&&p.sleeps==0,"successful home wins");
  p=new PowerPolicyBranchTest();p.mEndcallBehavior=3;p.homeResult=false;p.dispatch(true,true,false,e);p.dispatch(false,true,false,e);check(p.homes==1&&p.sleeps==1,"failed home falls through");
  System.out.println("PASS "+assertions+" handler assertions");
 }
}
'''

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    source = a.output / 'PowerPolicyBranchTest.java'
    source.write_text(PREFIX + HANDLER + SUFFIX)
    subprocess.run(['javac', '--release', '8', '-d', str(a.output), str(source)], check=True)
    subprocess.run(['java', '-cp', str(a.output), 'PowerPolicyBranchTest'], check=True)
