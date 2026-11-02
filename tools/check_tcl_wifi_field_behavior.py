"""Compare donor and candidate Wi-Fi accessor Java behavior on a host JVM.

Runs extracted accessors and storage helpers with a HashMap and TextUtils
stand-in. Does not exercise Android parceling, supplicant, Wi-Fi service or HAL.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from check_tcl_keypad_sound_behavior import method


def body(source):
    signatures = ['private String removeDoubleQuotes(', 'private String convertToQuotedString(',
                  'private String getFieldValue(String ', 'private void setFieldValue(String ']
    signatures += ['public ' + typ + ' ' + name + '(' for typ, name in
                   [('String', 'getSimSlot'), ('String', 'getIsPresetAp'),
                    ('void', 'setSimSlot'), ('void', 'setIsPresetAp')]]
    return '\n'.join(method(source, signature) for signature in signatures)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('donor', 'candidate', 'output', 'jdk'):
        p.add_argument('--' + key, type=Path, required=True)
    a = p.parse_args()
    fields = '''
      final HashMap<String,String> mFields=new HashMap<>();
      static final String EMPTY_VALUE="NULL";
      static final List<String> UNQUOTED_KEYS=Arrays.asList("engine","proactive_key_caching","eap_erp");
    '''
    source = '''import java.util.*;
public class WifiFieldBehavior {
 static class TextUtils { static boolean isEmpty(String s){return s==null||s.isEmpty();} }
 static class Donor { FIELDS DONOR }
 static class Candidate { FIELDS CANDIDATE }
 static int checks;
 static void check(boolean b){checks++;if(!b)throw new AssertionError("check "+checks);}
 public static void main(String[] args){
  String[] keys={null,"sim_num","sim_slot","preset_ap","engine","proactive_key_caching","eap_erp","identity"};
  String[] values={null,"","0","1","NULL","a b","\\\"quoted\\\"","é漢字","a\\nb"};
  for(String key:keys){
   Donor d=new Donor();Candidate c=new Candidate();
   check(d.getSimSlot(key).equals(c.getSimSlot(key)));
   for(String value:values){
    d.setSimSlot(key,value);c.setSimSlot(key,value);
    check(d.mFields.equals(c.mFields));check(d.getSimSlot(key).equals(c.getSimSlot(key)));
    check(d.getIsPresetAp(key).equals(c.getIsPresetAp(key)));
    d.setIsPresetAp(key,value);c.setIsPresetAp(key,value);
    check(d.mFields.equals(c.mFields));check(d.getIsPresetAp(key).equals(c.getIsPresetAp(key)));
   }
  }
  Candidate c=new Candidate();c.setSimSlot("sim_num","1");c.setIsPresetAp("preset","yes");
  check(c.getSimSlot("sim_num").equals("1"));check(c.getIsPresetAp("preset").equals("yes"));
  c.setSimSlot("sim_num",null);check(c.getSimSlot("sim_num").equals(""));
  check(c.getIsPresetAp("preset").equals("yes"));
  System.out.println(checks+" donor/candidate field assertions passed");
 }
}
'''.replace('FIELDS', fields).replace('DONOR', body(a.donor.read_text())).replace('CANDIDATE', body(a.candidate.read_text()))
    a.output.mkdir(parents=True)
    java = a.output / 'WifiFieldBehavior.java'
    java.write_text(source, encoding='utf-8')
    subprocess.run([str(a.jdk / 'bin/javac'), '-encoding', 'UTF-8', '-d', str(a.output), str(java)], check=True)
    run = subprocess.run([str(a.jdk / 'bin/java'), '-cp', str(a.output), 'WifiFieldBehavior'], check=True, capture_output=True, text=True)
    report = dict(scope=__doc__, result=run.stdout.strip(),
                  donor_source_sha256=hashlib.sha256(a.donor.read_bytes()).hexdigest(),
                  candidate_sha256=hashlib.sha256(a.candidate.read_bytes()).hexdigest(),
                  harness_sha256=hashlib.sha256(java.read_bytes()).hexdigest(), physical_parity=False)
    (a.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
