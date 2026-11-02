"""Build a permission-free, owned 1 MiB content-URI Bluetooth sender fixture."""
import argparse, hashlib, json, os, subprocess, zipfile
from pathlib import Path

PACKAGE = 'org.kaidroid.bluetoothpayload'
NAME = 'KaiDroid-BT-Large60.txt'
MANIFEST = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.kaidroid.bluetoothpayload">
<uses-sdk android:minSdkVersion="30" android:targetSdkVersion="30"/>
<application android:label="Owned Bluetooth test" android:debuggable="true">
<activity android:name=".SendActivity" android:exported="true"/>
<provider android:name=".PayloadProvider" android:authorities="org.kaidroid.bluetoothpayload.file" android:exported="false" android:grantUriPermissions="true"/>
</application></manifest>'''
ACTIVITY = '''package org.kaidroid.bluetoothpayload;
import android.app.Activity; import android.os.Bundle; import android.content.*; import android.net.Uri;
public final class SendActivity extends Activity {
 public void onCreate(Bundle b) { super.onCreate(b); if(b!=null)return;
 Uri u=Uri.parse("content://org.kaidroid.bluetoothpayload.file/payload");
 Intent i=new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_STREAM,u);
 i.setClipData(ClipData.newRawUri("Owned 1 MiB test payload",u));
 i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
 i.setComponent(new ComponentName("com.android.bluetooth","com.android.bluetooth.opp.BluetoothOppLauncherActivity"));
 startActivity(i); finish(); }
}'''
PROVIDER = '''package org.kaidroid.bluetoothpayload;
import android.content.*; import android.database.*; import android.net.Uri;
import android.os.ParcelFileDescriptor; import android.provider.OpenableColumns; import java.io.*;
public final class PayloadProvider extends ContentProvider {
 private static final String NAME="KaiDroid-BT-Large60.txt";
 private void check(Uri u){if(!u.toString().equals("content://org.kaidroid.bluetoothpayload.file/payload"))throw new IllegalArgumentException();}
 public boolean onCreate(){return true;}
 public String getType(Uri u){check(u);return "text/plain";}
 public Cursor query(Uri u,String[] p,String s,String[] a,String o){check(u);
 if(p==null)p=new String[]{OpenableColumns.DISPLAY_NAME,OpenableColumns.SIZE};
 MatrixCursor c=new MatrixCursor(p);Object[] row=new Object[p.length];
 for(int n=0;n<p.length;n++){if(p[n].equals(OpenableColumns.DISPLAY_NAME))row[n]=NAME;
 else if(p[n].equals(OpenableColumns.SIZE))row[n]=1048576L;else if(p[n].equals("mime_type"))row[n]="text/plain";}
 c.addRow(row);return c;}
 public synchronized ParcelFileDescriptor openFile(Uri u,String mode)throws FileNotFoundException{check(u);
 if(!mode.equals("r"))throw new FileNotFoundException("Read only");
 File f=new File(getContext().getFilesDir(),NAME);
 try{if(!f.exists()){try(InputStream in=getContext().getAssets().open(NAME);OutputStream out=new FileOutputStream(f)){
 byte[] buf=new byte[8192];int n;while((n=in.read(buf))!=-1)out.write(buf,0,n);}}
 if(f.length()!=1048576L)throw new IOException("Wrong length");
 return ParcelFileDescriptor.open(f,ParcelFileDescriptor.MODE_READ_ONLY);
 }catch(IOException e){throw new FileNotFoundException(e.toString());}}
 public Uri insert(Uri u,ContentValues v){throw new UnsupportedOperationException();}
 public int update(Uri u,ContentValues v,String w,String[] a){throw new UnsupportedOperationException();}
 public int delete(Uri u,String w,String[] a){throw new UnsupportedOperationException();}
}'''

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('sdk','jdk','payload','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();data=a.payload.read_bytes()
 if len(data)!=1048576 or hashlib.sha256(data).hexdigest()!='1c5e0054af4f8477470cdf44d82a290b5e70b542e144e3c7537e8b4e7d74c67d':raise ValueError('Wrong synthetic payload')
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 for d in ('src','classes','dex','assets'):(out/d).mkdir()
 (out/'AndroidManifest.xml').write_text(MANIFEST)
 for name,source in [('SendActivity',ACTIVITY),('PayloadProvider',PROVIDER)]:(out/'src'/(name+'.java')).write_text(source)
 (out/'assets'/NAME).write_bytes(data)
 bt=a.sdk.resolve()/'build-tools/35.0.0';android=a.sdk.resolve()/'platforms/android-30/android.jar';jdk=a.jdk.resolve()
 env=os.environ.copy();env['JAVA_HOME']=str(jdk);env['PATH']=str(jdk/'bin')+os.pathsep+env['PATH']
 def run(args):
  r=subprocess.run(list(map(str,args)),capture_output=True,text=True,env=env,timeout=120)
  with (out/'build.log').open('a') as log:log.write(r.stdout+r.stderr)
  r.check_returncode();return r.stdout
 run([bt/'aapt.exe','package','-f','-M',out/'AndroidManifest.xml','-A',out/'assets','-I',android,'-F',out/'unsigned.apk'])
 run([jdk/'bin/javac.exe','--release','8','-classpath',android,'-d',out/'classes',*sorted((out/'src').glob('*.java'))])
 run([jdk/'bin/java.exe','-cp',bt/'lib/d8.jar','com.android.tools.r8.D8','--min-api','30','--lib',android,'--output',out/'dex',*sorted((out/'classes').rglob('*.class'))])
 with zipfile.ZipFile(out/'unsigned.apk','a',compression=zipfile.ZIP_DEFLATED) as z:z.write(out/'dex/classes.dex','classes.dex')
 run([bt/'zipalign.exe','-f','4',out/'unsigned.apk',out/'aligned.apk'])
 key=out/'diagnostic.p12'
 run([jdk/'bin/keytool.exe','-genkeypair','-keystore',key,'-storepass','android','-keypass','android','-alias','diagnostic','-dname','CN=KaiDroid Diagnostic','-keyalg','RSA','-keysize','2048','-validity','3650','-noprompt'])
 signer=[jdk/'bin/java.exe','-jar',bt/'lib/apksigner.jar'];apk=out/'sender.apk'
 run([*signer,'sign','--ks',key,'--ks-pass','pass:android','--out',apk,out/'aligned.apk'])
 run([*signer,'verify','--verbose',apk]);run([bt/'zipalign.exe','-c','4',apk])
 report=dict(package=PACKAGE,apk_sha256=hashlib.sha256(apk.read_bytes()).hexdigest(),payload_sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),requested_permissions=[],provider_exported=False,grant_read_only=True,installed=False)
 (out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))

if __name__=='__main__':main()
