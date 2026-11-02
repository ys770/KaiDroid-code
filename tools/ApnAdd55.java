import android.content.*;
import android.database.Cursor;
import android.net.Uri;
import android.os.Looper;
import java.nio.file.*;
public class ApnAdd55 {
 static void require(boolean b,String m){if(!b)throw new IllegalStateException(m);}
 static String prop(String n)throws Exception{return (String)Class.forName("android.os.SystemProperties").getMethod("get",String.class).invoke(null,n);}
 public static void main(String[] a)throws Exception{
  require(a.length==1&&android.os.Process.myUid()==0,"Boot argument/root required");
  require(prop("ro.serialno").equals("DEVICE_SERIAL_REQUIRED")&&prop("ro.kaidroid.image").equals("55"),"Wrong handset/image");
  require(new String(Files.readAllBytes(Paths.get("/proc/sys/kernel/random/boot_id"))).trim().equals(a[0]),"Boot changed");
  require(prop("gsm.sim.operator.numeric").equals("310240"),"SIM operator changed");
  Class<?> amType=Class.forName("android.app.IActivityManager");
  Object am=Class.forName("android.app.ActivityManager").getMethod("getService").invoke(null);
  android.os.IBinder token=new android.os.Binder();
  Object holder=amType.getMethod("getContentProviderExternal",String.class,int.class,android.os.IBinder.class,String.class).invoke(am,"telephony",0,token,"KaiDroidAPN55");
  require(holder!=null,"No provider holder");Object provider=holder.getClass().getField("provider").get(holder);
  Class<?> api=Class.forName("android.content.IContentProvider");
  java.lang.reflect.Method query=api.getMethod("query",String.class,String.class,Uri.class,String[].class,android.os.Bundle.class,Class.forName("android.os.ICancellationSignal"));
  Uri table=Uri.parse("content://telephony/carriers");
  try {
  try(Cursor before=(Cursor)query.invoke(provider,"com.android.shell",null,table,new String[]{"_id"},null,null)){require(before!=null&&before.getCount()==0,"APN table not empty; no insert");}
  ContentValues v=new ContentValues();
  String[][] rows={{"name","T-Mobile US 240"},{"mcc","310"},{"mnc","240"},{"numeric","310240"},{"apn","fast.t-mobile.com"},{"type","default,supl,hipri,xcap,mms"},{"mmsc","http://mms.msg.eng.t-mobile.com/mms/wapenc"},{"protocol","IPV6"},{"roaming_protocol","IP"}};
  for(String[] row:rows)v.put(row[0],row[1]);v.put("carrier_enabled",1);v.put("user_visible",1);v.put("user_editable",1);
  Uri inserted=(Uri)api.getMethod("insert",String.class,String.class,Uri.class,ContentValues.class,android.os.Bundle.class).invoke(provider,"com.android.shell",null,table,v,null);require(inserted!=null,"No inserted URI; inspect before retry");System.out.println("inserted="+inserted);
  try(Cursor after=(Cursor)query.invoke(provider,"com.android.shell",null,inserted,new String[]{"_id","apn","numeric","mmsc","protocol"},null,null)){
   require(after!=null&&after.moveToFirst()&&after.getCount()==1,"Row readback failed");
   require(after.getString(1).equals("fast.t-mobile.com")&&after.getString(2).equals("310240")&&after.getString(3).equals(v.getAsString("mmsc"))&&after.getString(4).equals("IPV6"),"Row mismatch");System.out.println("verified_id="+after.getLong(0));
  }
  } finally {amType.getMethod("removeContentProviderExternal",String.class,android.os.IBinder.class).invoke(am,"telephony",token);}
  System.exit(0);
 }
}
