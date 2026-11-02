import java.lang.reflect.*;
import java.nio.file.*;
import android.os.IBinder;
public class RadioMode55 {
 static void require(boolean ok,String why){if(!ok)throw new IllegalStateException(why);}
 static String prop(String name)throws Exception{return (String)Class.forName("android.os.SystemProperties").getMethod("get",String.class).invoke(null,name);}
 public static void main(String[] a)throws Exception{
  require(a.length==2,"Expected boot ID and read|lte|restore");
  require(android.os.Process.myUid()==0,"Root required");
  require(prop("ro.serialno").equals("DEVICE_SERIAL_REQUIRED")&&prop("ro.kaidroid.image").equals("55"),"Wrong handset/image");
  require(new String(Files.readAllBytes(Paths.get("/proc/sys/kernel/random/boot_id"))).trim().equals(a[0]),"Boot changed");
  require(prop("gsm.sim.state").equals("LOADED"),"SIM not loaded");
  IBinder sb=(IBinder)Class.forName("android.os.ServiceManager").getMethod("getService",String.class).invoke(null,"isub");
  Object sub=Class.forName("com.android.internal.telephony.ISub$Stub").getMethod("asInterface",IBinder.class).invoke(null,sb);
  int id=(Integer)Class.forName("com.android.internal.telephony.ISub").getMethod("getDefaultSubId").invoke(sub);
  System.out.println("default_subscription="+id);
  require(id==1,"Subscription changed");
  IBinder binder=(IBinder)Class.forName("android.os.ServiceManager").getMethod("getService",String.class).invoke(null,"phone");
  require(binder!=null,"No phone binder");
  Object phone=Class.forName("com.android.internal.telephony.ITelephony$Stub").getMethod("asInterface",IBinder.class).invoke(null,binder);
  Class<?> api=Class.forName("com.android.internal.telephony.ITelephony");
  Method get=api.getMethod("getPreferredNetworkType",int.class);
  int before=(Integer)get.invoke(phone,id);
  System.out.println("before="+before+" subscription="+id);
  if(a[1].equals("read"))return;
  require(a[1].equals("lte")||a[1].equals("restore"),"Invalid action");
  int expected=a[1].equals("lte")?0:9,target=a[1].equals("lte")?9:0;
  require(before==expected,"Unexpected current mode; no write");
  boolean result=(Boolean)api.getMethod("setPreferredNetworkType",int.class,int.class).invoke(phone,id,target);
  System.out.println("set_result="+result+" requested="+target);
  require(result,"API rejected mode; do not automatically retry");
  int after=(Integer)get.invoke(phone,id);System.out.println("after="+after);require(after==target,"Readback mismatch");
 }
}
