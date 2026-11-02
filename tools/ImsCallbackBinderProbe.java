import android.os.Binder;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import android.telephony.ims.ImsStreamMediaProfile;
import android.telephony.ims.aidl.IImsCallSessionListener;
import dalvik.system.DexClassLoader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/** Isolated same-process real AIDL proxy/Parcel test, not IMS registration. */
public final class ImsCallbackBinderProbe {
    static final String NAME = "android.telephony.ims.ImsCallSessionListener";
    static final String DESCRIPTOR = "android.telephony.ims.aidl.IImsCallSessionListener";

    static final class Loader extends DexClassLoader {
        Loader(String path, String cache) {
            super(path, cache, null, ImsCallbackBinderProbe.class.getClassLoader());
        }
        @Override protected synchronized Class<?> loadClass(String name, boolean resolve)
                throws ClassNotFoundException {
            if (!NAME.equals(name)) return super.loadClass(name, resolve);
            Class<?> c = findLoadedClass(name);
            if (c == null) c = findClass(name);
            if (resolve) resolveClass(c);
            return c;
        }
    }

    static final class Receiver extends Binder {
        final int expectedCode;
        int calls;
        boolean receiving;
        Receiver(int code) { expectedCode = code; }
        @Override public IInterface queryLocalInterface(String descriptor) { return null; }
        @Override protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                throws RemoteException {
            if (code != expectedCode) throw new AssertionError("Unexpected transaction " + code);
            if ((flags & IBinder.FLAG_ONEWAY) == 0) throw new AssertionError("Expected oneway");
            data.enforceInterface(DESCRIPTOR);
            if (data.readInt() != 1) throw new AssertionError("Missing profile");
            ImsStreamMediaProfile profile = ImsStreamMediaProfile.CREATOR.createFromParcel(data);
            if (data.dataAvail() != 0) throw new AssertionError("Trailing parcel data");
            receiving = profile.isReceivingRttAudio();
            calls++;
            return true;
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("original.dex.jar candidate.dex.jar cache");
        Class<?> baseline = new Loader(args[0], args[2]).loadClass(NAME);
        try {
            baseline.getMethod("callSessionPropertyChanged", int.class);
            throw new AssertionError("Baseline unexpectedly has callback");
        } catch (NoSuchMethodException expected) {
            System.out.println("BASELINE_MISSING_CALLBACK_PASS");
        }
        Class<?> candidate = new Loader(args[1], args[2]).loadClass(NAME);
        if (candidate.getClassLoader() == baseline.getClassLoader()
                || candidate.getClassLoader() == ImsStreamMediaProfile.class.getClassLoader()) {
            throw new AssertionError("Candidate class-loader isolation failed");
        }
        Field transaction = IImsCallSessionListener.Stub.class.getDeclaredField(
                "TRANSACTION_callSessionRttAudioIndicatorChanged");
        transaction.setAccessible(true);
        Receiver receiver = new Receiver(transaction.getInt(null));
        IImsCallSessionListener proxy = IImsCallSessionListener.Stub.asInterface(receiver);
        if (!proxy.getClass().getName().endsWith("$Stub$Proxy")) {
            throw new AssertionError("AIDL proxy bypassed");
        }
        Object listener = candidate.getConstructor(IImsCallSessionListener.class).newInstance(proxy);
        Method method = candidate.getMethod("callSessionPropertyChanged", int.class);
        int count = 0;
        for (int value : new int[]{0, 1, 0, 1}) {
            method.invoke(listener, value);
            count++;
            if (receiver.calls != count || receiver.receiving != (value == 1)) {
                throw new AssertionError("Callback value/count mismatch");
            }
            System.out.println("PARCEL_CALLBACK_PASS value=" + value + " calls=" + receiver.calls);
        }
        System.out.println("PASS same-process AIDL proxy and real Parcel; no remote Binder or IMS claim");
    }
}
