package com.android.mms.transaction;

import android.app.Service;
import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Binder;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Log;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.WeakHashMap;

/** Boot-only lifecycle bridge. Ordinary started-service and wakelock paths stay intact. */
public final class KaiBootRecovery {
    // Separate from the donor's incrementing push-job IDs (which begin at two).
    public static final int JOB_ID = 0x4b440001;
    private static final AtomicInteger NEXT_START_ID = new AtomicInteger(Integer.MIN_VALUE);
    private static final String ACTION = "com.android.mms.action.KAI_BOOT_BIND";
    private static final String PREFIX = "com.android.mms.transaction.";
    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static volatile Session active;
    private static final WeakHashMap<Service, MmsState> MMS = new WeakHashMap<>();

    /** Implemented by the existing worker without replacing its recovery code. */
    public interface MmsWorker {
        void onNewIntent(Intent intent, int startId);
        boolean kaiBootIsIdle();
    }

    private static final class MmsState {
        int queued;
        int running;
        long revision;
        boolean idleRequested;
    }

    private static MmsState state(Service service) {
        MmsState value = MMS.get(service);
        if (value == null) { value = new MmsState(); MMS.put(service, value); }
        return value;
    }

    /** Runs on MAIN before the donor enqueues handler message5, including normal starts. */
    public static void mmsCommandQueued(Service service) {
        synchronized (MMS) {
            MmsState value = state(service);
            value.queued++; value.revision++; value.idleRequested = false;
        }
    }

    /** Wraps only message5's existing onNewIntent call, with exception-safe accounting. */
    public static void dispatchMms(Service service, Intent intent, int startId) {
        synchronized (MMS) {
            MmsState value = state(service);
            if (value.queued <= 0) throw new IllegalStateException("Unaccounted MMS command");
            value.queued--; value.running++; value.revision++; value.idleRequested = false;
        }
        boolean completed = false;
        try {
            ((MmsWorker) service).onNewIntent(intent, startId);
            completed = true;
        } finally {
            synchronized (MMS) {
                MmsState value = state(service);
                value.running--; value.revision++;
                if (!completed) value.idleRequested = false;
            }
            if (completed) checkMmsCompletion(service);
        }
    }

    private KaiBootRecovery() {}

    public static void schedule(Context context) {
        JobScheduler scheduler = (JobScheduler) context.getSystemService(Context.JOB_SCHEDULER_SERVICE);
        JobInfo job = new JobInfo.Builder(JOB_ID,
                new ComponentName(context, PREFIX + "MmsJobService"))
                .setOverrideDeadline(0).build();
        if (scheduler.schedule(job) != JobScheduler.RESULT_SUCCESS) {
            throw new IllegalStateException("Messaging boot recovery could not be scheduled");
        }
    }

    public static boolean isBootJob(JobParameters parameters) {
        return parameters.getJobId() == JOB_ID;
    }

    /** Called only by the existing, permission-protected MmsJobService. */
    public static void start(JobService service, JobParameters parameters) {
        if (active != null) throw new IllegalStateException("Duplicate Messaging boot job");
        Session session = new Session(service, parameters);
        active = session;
        session.begin();
    }

    /** JobScheduler owns the CPU wake lock; stopping unbinds workers and requests retry. */
    public static void stop(JobService service, JobParameters parameters) {
        Session session = active;
        if (session != null && session.service == service && isBootJob(parameters)) {
            session.close(false, true);
        }
    }

    public static IBinder binder(Service service, Intent intent) {
        return intent != null && ACTION.equals(intent.getAction()) ? new WorkerBinder(service) : null;
    }

    /** Replaces the two existing TransactionService stopSelf(int) call sites. */
    public static void stopMms(Service service, int startId) {
        // These sites mean no pending/processing transactions, or no longer default SMS.
        Session session = active;
        if (startId >= 0 || (session != null && session.startId == startId)) {
            synchronized (MMS) {
                MmsState value = state(service);
                value.idleRequested = true; value.revision++;
            }
            checkMmsCompletion(service);
        }
        if (startId >= 0) service.stopSelf(startId);
    }

    private static void checkMmsCompletion(Service worker) {
        Session session = active;
        if (session == null) return;
        MAIN.post(() -> {
            if (active != session || session.connections[0].worker != worker) return;
            long revision;
            synchronized (MMS) {
                MmsState value = state(worker);
                if (!value.idleRequested || value.queued != 0 || value.running != 0) return;
                revision = value.revision;
            }
            // Never hold MMS's accounting monitor while taking the donor's
            // mProcessing monitor: stopSelfIfIdle takes those in the opposite order.
            if (!((MmsWorker) worker).kaiBootIsIdle()) return;
            synchronized (MMS) {
                MmsState value = state(worker);
                if (revision != value.revision || !value.idleRequested
                        || value.queued != 0 || value.running != 0) return;
            }
            // onStartCommand and binding release share MAIN, so another start
            // cannot enter between this validation and the release.
            session.complete(worker);
        });
    }

    /** Reserved dispatch never acquired SmsReceiver's legacy startup wakelock. */
    public static boolean finishSms(Service service, int startId) {
        if (startId >= 0) return false;
        complete(service, startId);
        return true;
    }

    private static void complete(Service worker, int startId) {
        Session session = active;
        if (session == null) return;
        MAIN.post(() -> {
            if (session != null && active == session
                    && (startId >= 0 || startId == session.startId)) session.complete(worker);
        });
    }

    private static final class WorkerBinder extends Binder {
        final Service service;
        WorkerBinder(Service service) { this.service = service; }
    }

    private static final class Session {
        final JobService service;
        final JobParameters parameters;
        final int startId = NEXT_START_ID.getAndIncrement();
        final Connection[] connections;
        boolean closed;

        Session(JobService service, JobParameters parameters) {
            this.service = service;
            this.parameters = parameters;
            connections = new Connection[] {
                new Connection("TransactionService", new Intent()),
                new Connection("SmsReceiverService", new Intent(Intent.ACTION_BOOT_COMPLETED))
            };
        }

        void begin() {
            for (Connection connection : connections) {
                if (closed) return;
                Intent binding = new Intent(ACTION).setComponent(connection.component);
                connection.bound = service.bindService(binding, connection, Context.BIND_AUTO_CREATE);
                if (!connection.bound) {
                    Log.e("KaiBootRecovery", "Cannot bind " + connection.component);
                    close(true, true);
                    return;
                }
            }
        }

        void complete(Service worker) {
            if (closed) return;
            for (Connection connection : connections) {
                if (connection.worker == worker && !connection.done) {
                    connection.done = true;
                    connection.unbind();
                }
            }
            if (connections[0].done && connections[1].done) close(true, false);
        }

        void close(boolean notifyScheduler, boolean retry) {
            if (closed) return;
            closed = true;
            if (active == this) active = null;
            for (Connection connection : connections) connection.unbind();
            if (notifyScheduler) service.jobFinished(parameters, retry);
        }

        final class Connection implements ServiceConnection {
            final ComponentName component;
            final Intent work;
            Service worker;
            boolean bound;
            boolean done;

            Connection(String name, Intent work) {
                component = new ComponentName(service, PREFIX + name);
                this.work = work.setComponent(component);
            }

            @Override public void onServiceConnected(ComponentName name, IBinder binder) {
                if (closed || done) return;
                if (!(binder instanceof WorkerBinder)) {
                    Log.e("KaiBootRecovery", "Unexpected worker binder: " + name);
                    close(true, true);
                    return;
                }
                worker = ((WorkerBinder) binder).service;
                // Keep the original handlers, pending-message queries, retry alarms and
                // SMS boot recovery. Binding supplies the lifecycle without startService.
                worker.onStartCommand(work, 0, startId);
            }

            @Override public void onServiceDisconnected(ComponentName name) { close(true, true); }
            @Override public void onBindingDied(ComponentName name) { close(true, true); }
            @Override public void onNullBinding(ComponentName name) { close(true, true); }

            void unbind() {
                if (bound) {
                    bound = false;
                    service.unbindService(this);
                }
                worker = null;
            }
        }
    }
}
