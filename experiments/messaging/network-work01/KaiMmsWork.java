package com.android.mms.transaction;

import android.app.Service;
import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.app.job.JobWorkItem;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.util.Log;
import java.util.HashSet;
import java.util.WeakHashMap;

/** Candidate: carry original TransactionService wakeups through a real OS job. */
public final class KaiMmsWork {
    public static final int JOB_ID = 0x4b440002;
    private static final String WORKER = "com.android.mms.transaction.TransactionService";
    private static final String BIND = "com.android.mms.action.KAI_BOOT_BIND";
    private static final WeakHashMap<Service, HashSet<Integer>> ISSUED = new WeakHashMap<>();
    // JobService, binding and completion callbacks are serialized on MAIN.
    private static Session active;

    private KaiMmsWork() {}

    public static void enqueue(Context context, Intent intent) {
        ComponentName expected = new ComponentName(context, WORKER);
        if (intent == null || !expected.equals(intent.getComponent())) {
            throw new IllegalArgumentException("Expected original MMS transaction intent");
        }
        JobScheduler scheduler = (JobScheduler) context.getSystemService(Context.JOB_SCHEDULER_SERVICE);
        JobInfo job = new JobInfo.Builder(JOB_ID,
                new ComponentName(context, "com.android.mms.transaction.MmsJobService"))
                .setOverrideDeadline(0).build();
        if (scheduler == null || scheduler.enqueue(job, new JobWorkItem(new Intent(intent)))
                != JobScheduler.RESULT_SUCCESS) {
            throw new IllegalStateException("MMS transaction work was not accepted by JobScheduler");
        }
    }

    public static boolean isJob(JobParameters parameters) { return parameters.getJobId() == JOB_ID; }

    public static void start(JobService service, JobParameters parameters) {
        if (!isJob(parameters) || active != null) throw new IllegalStateException("Duplicate or wrong MMS work job");
        Session session = new Session(service, parameters);
        active = session;
        session.begin();
    }

    public static void stop(JobService service, JobParameters parameters) {
        Session session = active;
        if (session != null && session.service == service && isJob(parameters)) {
            // No completeWork: the OS retains the in-flight item for redelivery.
            session.close(false, true);
        }
    }

    public static boolean watching(Service worker) {
        Session session = active;
        return session != null && !session.closed && session.worker == worker && session.current != null;
    }

    /** Event IDs remain eligible after cancellation until their actual idle callback. */
    public static boolean acceptCompletion(Service worker, int id) {
        synchronized (ISSUED) {
            HashSet<Integer> values = ISSUED.get(worker);
            boolean found = values != null && values.remove(id);
            if (values != null && values.isEmpty()) ISSUED.remove(worker);
            return found;
        }
    }

    /** Called only after the shared queue, running count and donor lists are idle. */
    public static void idle(Service worker) {
        Session session = active;
        if (session == null || session.closed || session.worker != worker || session.current == null) return;
        try {
            session.parameters.completeWork(session.current);
        } catch (IllegalArgumentException noLongerActive) {
            // The server may cancel/stop before its MAIN stop callback arrives.
            // Do not claim an acknowledgement: retain OS work and request retry.
            Log.w("KaiMmsWork", "Work acknowledgement rejected; requesting retry", noLongerActive);
            session.close(true, true);
            return;
        }
        acceptCompletion(worker, session.startId);
        session.current = session.parameters.dequeueWork();
        if (session.current == null) session.close(true, false);
        else session.dispatch();
    }

    private static final class Session implements ServiceConnection {
        final JobService service;
        final JobParameters parameters;
        JobWorkItem current;
        Service worker;
        int startId;
        boolean bound;
        boolean closed;

        Session(JobService service, JobParameters parameters) {
            this.service = service;
            this.parameters = parameters;
        }

        void begin() {
            current = parameters.dequeueWork();
            if (current == null) { close(true, false); return; }
            Intent binding = new Intent(BIND).setComponent(new ComponentName(service, WORKER));
            bound = service.bindService(binding, this, Context.BIND_AUTO_CREATE);
            if (!bound) { Log.e("KaiMmsWork", "Cannot bind original transaction worker"); close(true, true); }
        }

        void dispatch() {
            Intent work = current.getIntent();
            if (work == null || !new ComponentName(service, WORKER).equals(work.getComponent())) {
                throw new IllegalStateException("MMS queued intent identity changed");
            }
            startId = KaiBootRecovery.reserveWorkStartId();
            synchronized (ISSUED) {
                HashSet<Integer> values = ISSUED.get(worker);
                if (values == null) { values = new HashSet<>(); ISSUED.put(worker, values); }
                values.add(startId);
            }
            // Existing onStartCommand queues the unchanged original intent to handler5.
            worker.onStartCommand(new Intent(work), 0, startId);
        }

        @Override public void onServiceConnected(ComponentName name, IBinder binder) {
            if (closed) return;
            worker = KaiBootRecovery.boundWorker(binder);
            if (worker == null) { Log.e("KaiMmsWork", "Unexpected transaction binder"); close(true, true); return; }
            dispatch();
        }

        @Override public void onServiceDisconnected(ComponentName name) { close(true, true); }
        @Override public void onBindingDied(ComponentName name) { close(true, true); }
        @Override public void onNullBinding(ComponentName name) { close(true, true); }

        void close(boolean notifyScheduler, boolean retry) {
            if (closed) return;
            closed = true;
            if (active == this) active = null;
            if (bound) { bound = false; service.unbindService(this); }
            worker = null;
            if (notifyScheduler) service.jobFinished(parameters, retry);
        }
    }
}
