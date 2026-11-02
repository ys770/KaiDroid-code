package org.kaidroid.contacts;

import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.LongSupplier;

/** Non-UI loader for one SIM slot. Not wired to Contacts until a backend is supplied. */
public final class SimCapacityLoader implements AutoCloseable {
    public enum State { ABSENT, LOADING, READY, DENIED, UNSUPPORTED, FAILED, TIMED_OUT, CLOSED }

    /** Supply only six measured counts: total/used ADN, email, and ANR. */
    public interface Backend {
        int[] load(int subscriptionId) throws Exception;
    }

    public static final class Snapshot {
        public final State state;
        public final int subscriptionId;
        public final long generation;
        private final int[] counts;

        private Snapshot(State state, int subId, long generation, int[] counts) {
            this.state = state;
            this.subscriptionId = subId;
            this.generation = generation;
            this.counts = counts == null ? null : counts.clone();
        }

        /** Null means unavailable, not an empty phonebook. Never expose mutable cache data. */
        public int[] measuredCounts() { return counts == null ? null : counts.clone(); }
    }

    private final Backend backend;
    private final LongSupplier clock;
    private final long timeoutNanos;
    private final ExecutorService worker;
    private int subId = -1;
    private long cardGeneration;
    private long requestGeneration;
    private long started;
    private boolean scheduled;
    private boolean pending;
    private boolean closed;
    private Snapshot current = new Snapshot(State.ABSENT, -1, 0, null);

    public SimCapacityLoader(Backend backend, long timeoutNanos) {
        this(backend, timeoutNanos, System::nanoTime);
    }

    /** Clock injection permits deterministic timeout tests without sleeping. */
    public SimCapacityLoader(Backend backend, long timeoutNanos, LongSupplier clock) {
        if (backend == null || clock == null || timeoutNanos <= 0) {
            throw new IllegalArgumentException("Backend, monotonic clock and positive timeout required");
        }
        this.backend = backend;
        this.clock = clock;
        this.timeoutNanos = timeoutNanos;
        worker = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "KaiDroid-SimCapacity");
            thread.setDaemon(true);
            return thread;
        });
    }

    /** Caller changes cardGeneration on card replacement, even if the subId is reused. */
    public synchronized void select(int subscriptionId, long newCardGeneration) {
        ensureOpen();
        if (subscriptionId == subId && newCardGeneration == cardGeneration) return;
        subId = subscriptionId;
        cardGeneration = newCardGeneration;
        invalidate();
    }

    /** Explicit retry or refresh after a successful write; never call for every menu opening. */
    public synchronized void refresh() {
        ensureOpen();
        invalidate();
    }

    private void invalidate() {
        requestGeneration++;
        started = clock.getAsLong();
        pending = subId >= 0;
        current = new Snapshot(pending ? State.LOADING : State.ABSENT,
                subId, requestGeneration, null);
        if (pending && !scheduled) {
            scheduled = true;
            worker.execute(this::drain);
        }
    }

    public synchronized Snapshot snapshot() {
        if (current.state == State.LOADING && clock.getAsLong() - started >= timeoutNanos) {
            current = new Snapshot(State.TIMED_OUT, subId, requestGeneration, null);
        }
        return current;
    }

    private void drain() {
        while (true) {
            int requestedSub;
            long generation;
            synchronized (this) {
                if (closed || !pending) {
                    scheduled = false;
                    return;
                }
                pending = false;
                requestedSub = subId;
                generation = requestGeneration;
            }
            State state;
            int[] counts = null;
            try {
                counts = backend.load(requestedSub);
                validate(counts);
                counts = counts.clone();
                state = State.READY;
            } catch (SecurityException denied) {
                state = State.DENIED;
            } catch (UnsupportedOperationException unsupported) {
                state = State.UNSUPPORTED;
            } catch (Exception failure) {
                state = State.FAILED;
            } catch (LinkageError incompatibleBackend) {
                state = State.FAILED;
            }
            synchronized (this) {
                // Neither late responses nor old-card results may repopulate the cache.
                if (!closed && generation == requestGeneration) {
                    if (clock.getAsLong() - started >= timeoutNanos) {
                        state = State.TIMED_OUT;
                    }
                    current = new Snapshot(state, requestedSub, generation,
                            state == State.READY ? counts : null);
                }
            }
            // Only one running request and one coalesced pending generation, even if
            // Binder ignores interruption. A timeout does not spawn another worker.
        }
    }

    private static void validate(int[] values) {
        if (values == null || values.length != 6) {
            throw new IllegalArgumentException("Backend must return six measured counts");
        }
        for (int i = 0; i < 6; i += 2) {
            if (values[i] < 0 || values[i + 1] < 0 || values[i + 1] > values[i]) {
                throw new IllegalArgumentException("Invalid total/used pair: " + Arrays.toString(values));
            }
        }
    }

    private void ensureOpen() {
        if (closed) throw new IllegalStateException("Loader closed");
    }

    @Override public synchronized void close() {
        if (closed) return;
        closed = true;
        pending = false;
        requestGeneration++;
        current = new Snapshot(State.CLOSED, subId, requestGeneration, null);
        worker.shutdownNow();
    }
}
