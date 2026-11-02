import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Map;
import org.json.JSONObject;

/** Synthetic allocation churn, not a UI/startup or hardware acceptance test. */
public final class HeapSlackProbe {
    private static volatile byte[][] retained;
    private static volatile int checksum;
    private static JSONObject runtimeStats() throws Exception {
        return new JSONObject((Map<?, ?>) Class.forName("dalvik.system.VMDebug")
            .getMethod("getRuntimeStats").invoke(null));
    }
    private static long cpuTicks() throws Exception {
        String stat = new String(Files.readAllBytes(Paths.get("/proc/self/stat")));
        String[] fields = stat.substring(stat.lastIndexOf(')')+2).trim().split("\\s+");
        return Long.parseLong(fields[11])+Long.parseLong(fields[12]);
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("image boot");
        String boot = new String(Files.readAllBytes(
            Paths.get("/proc/sys/kernel/random/boot_id"))).trim();
        if (!args[1].equals(boot)) throw new IllegalStateException("Wrong boot");
        // Host runner must check image before launching. Avoid AndroidRuntime
        // native dependencies so dalvikvm can receive truly process-local flags.
        // 8 MiB live data, then 64 MiB churn per round. Touch every page.
        retained = new byte[128][];
        for (int i=0;i<retained.length;i++) retained[i]=new byte[65536];
        long[] times = new long[12];
        JSONObject before = runtimeStats();
        long cpu = cpuTicks();
        long maxUsed = 0;
        for (int round=0;round<times.length;round++) {
            long begin=System.nanoTime();
            for (int i=0;i<1024;i++) {
                byte[] value = new byte[65536];
                for (int j=0;j<value.length;j+=4096) value[j]=(byte)(i+round);
                retained[i % retained.length]=value;
                checksum += value[(i % 16)*4096];
                Runtime rt=Runtime.getRuntime();
                maxUsed=Math.max(maxUsed,rt.totalMemory()-rt.freeMemory());
            }
            times[round]=System.nanoTime()-begin;
        }
        long ticks=cpuTicks()-cpu;
        JSONObject after = runtimeStats();
        String smaps = new String(Files.readAllBytes(Paths.get("/proc/self/smaps_rollup")));
        long[] sorted=times.clone(); Arrays.sort(sorted);
        System.out.println(new JSONObject().put("boot",boot).put("image",args[0])
            .put("rounds",12).put("churn_bytes_per_round",67108864)
            .put("p50_round_ms",(sorted[5]+sorted[6])/2000000.0)
            .put("p95_round_ms",sorted[11]/1000000.0)
            .put("process_cpu_ticks",ticks).put("sampled_peak_managed_used_bytes",maxUsed)
            .put("end_smaps_rollup",smaps)
            .put("gc_before",before).put("gc_after",after).put("checksum",checksum)
            .put("scope","synthetic isolated dalvikvm; no UI or foreground process-state simulation"));
    }
}
