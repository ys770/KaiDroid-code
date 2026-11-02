/* Fixed sensor trial: copied registry, foreground daemon, PID namespace deadline. */
#define main probe_private_namespace
#include "probe_mount_namespace.c"
#undef main
#include <fcntl.h>
#include <grp.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#define SOURCE "/data/local/tmp/kaidroid-sensor-trial01/sensors"
#define TARGET "/mnt/vendor/persist/sensors"

static int expected_label(const char *path) {
    char label[128] = {0};
    ssize_t size = lgetxattr(path, "security.selinux", label, sizeof(label) - 1);
    return size > 0 && !strcmp(label, "u:object_r:sensors_persist_file:s0");
}

static int enter_sensor_context(void) {
    struct stat source, original, bound;
    char canonical[4096], context[128] = {0};
    if (!realpath(SOURCE, canonical) || strcmp(canonical, SOURCE)) return 20;
    if (!realpath(TARGET, canonical) || strcmp(canonical, TARGET)) return 21;
    if (stat(SOURCE, &source) || stat(TARGET, &original)) return 22;
    if (!S_ISDIR(source.st_mode) || source.st_uid != 1000 || source.st_gid != 1000) return 23;
    if (source.st_dev == original.st_dev && source.st_ino == original.st_ino) return 24;
    if (!expected_label(SOURCE) || !expected_label(SOURCE "/sensors_settings")) return 25;
    if (probe_private_namespace()) return 26;
    if (mount(SOURCE, TARGET, NULL, MS_BIND, NULL)) { perror("bind"); return 27; }
    if (stat(TARGET, &bound) || bound.st_dev != source.st_dev || bound.st_ino != source.st_ino) return 28;
    if (setgroups(0, NULL) || setgid(1000) || setuid(1000)) { perror("identity"); return 29; }
    const char domain[] = "u:r:sensors:s0";
    int fd = open("/proc/self/attr/current", O_WRONLY);
    if (fd < 0) { perror("context-open"); return 30; }
    ssize_t written = write(fd, domain, sizeof(domain) - 1);
    int saved = written == sizeof(domain) - 1;
    if (!saved) perror("context-write");
    close(fd);
    if (!saved) return 31;
    fd = open("/proc/self/attr/current", O_RDONLY);
    if (fd < 0) { perror("context-read"); return 32; }
    ssize_t count = read(fd, context, sizeof(context) - 1);
    close(fd);
    if (count <= 0 || strcmp(context, domain) || getuid() != 1000 || getgid() != 1000) return 33;
    return 0;
}

#include <errno.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>

static volatile sig_atomic_t stopped;
static void stop_requested(int sig) { (void)sig; stopped = 1; }

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    struct sigaction action = {0};
    action.sa_handler = stop_requested;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL)) return 40;
    if (unshare(CLONE_NEWPID)) { perror("unshare-pid"); return 41; }
    pid_t child = fork();
    if (child < 0) { perror("fork"); return 42; }
    if (!child) {
        if (getpid() != 1) _exit(43);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL)) _exit(44);
        int result = enter_sensor_context();
        if (result) _exit(result);
        /* Credential changes clear PDEATHSIG. Reinstate before exec. */
        if (prctl(PR_SET_PDEATHSIG, SIGKILL)) _exit(45);
        printf("{\"exec_requested\":true,\"namespace_pid\":1,\"uid\":%u}\n", getuid());
        execl("/vendor/bin/sensors.qti", "sensors.qti", (char *)NULL);
        perror("exec-sensors");
        _exit(46);
    }
    printf("{\"supervised_host_pid\":%d,\"deadline_seconds\":30}\n", child);
    struct timespec start, now, delay = {0, 100000000};
    if (clock_gettime(CLOCK_MONOTONIC, &start)) { kill(child, SIGKILL); waitpid(child, NULL, 0); return 47; }
    int status = 0, forced = 0;
    for (;;) {
        pid_t done = waitpid(child, &status, WNOHANG);
        if (done == child) break;
        if (done < 0 && errno != EINTR) return 48;
        if (clock_gettime(CLOCK_MONOTONIC, &now) || stopped || now.tv_sec - start.tv_sec >= 30) {
            forced = 1;
            if (kill(child, SIGKILL) && errno != ESRCH) { perror("kill-init"); return 49; }
            while (waitpid(child, &status, 0) < 0) if (errno != EINTR) return 50;
            break;
        }
        nanosleep(&delay, NULL);
    }
    printf("{\"namespace_init_reaped\":true,\"forced_stop\":%s,\"wait_status\":%d}\n", forced ? "true" : "false", status);
    if (forced) return 124;
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 55;
}
