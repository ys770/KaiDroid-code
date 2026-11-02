/* Experimental Nokia hall -> Android SW_LID adapter. No power/key injection.
 * Default is observation only. --uinput explicitly enables a virtual lid device.
 * Caller must verify handset/build; no init service or policy is installed here.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static void stop(int sig) { (void)sig; stopping = 1; }
static long seconds(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
    return t.tv_sec;
}
static int read_text(const char *path, char *out, size_t size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, out, size - 1);
    close(fd);
    if (n <= 0) return -1;
    out[n] = 0;
    out[strcspn(out, "\r\n")] = 0;
    return 0;
}
static int state(const char *path) {
    char text[16];
    if (read_text(path, text, sizeof(text))) return -1;
    if (!strcmp(text, "0")) return 0;
    if (!strcmp(text, "1")) return 1;
    errno = EINVAL;
    return -1;
}
static int emit(int fd, int closed) {
    struct input_event e[2] = {0};
    e[0].type = EV_SW;
    e[0].code = SW_LID;
    e[0].value = closed;
    e[1].type = EV_SYN;
    e[1].code = SYN_REPORT;
    return write(fd, e, sizeof(e)) == sizeof(e) ? 0 : -1;
}
int main(int argc, char **argv) {
    int enabled = 0, duration = 60, daemon = 0, duration_set = 0;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--uinput")) enabled = 1;
        else if (!strcmp(argv[i], "--daemon")) daemon = 1;
        else if (!strcmp(argv[i], "--seconds") && i + 1 < argc) {
            char *end;
            long n = strtol(argv[++i], &end, 10);
            if (*end || n < 1 || n > 300) return 2;
            duration = (int)n;
            duration_set = 1;
        } else { fprintf(stderr, "Usage: %s [--uinput] [--seconds 1..300 | --daemon]\n", argv[0]); return 2; }
    }
    if (daemon && duration_set) { fprintf(stderr, "--daemon and --seconds are mutually exclusive\n"); return 2; }
    DIR *dir = opendir("/sys/class/input");
    if (!dir) { perror("input sysfs"); return 1; }
    char status[512] = "", device[128] = "";
    int matches = 0;
    struct dirent *ent;
    while ((ent = readdir(dir))) {
        unsigned number;
        char extra;
        if (sscanf(ent->d_name, "event%u%c", &number, &extra) != 1) continue;
        char path[512], name[128], resolved[4096];
        snprintf(path, sizeof(path), "/sys/class/input/event%u/device", number);
        /* The service is granted only the measured hall subtree, not generic
         * sysfs file access. Resolve before opening unrelated input names. */
        if (!realpath(path, resolved) ||
            strncmp(resolved, "/sys/devices/platform/soc/soc:hall_sensor/",
                    strlen("/sys/devices/platform/soc/soc:hall_sensor/"))) continue;
        snprintf(path, sizeof(path), "/sys/class/input/event%u/device/name", number);
        if (read_text(path, name, sizeof(name)) || strcmp(name, "hall_sensor")) continue;
        ++matches;
        snprintf(status, sizeof(status), "/sys/class/input/event%u/device/device/hall_status", number);
        snprintf(device, sizeof(device), "/dev/input/event%u", number);
    }
    closedir(dir);
    if (matches != 1) { fprintf(stderr, "Expected one hall_sensor, got %d\n", matches); return 1; }
    int sensor = open(device, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (sensor < 0 || state(status) < 0) { perror("hall input/status"); if (sensor >= 0) close(sensor); return 1; }
    int virtual = -1, created = 0, result = 0;
    if (enabled) {
        virtual = open("/dev/uinput", O_WRONLY | O_NONBLOCK | O_CLOEXEC);
        struct uinput_user_dev dev = {0};
        snprintf(dev.name, sizeof(dev.name), "KaiDroid Nokia Lid");
        dev.id.bustype = BUS_VIRTUAL;
        if (virtual < 0 || ioctl(virtual, UI_SET_EVBIT, EV_SW) < 0 ||
            ioctl(virtual, UI_SET_SWBIT, SW_LID) < 0 ||
            write(virtual, &dev, sizeof(dev)) != sizeof(dev) ||
            ioctl(virtual, UI_DEV_CREATE) < 0) {
            perror("uinput create"); result = 1; goto done;
        }
        created = 1;
    }
    signal(SIGTERM, stop);
    signal(SIGINT, stop);
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("mode=%s sensor=%s status=%s\n", enabled ? "uinput" : "observe", device, status);
    long deadline = seconds() + duration;
    int previous = -1;
    while (!stopping && (daemon || seconds() < deadline)) {
        /* Read the actual state on startup, transitions and periodic recovery.
         * Do not translate KEY249 DOWN/UP into blind power toggles. */
        int current = state(status);
        if (current < 0) { perror("hall status"); result = 1; break; }
        if (current != previous) {
            if (enabled && emit(virtual, current)) { perror("SW_LID"); result = 1; break; }
            printf("uptime=%ld closed=%d emitted=%d\n", seconds(), current, enabled);
            previous = current;
        }
        struct pollfd p = { .fd = sensor, .events = POLLIN };
        int ready = poll(&p, 1, 250);
        if (ready < 0 && errno != EINTR) { perror("poll"); result = 1; break; }
        if (ready > 0 && (p.revents & (POLLERR | POLLHUP | POLLNVAL))) { result = 1; break; }
        if (ready > 0 && (p.revents & POLLIN)) {
            struct input_event events[32];
            ssize_t n;
            do { n = read(sensor, events, sizeof(events)); } while (n > 0);
            if (n < 0 && errno != EAGAIN && errno != EINTR) { perror("input read"); result = 1; break; }
        }
    }
done:
    if (created && ioctl(virtual, UI_DEV_DESTROY) < 0) { perror("uinput destroy"); result = 1; }
    if (virtual >= 0) close(virtual);
    close(sensor);
    return result;
}
