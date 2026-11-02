/* Registry-access probe only: no daemon or hardware device access. */
#define main probe_private_namespace
#include "probe_mount_namespace.c"
#undef main
#include <fcntl.h>
#include <grp.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#define SOURCE "/data/local/tmp/kaidroid-sensor-access01/sensors"
#define TARGET "/mnt/vendor/persist/sensors"

static int expected_label(const char *path) {
    char label[128] = {0};
    ssize_t size = lgetxattr(path, "security.selinux", label, sizeof(label) - 1);
    return size > 0 && !strcmp(label, "u:object_r:sensors_persist_file:s0");
}

int main(void) {
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
    fd = open(TARGET "/kaidroid-access-marker01", O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
    if (fd < 0) { perror("marker-open"); return 34; }
    const char marker[] = "system-sensors-domain\n";
    int failed = write(fd, marker, sizeof(marker) - 1) != sizeof(marker) - 1;
    failed |= fsync(fd) != 0;
    failed |= close(fd) != 0;
    if (failed) return 35;
    printf("{\"uid\":%u,\"gid\":%u,\"domain\":\"%s\",\"marker_written\":true}\n", getuid(), getgid(), context);
    return 0;
}
