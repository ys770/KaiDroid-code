/* Fixed-path copied-directory test; no daemon, firmware or real registry writes. */
#define main probe_private_namespace
#include "probe_mount_namespace.c"
#undef main
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>

#define SOURCE "/data/local/tmp/kaidroid-sensor-bind01/sensors"
#define TARGET "/mnt/vendor/persist/sensors"
#define MARKER "/kaidroid-isolation-marker01"

int main(void) {
    struct stat source, original, bound, marker, copied;
    char canonical[4096];
    if (!realpath(SOURCE, canonical) || strcmp(canonical, SOURCE)) return 20;
    if (!realpath(TARGET, canonical) || strcmp(canonical, TARGET)) return 21;
    if (stat(SOURCE, &source) || stat(TARGET, &original)) return 22;
    if (!S_ISDIR(source.st_mode) || !S_ISDIR(original.st_mode)) return 23;
    if (source.st_dev == original.st_dev && source.st_ino == original.st_ino) return 24;
    if (probe_private_namespace()) return 25;
    if (mount(SOURCE, TARGET, NULL, MS_BIND, NULL)) { perror("bind"); return 26; }
    if (stat(TARGET, &bound) || bound.st_dev != source.st_dev || bound.st_ino != source.st_ino) return 27;
    int fd = open(TARGET MARKER, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
    if (fd < 0) { perror("marker"); return 28; }
    const char bytes[] = "private-copy-only\n";
    int failed = write(fd, bytes, sizeof(bytes) - 1) != sizeof(bytes) - 1;
    failed |= fsync(fd) != 0;
    failed |= fstat(fd, &marker) != 0;
    failed |= close(fd) != 0;
    if (failed || stat(SOURCE MARKER, &copied)) return 29;
    if (marker.st_dev != copied.st_dev || marker.st_ino != copied.st_ino) return 30;
    puts("{\"bound_to_copy\":true,\"marker_is_in_copy\":true}");
    return 0; /* Namespace and its bind mount disappear at process exit. */
}
