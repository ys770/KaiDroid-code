/* Engineering-only, fixed-target diagnostic. Never installed as a boot service.
 * Invoke under a host-supervised timeout as UID/GID 1000 in the eng su domain.
 * Sets the next-exec SELinux context, not policy or global enforcement.
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static _Thread_local unsigned char tls_alignment[32] __attribute__((aligned(32), used));

int main(void) {
    char context[128] = {0};
    if (getuid() != 1000 || getgid() != 1000) return 2;
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 2;
    ssize_t size = read(fd, context, sizeof(context)-1);
    close(fd);
    if (size < 0 || strcmp(context, "u:r:su:s0") != 0) return 2;
    if (chdir("/")) return 2;
    const char *target = "u:r:hal_memtrack_default:s0";
    fd = open("/proc/self/attr/exec", O_WRONLY | O_CLOEXEC);
    if (fd < 0) { perror("open exec context"); return 2; }
    ssize_t written = write(fd, target, strlen(target)+1);
    close(fd);
    if (written != (ssize_t)strlen(target)+1) { perror("set exec context"); return 2; }
    char *const argv[] = {"/mnt/kaidroid-memtrack-probe/service", NULL};
    char *const env[] = {
        "LD_LIBRARY_PATH=/apex/com.android.vndk.v29/lib:/vendor/lib:/vendor/lib/hw",
        "PATH=/system/bin", "ANDROID_ROOT=/system", "ANDROID_DATA=/data", NULL
    };
    execve(argv[0], argv, env);
    perror("exec memtrack");
    return 2;
}
