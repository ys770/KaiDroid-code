/* Bounded diagnostic: changes only this process's mount namespace.
 * No daemon execution, bind mounts, file creation or arbitrary commands. */
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

static int namespace_name(char *buf, size_t size) {
    ssize_t n = readlink("/proc/self/ns/mnt", buf, size - 1);
    if (n < 0) { perror("readlink"); return -1; }
    buf[n] = 0;
    return 0;
}

int main(void) {
    char before[128], after[128], line[8192];
    if (namespace_name(before, sizeof(before))) return 2;
    if (unshare(CLONE_NEWNS)) { perror("unshare"); return 3; }
    if (namespace_name(after, sizeof(after))) return 4;
    if (!strcmp(before, after)) return 5;
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
        perror("mount-private"); return 6;
    }
    FILE *fp = fopen("/proc/self/mountinfo", "r");
    if (!fp) { perror("mountinfo"); return 7; }
    unsigned rows = 0, tags = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (!strchr(line, '\n')) { fclose(fp); return 8; }
        char *separator = strstr(line, " - ");
        if (!separator) { fclose(fp); return 9; }
        *separator = 0;
        tags += strstr(line, " shared:") != NULL || strstr(line, " master:") != NULL;
        rows++;
    }
    int failed = ferror(fp);
    fclose(fp);
    printf("{\"namespace_before\":\"%s\",\"namespace_after\":\"%s\","
           "\"mount_rows\":%u,\"propagation_tags\":%u}\n", before, after, rows, tags);
    return failed || !rows || tags ? 10 : 0;
}
