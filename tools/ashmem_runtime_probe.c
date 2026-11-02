/* Bounded standalone test. Loads one explicit library; never installs it. */
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void check(int ok, const char *step) {
    if (!ok) { fprintf(stderr, "FAIL %s errno=%d\n", step, errno); exit(1); }
}

int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/') return 2;
    alarm(10);
    void *lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 3; }
    FILE *maps = fopen("/proc/self/maps", "r");
    check(maps != NULL, "maps");
    char line[512];
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "libcutils") || strstr(line, "libbase.so") || strstr(line, "libc++.so"))
            fputs(line, stdout);
    }
    fclose(maps);
    int (*create)(const char *, size_t) = dlsym(lib, "ashmem_create_region");
    int (*size)(int) = dlsym(lib, "ashmem_get_size_region");
    int (*protect)(int, int) = dlsym(lib, "ashmem_set_prot_region");
    check(create && size && protect, "symbols");
    int fd = create("kaidroid_probe", 4096);
    check(fd >= 0, "create");
    check(size(fd) == 4096, "size");
    struct stat st;
    check(fstat(fd, &st) == 0 && S_ISCHR(st.st_mode), "ashmem-character-fd");
    char link[64], target[256];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t length = readlink(link, target, sizeof(target) - 1);
    check(length >= 0, "fd-path"); target[length] = 0;
    printf("fd_path=%s\n", target);
    char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check(page != MAP_FAILED, "map-parent");
    strcpy(page, "parent-to-child");
    int sockets[2]; check(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) == 0, "socketpair");
    pid_t child = fork(); check(child >= 0, "fork");
    if (child == 0) {
        alarm(5); close(sockets[0]); close(fd); munmap(page, 4096);
        char byte, control[CMSG_SPACE(sizeof(int))] = {0};
        struct iovec io = {.iov_base = &byte, .iov_len = 1};
        struct msghdr msg = {.msg_iov = &io, .msg_iovlen = 1,
                             .msg_control = control, .msg_controllen = sizeof(control)};
        check(recvmsg(sockets[1], &msg, 0) == 1 && !(msg.msg_flags & MSG_CTRUNC), "receive-fd");
        struct cmsghdr *header = CMSG_FIRSTHDR(&msg);
        check(header && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS
              && header->cmsg_len == CMSG_LEN(sizeof(int)), "fd-message");
        int received; memcpy(&received, CMSG_DATA(header), sizeof(received));
        check(size(received) == 4096, "received-size");
        char *other = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, received, 0);
        check(other != MAP_FAILED && strcmp(other, "parent-to-child") == 0, "received-map");
        strcpy(other + 128, "child-to-parent");
        munmap(other, 4096); close(received); close(sockets[1]); _exit(0);
    }
    close(sockets[1]);
    char byte = 'x', control[CMSG_SPACE(sizeof(int))] = {0};
    struct iovec io = {.iov_base = &byte, .iov_len = 1};
    struct msghdr msg = {.msg_iov = &io, .msg_iovlen = 1,
                         .msg_control = control, .msg_controllen = sizeof(control)};
    struct cmsghdr *header = CMSG_FIRSTHDR(&msg);
    header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int)); memcpy(CMSG_DATA(header), &fd, sizeof(fd));
    check(sendmsg(sockets[0], &msg, 0) == 1, "send-fd");
    int status; check(waitpid(child, &status, 0) == child && WIFEXITED(status)
                      && WEXITSTATUS(status) == 0, "child");
    check(strcmp(page + 128, "child-to-parent") == 0, "shared-content");
    check(protect(fd, PROT_READ) == 0, "restrict-protection");
    errno = 0;
    void *denied = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check(denied == MAP_FAILED && (errno == EPERM || errno == EACCES), "write-map-denied");
    void *readonly = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    check(readonly != MAP_FAILED, "readonly-map");
    munmap(readonly, 4096); munmap(page, 4096); close(fd); close(sockets[0]);
    puts("PASS allocation size SCM_RIGHTS shared-content protection");
    dlclose(lib); return 0;
}
