/* Read-only policy metadata probe: no key operations, policy setters or writes. */
#include <errno.h>
#include <fcntl.h>
#include <linux/fscrypt.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* The retained ARM Bionic loader requires at least 32-byte executable TLS alignment. */
static _Thread_local unsigned char tls_alignment[32] __attribute__((aligned(32), used));

int main(void) {
    static const char *paths[] = {
        "/data", "/data/fota", "/data/usbmsc", "/data/hostapd",
        "/data/misc", "/data/misc/vold", "/data/unencrypted",
        "/data/system", "/data/system_de/0", "/data/user_de/0", "/data/user/0"
    };
    alarm(10);
    for (unsigned i = 0; i < sizeof(paths)/sizeof(paths[0]); ++i) {
        int fd = open(paths[i], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) { printf("%s open_errno=%d\n", paths[i], errno); continue; }
        struct fscrypt_policy_v1 p;
        memset(&p, 0, sizeof(p));
        int rc = ioctl(fd, FS_IOC_GET_ENCRYPTION_POLICY, &p);
        int error = errno;
        close(fd);
        if (rc) { printf("%s get_policy_errno=%d\n", paths[i], error); continue; }
        printf("%s version=%u contents=%u filenames=%u flags=%u descriptor=",
               paths[i], p.version, p.contents_encryption_mode,
               p.filenames_encryption_mode, p.flags);
        for (unsigned j = 0; j < sizeof(p.master_key_descriptor); ++j)
            printf("%02x", p.master_key_descriptor[j]);
        puts("");
    }
    return 0;
}
