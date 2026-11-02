/* Read-only framebuffer ABI query/snapshot. No framebuffer write or SET ioctl. */
#include <errno.h>
#include <fcntl.h>
#include <linux/fb.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <unistd.h>

static int property_is(const char *key, const char *expected) {
    char value[PROP_VALUE_MAX] = {0};
    return __system_property_get(key, value) > 0 && !strcmp(value, expected);
}

int main(int argc, char **argv) {
    char boot[80] = {0};
    struct fb_fix_screeninfo fix = {0};
    struct fb_var_screeninfo var = {0};
    alarm(10);
    if ((argc != 2 && argc != 3) || !property_is("ro.serialno", "DEVICE_SERIAL_REQUIRED") ||
        !property_is("ro.kaidroid.image", "47")) {
        fprintf(stderr, "Expected exact engineering Nokia image47 and boot argument\n");
        return 2;
    }
    FILE *f = fopen("/proc/sys/kernel/random/boot_id", "r");
    if (!f) return 3;
    int ok = fgets(boot, sizeof boot, f) != NULL;
    fclose(f);
    boot[strcspn(boot, "\r\n")] = 0;
    if (!ok || strcmp(boot, argv[1])) return 4;
    int fd = open("/dev/graphics/fb1", O_RDONLY | O_CLOEXEC);
    if (fd < 0) { perror("open fb1"); return 5; }
    if (ioctl(fd, FBIOGET_FSCREENINFO, &fix) || ioctl(fd, FBIOGET_VSCREENINFO, &var)) {
        perror("GET framebuffer info"); close(fd); return 6;
    }
    /* Optional exclusive snapshot supports later pixel restoration. No mapping writes. */
    if (argc == 3) {
        if (var.xres != 128 || var.yres != 160 || var.xres_virtual != 128 ||
            var.yres_virtual != 320 || var.bits_per_pixel != 16 ||
            fix.line_length != 256 || fix.smem_len != 81920 ||
            var.xoffset || var.yoffset || var.red.offset != 11 || var.red.length != 5 ||
            var.green.offset != 5 || var.green.length != 6 || var.blue.offset ||
            var.blue.length != 5 || var.transp.length || var.red.msb_right ||
            var.green.msb_right || var.blue.msb_right || var.nonstd || var.grayscale ||
            fix.type != FB_TYPE_PACKED_PIXELS || fix.visual != FB_VISUAL_TRUECOLOR) {
            fprintf(stderr, "Unexpected framebuffer layout; snapshot rejected\n");
            close(fd); return 7;
        }
        const unsigned char *map = mmap(NULL, fix.smem_len, PROT_READ, MAP_SHARED, fd, 0);
        if (map == MAP_FAILED) { perror("read-only mmap"); close(fd); return 8; }
        int out = open(argv[2], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (out < 0) { perror("exclusive snapshot"); munmap((void *)map,fix.smem_len); close(fd); return 9; }
        size_t done = 0;
        while (done < fix.smem_len) {
            ssize_t n = write(out, map + done, fix.smem_len - done);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { perror("snapshot write"); close(out); munmap((void *)map,fix.smem_len); close(fd); return 10; }
            done += (size_t)n;
        }
        int rc = fsync(out);
        int close_rc = close(out);
        munmap((void *)map, fix.smem_len);
        if (rc || close_rc) { close(fd); return 11; }
    }
    close(fd);
    printf("{\"xres\":%u,\"yres\":%u,\"xres_virtual\":%u,\"yres_virtual\":%u,"
           "\"xoffset\":%u,\"yoffset\":%u,\"bits_per_pixel\":%u,\"line_length\":%u,"
           "\"smem_len\":%u,\"type\":%u,\"visual\":%u,\"activate\":%u,"
           "\"red\":[%u,%u,%u],\"green\":[%u,%u,%u],\"blue\":[%u,%u,%u],"
           "\"alpha\":[%u,%u,%u],\"nonstd\":%u,\"grayscale\":%u}\n",
           var.xres,var.yres,var.xres_virtual,var.yres_virtual,var.xoffset,var.yoffset,
           var.bits_per_pixel,fix.line_length,fix.smem_len,fix.type,fix.visual,var.activate,
           var.red.offset,var.red.length,var.red.msb_right,
           var.green.offset,var.green.length,var.green.msb_right,
           var.blue.offset,var.blue.length,var.blue.msb_right,
           var.transp.offset,var.transp.length,var.transp.msb_right,var.nonstd,var.grayscale);
    return 0;
}
