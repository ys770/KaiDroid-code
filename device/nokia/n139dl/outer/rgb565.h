#ifndef KAIDROID_OUTER_RGB565_H
#define KAIDROID_OUTER_RGB565_H
#include <stddef.h>
#include <stdint.h>

/* RGBA8 input, little-endian RGB565 output; padding remains untouched.
 * Caller provides disjoint buffers. Reject all invalid extents before writes.
 * This module has no framebuffer, power, ioctl or allocation side effects. */
static int kd_rgb565(uint8_t *dst, size_t dst_len, size_t dst_stride,
                     const uint8_t *src, size_t src_len, size_t src_stride,
                     size_t width, size_t height) {
    if (!dst || !src || !width || !height || width > SIZE_MAX / 4) return -1;
    size_t in_row = width * 4, out_row = width * 2;
    if (src_stride < in_row || dst_stride < out_row) return -1;
    if (height - 1 > (SIZE_MAX - in_row) / src_stride ||
        height - 1 > (SIZE_MAX - out_row) / dst_stride) return -1;
    if (src_len < (height - 1) * src_stride + in_row ||
        dst_len < (height - 1) * dst_stride + out_row) return -1;
    for (size_t y = 0; y < height; ++y) {
        const uint8_t *s = src + y * src_stride;
        uint8_t *d = dst + y * dst_stride;
        for (size_t x = 0; x < width; ++x) {
            uint16_t pixel = ((uint16_t)(s[4*x] >> 3) << 11) |
                             ((uint16_t)(s[4*x+1] >> 2) << 5) |
                             (uint16_t)(s[4*x+2] >> 3);
            d[2*x] = (uint8_t)pixel;
            d[2*x+1] = (uint8_t)(pixel >> 8);
        }
    }
    return 0;
}
#endif
