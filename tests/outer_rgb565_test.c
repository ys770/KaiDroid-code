#include <stdio.h>
#include <string.h>
#include "../device/nokia/n139dl/outer/rgb565.h"
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"FAIL line %d\n",__LINE__); return 1; } } while(0)
int main(void) {
    /* Odd width and both input/output row padding catch packed-row assumptions. */
    const uint8_t src[28] = {
        255,0,0,0, 0,255,0,1, 0,0,255,255, 9,9,9,9,
        255,255,255,12, 0,0,0,255, 128,128,128,0
    };
    const uint8_t expected[16] = {
        0,248,224,7,31,0, 0xa5,0xa5,
        255,255,0,0,16,132, 0xa5,0xa5
    };
    uint8_t dst[18]; memset(dst,0xa5,sizeof dst);
    CHECK(kd_rgb565(dst+1,16,8,src,sizeof src,16,3,2)==0);
    CHECK(!memcmp(dst+1,expected,16));
    CHECK(dst[0]==0xa5 && dst[17]==0xa5);
    uint8_t before[18]; memcpy(before,dst,sizeof dst);
    CHECK(kd_rgb565(dst+1,13,8,src,sizeof src,16,3,2)==-1);
    CHECK(kd_rgb565(dst+1,16,8,src,27,16,3,2)==-1);
    CHECK(kd_rgb565(dst+1,16,5,src,sizeof src,16,3,2)==-1);
    CHECK(kd_rgb565(dst+1,16,8,src,sizeof src,11,3,2)==-1);
    CHECK(kd_rgb565(dst+1,16,8,src,sizeof src,16,0,2)==-1);
    CHECK(kd_rgb565(dst+1,16,8,src,sizeof src,16,SIZE_MAX,2)==-1);
    CHECK(kd_rgb565(dst+1,16,8,src,sizeof src,16,3,SIZE_MAX)==-1);
    CHECK(kd_rgb565(NULL,16,8,src,sizeof src,16,3,2)==-1);
    CHECK(!memcmp(before,dst,sizeof dst));
    puts("PASS golden colors, alpha ignored, odd width, padded strides, canaries, short extents, overflow rejection, no-write failures");
    return 0;
}
