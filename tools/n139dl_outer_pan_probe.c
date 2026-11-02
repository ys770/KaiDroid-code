/* Same-mode PAN diagnostic. Does not write framebuffer pixels or change power. */
#include <errno.h>
#include <fcntl.h>
#include <linux/fb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <unistd.h>

static int prop(const char *key, const char *expected) {
    char value[PROP_VALUE_MAX] = {0};
    return __system_property_get(key,value)>0 && !strcmp(value,expected);
}
int main(int argc,char **argv) {
    alarm(10);
    setbuf(stdout,NULL);
    if(argc!=2 || getuid()!=0 || !prop("ro.serialno","DEVICE_SERIAL_REQUIRED") ||
       !prop("ro.kaidroid.image","47")) return 2;
    char boot[80]={0};
    FILE *f=fopen("/proc/sys/kernel/random/boot_id","r");
    if(!f) return 3;
    int ok=fgets(boot,sizeof boot,f)!=NULL; fclose(f);
    boot[strcspn(boot,"\r\n")]=0;
    if(!ok || strcmp(boot,argv[1])) return 4;
    int fd=open("/dev/graphics/fb1",O_RDWR|O_CLOEXEC);
    if(fd<0) return 5;
    struct fb_fix_screeninfo fix={0};
    struct fb_var_screeninfo before={0},request={0},after={0};
    if(ioctl(fd,FBIOGET_FSCREENINFO,&fix) || ioctl(fd,FBIOGET_VSCREENINFO,&before)) return 6;
    if(before.xres!=128 || before.yres!=160 || before.xres_virtual!=128 ||
       before.yres_virtual!=320 || before.bits_per_pixel!=16 || before.xoffset ||
       before.yoffset || fix.line_length!=256 || fix.smem_len!=81920 ||
       fix.type!=FB_TYPE_PACKED_PIXELS || fix.visual!=FB_VISUAL_TRUECOLOR ||
       before.red.offset!=11 || before.red.length!=5 || before.green.offset!=5 ||
       before.green.length!=6 || before.blue.offset || before.blue.length!=5 ||
       before.transp.length || before.nonstd || before.grayscale) return 7;
    const unsigned char *map=mmap(NULL,fix.smem_len,PROT_READ,MAP_SHARED,fd,0);
    if(map==MAP_FAILED) return 8;
    unsigned char *saved=malloc(fix.smem_len);
    if(!saved) return 9;
    memcpy(saved,map,fix.smem_len);
    request=before;
    /* Exactly one PAN, using the current mode and offsets unchanged. */
    errno=0;
    int rc=ioctl(fd,FBIOPAN_DISPLAY,&request),error=errno;
    int query=ioctl(fd,FBIOGET_VSCREENINFO,&after);
    int equal=!query && !memcmp(&before,&after,sizeof before);
    int pixels=!memcmp(saved,map,fix.smem_len);
    printf("PAN rc=%d errno=%d query=%d variable_equal=%d pixels_equal=%d\n",
           rc,rc?error:0,query,equal,pixels);
    if(!equal) {
        struct fb_var_screeninfo restore=before;
        int restored=ioctl(fd,FBIOPUT_VSCREENINFO,&restore);
        printf("UNEXPECTED_MODE_CHANGE restore_rc=%d\n",restored);
    }
    free(saved);munmap((void *)map,fix.smem_len);close(fd);
    /* A rejected PAN is diagnostic data, not failure of this observer. */
    return equal && pixels ? 0:10;
}
