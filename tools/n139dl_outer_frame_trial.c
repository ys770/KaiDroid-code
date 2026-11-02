/* Engineering handset only. Finite fb1 test; parent owns restoration. */
#ifndef KD_OUTER_IMAGE
#define KD_OUTER_IMAGE "47"
#endif
#include <errno.h>
#include <fcntl.h>
#include <linux/fb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "../device/nokia/n139dl/outer/rgb565.h"

static volatile sig_atomic_t stopping;
static void stop(int signal_number) { (void)signal_number; stopping = 1; }
static int prop(const char *key, const char *value) {
    char actual[PROP_VALUE_MAX] = {0};
    return __system_property_get(key,actual) > 0 && !strcmp(actual,value);
}
static int identity(const char *expected) {
    char boot[80] = {0};
    FILE *f = fopen("/proc/sys/kernel/random/boot_id","r");
    if (!f) return 0;
    int ok = fgets(boot,sizeof boot,f) != NULL; fclose(f);
    boot[strcspn(boot,"\r\n")] = 0;
    return ok && !strcmp(boot,expected) && prop("ro.serialno","DEVICE_SERIAL_REQUIRED") &&
           prop("ro.kaidroid.image",KD_OUTER_IMAGE) && getuid()==0;
}
static int layout(const struct fb_fix_screeninfo *f, const struct fb_var_screeninfo *v) {
    return v->xres==128 && v->yres==160 && v->xres_virtual==128 && v->yres_virtual==320 &&
        !v->xoffset && !v->yoffset && v->bits_per_pixel==16 && f->line_length==256 &&
        f->smem_len==81920 && f->type==0 && f->visual==2 &&
        v->red.offset==11 && v->red.length==5 && !v->red.msb_right &&
        v->green.offset==5 && v->green.length==6 && !v->green.msb_right &&
        v->blue.offset==0 && v->blue.length==5 && !v->blue.msb_right &&
        !v->transp.length && !v->nonstd && !v->grayscale;
}
static int write_all(int fd,const void *data,size_t size) {
    const unsigned char *p=data;
    while(size) {
        ssize_t n=write(fd,p,size);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) return -1;
        p+=n; size-=(size_t)n;
    }
    return 0;
}
static double now(void) {
    struct timespec t; if(clock_gettime(CLOCK_MONOTONIC,&t)) return -1;
    return t.tv_sec+t.tv_nsec/1e9;
}
static int panel_suspended(void) {
    char text[80]={0};
    FILE *f=fopen("/sys/class/graphics/fb1/msm_fb_panel_status","r");
    if(!f) return 0;
    int ok=fgets(text,sizeof text,f)!=NULL;fclose(f);
    return ok && !strcmp(text,"panel_status=suspend\n");
}
int main(int argc,char **argv) {
    setbuf(stdout,NULL); setbuf(stderr,NULL);
    if(argc!=4 || (strcmp(argv[2],"--dry-run") && strcmp(argv[2],"--test") &&
                  strcmp(argv[2],"--wake-test")) || !identity(argv[1])) return 2;
    int wake=!strcmp(argv[2],"--wake-test");
    int test=wake || !strcmp(argv[2],"--test");
    if(wake && !panel_suspended()) return 17;
    signal(SIGHUP,SIG_IGN); signal(SIGTERM,stop); signal(SIGINT,stop);
    int fd=open("/dev/graphics/fb1",(test?O_RDWR:O_RDONLY)|O_CLOEXEC);
    if(fd<0) {perror("open");return 3;}
    struct fb_fix_screeninfo fix={0}; struct fb_var_screeninfo original={0};
    if(ioctl(fd,FBIOGET_FSCREENINFO,&fix) || ioctl(fd,FBIOGET_VSCREENINFO,&original) || !layout(&fix,&original)) return 4;
    unsigned char *map=mmap(NULL,fix.smem_len,PROT_READ|(test?PROT_WRITE:0),MAP_SHARED,fd,0);
    if(map==MAP_FAILED) {perror("mmap");return 5;}
    unsigned char *saved=malloc(fix.smem_len), *frame=malloc(fix.smem_len), *rgba=malloc(128*160*4);
    if(!saved || !frame || !rgba) return 6;
    memcpy(saved,map,fix.smem_len); memcpy(frame,saved,fix.smem_len);
    static const unsigned char colors[4][3]={{255,0,0},{0,255,0},{0,0,255},{255,255,255}};
    for(unsigned y=0;y<160;y++) for(unsigned x=0;x<128;x++) {
        unsigned char *p=rgba+(y*128+x)*4;
        memcpy(p,colors[x/32],3); p[3]=255;
        if(y<3 || y>=157 || x<3 || x>=125) p[0]=p[1]=p[2]=0;
    }
    if(kd_rgb565(frame,fix.smem_len,fix.line_length,rgba,128*160*4,128*4,128,160)) return 7;
    int backup=open(argv[3],O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(backup<0) {perror("backup");return 8;}
    if(write_all(backup,&original,sizeof original) || write_all(backup,saved,fix.smem_len) || fsync(backup)) return 9;
    if(close(backup)) return 9;
    printf("BACKUP bytes=%zu pixels=%u mode=%s\n",sizeof original+fix.smem_len,fix.smem_len,argv[2]);
    if(!test) {puts("DRY_RUN no framebuffer writes or SET ioctls");return 0;}
    if(stopping || !identity(argv[1])) return 10;
    int gate[2]; if(pipe(gate)) return 11;
    double deadline=now()+30; if(deadline<30) return 12;
    pid_t child=fork(); if(child<0) return 13;
    if(child==0) {
        close(gate[1]); signal(SIGTERM,SIG_DFL); signal(SIGINT,SIG_DFL);
        char go=0; if(read(gate[0],&go,1)!=1 || go!='G') _exit(14);
        close(gate[0]);
        /* Write before any potentially blocking driver call: no late pixel write after parent cleanup. */
        memcpy(map,frame,fix.smem_len);
        if(wake) {
            errno=0;
            int rc=ioctl(fd,FBIOBLANK,FB_BLANK_UNBLANK),err=errno;
            printf("UNBLANK rc=%d errno=%d suspended=%d\n",rc,rc?err:0,panel_suspended());
            if(rc)_exit(18);
        }
        struct fb_var_screeninfo update=original; update.activate=0x90;
        int sync_rc=fsync(fd); int sync_errno=errno;
        int rc=ioctl(fd,wake?FBIOPAN_DISPLAY:FBIOPUT_VSCREENINFO,&update); int err=errno;
        printf("SUBMIT fsync=%d fsync_errno=%d ioctl=%d ioctl_errno=%d\n",sync_rc,sync_rc?sync_errno:0,rc,rc?err:0);
        _exit(rc?15:0);
    }
    close(gate[0]);
    printf("ARMED parent=%d child=%d deadline=%.3f\n",getpid(),child,deadline);
    if(write(gate[1],"G",1)!=1) stopping=1;
    close(gate[1]);
    int status=0, reaped=0;
    while(!stopping && now()<deadline) {
        if(!reaped) {pid_t r=waitpid(child,&status,WNOHANG); if(r==child) reaped=1;}
        if(reaped && (!WIFEXITED(status) || WEXITSTATUS(status))) break;
        usleep(100000);
    }
    if(!reaped) {kill(child,SIGKILL); for(int i=0;i<10;i++){if(waitpid(child,&status,WNOHANG)==child){reaped=1;break;}usleep(100000);}}
    /* Child writes only before its submit ioctl; no later pixel writes can race restoration. */
    memcpy(map,saved,fix.smem_len);
    struct fb_var_screeninfo redraw=original; redraw.activate=0x90;
    int sync_rc=fsync(fd);
    int redraw_rc=ioctl(fd,wake?FBIOPAN_DISPLAY:FBIOPUT_VSCREENINFO,&redraw);
    struct fb_var_screeninfo restore=original;
    int restore_rc=ioctl(fd,FBIOPUT_VSCREENINFO,&restore);
    int power_ok=1;
    if(wake) {
        errno=0;
        int rc=ioctl(fd,FBIOBLANK,FB_BLANK_POWERDOWN),err=errno;
        int suspended=panel_suspended();power_ok=!rc && suspended;
        printf("POWERDOWN rc=%d errno=%d suspended=%d\n",rc,rc?err:0,suspended);
    }
    struct fb_var_screeninfo after={0};
    int query_rc=ioctl(fd,FBIOGET_VSCREENINFO,&after);
    int bytes_ok=!memcmp(map,saved,fix.smem_len);
    int var_ok=!query_rc && !memcmp(&after,&original,sizeof after);
    /* Restoration alone does not prove the test pattern was submitted. */
    int submitted=reaped && WIFEXITED(status) && WEXITSTATUS(status)==0;
    int completed=submitted && !stopping;
    printf("RESTORE bytes_equal=%d variable_equal=%d fsync=%d redraw=%d restore=%d child_reaped=%d child_status=%d\n",bytes_ok,var_ok,sync_rc,redraw_rc,restore_rc,reaped,status);
    printf("TRIAL submitted=%d interrupted=%d completed=%d\n",submitted,!!stopping,completed);
    munmap(map,fix.smem_len);close(fd);free(saved);free(frame);free(rgba);
    return bytes_ok && var_ok && !redraw_rc && !restore_rc && completed && power_ok ? 0:16;
}
