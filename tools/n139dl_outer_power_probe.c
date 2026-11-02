/* Finite standard fb1 UNBLANK/PAN/POWERDOWN probe, initially suspended only. */
#define main same_mode_pan_probe
#include "n139dl_outer_pan_probe.c"
#undef main
#include <signal.h>
#include <sys/wait.h>
#include <time.h>

static volatile sig_atomic_t stop_requested;
static void stop_probe(int sig) { (void)sig;stop_requested=1; }
static int suspended(void) {
    char text[80]={0};
    FILE *f=fopen("/sys/class/graphics/fb1/msm_fb_panel_status","r");
    if(!f) return 0;
    int ok=fgets(text,sizeof text,f)!=NULL;fclose(f);
    return ok && !strcmp(text,"panel_status=suspend\n");
}
static double monotonic(void) {
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t)) return -1;
    return t.tv_sec+t.tv_nsec/1e9;
}
int main(int argc,char **argv) {
    setbuf(stdout,NULL);alarm(10);
    if(argc!=2 || getuid()!=0 || !prop("ro.serialno","DEVICE_SERIAL_REQUIRED") ||
       !prop("ro.kaidroid.image","47")) return 2;
    char boot[80]={0};FILE *f=fopen("/proc/sys/kernel/random/boot_id","r");
    if(!f) return 3;
    int ok=fgets(boot,sizeof boot,f)!=NULL;fclose(f);
    boot[strcspn(boot,"\r\n")]=0;
    if(!ok || strcmp(boot,argv[1]) || !suspended()) return 4;
    int fd=open("/dev/graphics/fb1",O_RDWR|O_CLOEXEC);
    if(fd<0) return 5;
    struct fb_fix_screeninfo fix={0};struct fb_var_screeninfo var={0},after={0};
    if(ioctl(fd,FBIOGET_FSCREENINFO,&fix) || ioctl(fd,FBIOGET_VSCREENINFO,&var)) return 6;
    if(fix.smem_len!=81920 || fix.line_length!=256 || var.xres!=128 || var.yres!=160 ||
       var.xres_virtual!=128 || var.yres_virtual!=320 || var.bits_per_pixel!=16 ||
       var.xoffset || var.yoffset) return 7;
    const unsigned char *map=mmap(NULL,fix.smem_len,PROT_READ,MAP_SHARED,fd,0);
    if(map==MAP_FAILED) return 8;
    unsigned char *saved=malloc(fix.smem_len);if(!saved)return 9;
    memcpy(saved,map,fix.smem_len);
    int gate[2];if(pipe(gate))return 10;
    double deadline=monotonic()+15;if(deadline<15)return 11;
    signal(SIGHUP,SIG_IGN);signal(SIGTERM,stop_probe);signal(SIGINT,stop_probe);
    alarm(0);
    pid_t child=fork();if(child<0)return 12;
    if(child==0) {
        close(gate[1]);signal(SIGTERM,SIG_DFL);signal(SIGINT,SIG_DFL);alarm(10);
        char go=0;if(read(gate[0],&go,1)!=1 || go!='G')_exit(13);
        close(gate[0]);errno=0;
        int rc=ioctl(fd,FBIOBLANK,FB_BLANK_UNBLANK),error=errno;
        printf("UNBLANK rc=%d errno=%d suspended=%d\n",rc,rc?error:0,suspended());
        if(rc)_exit(14);
        _exit(same_mode_pan_probe(argc,argv));
    }
    close(gate[0]);
    printf("ARMED parent=%d child=%d deadline=%.3f\n",getpid(),child,deadline);
    if(write(gate[1],"G",1)!=1)stop_requested=1;
    close(gate[1]);
    int status=0,reaped=0;
    while(!stop_requested && monotonic()<deadline) {
        if(waitpid(child,&status,WNOHANG)==child){reaped=1;break;}
        usleep(100000);
    }
    if(!reaped) {
        kill(child,SIGKILL);
        for(int n=0;n<10;n++){if(waitpid(child,&status,WNOHANG)==child){reaped=1;break;}usleep(100000);}
    }
    /* Always request the original suspended state, even after partial UNBLANK failure. */
    errno=0;int rc=ioctl(fd,FBIOBLANK,FB_BLANK_POWERDOWN),error=errno;
    int state=suspended(),query=ioctl(fd,FBIOGET_VSCREENINFO,&after);
    int mode=!query && !memcmp(&var,&after,sizeof var),pixels=!memcmp(saved,map,fix.smem_len);
    printf("POWERDOWN rc=%d errno=%d suspended=%d mode_equal=%d pixels_equal=%d child_reaped=%d child_status=%d\n",
           rc,rc?error:0,state,mode,pixels,reaped,status);
    munmap((void *)map,fix.smem_len);free(saved);close(fd);
    return !rc && state && mode && pixels && reaped ? 0:15;
}
