/* Bounded corpus/readback benchmark for an explicitly owned, fresh zramN (N>0).
 * Does not allocate/reset/remove devices or activate swap. Default is preflight.
 * Caller must establish exclusive ownership and retain its creation receipt.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>

#define PAGE_BYTES 4096u
#define CORPUS_BYTES (4u * 1024u * 1024u)
#define PAGES (CORPUS_BYTES / PAGE_BYTES)

static void fail(const char *message) { fprintf(stderr,"%s: %s\n",message,strerror(errno)); exit(1); }
static unsigned number(const char *s) {
    char *end; errno=0; unsigned long value=strtoul(s,&end,10);
    if (errno || !*s || *end || value>65535) { errno=EINVAL; fail("invalid numeric argument"); }
    return (unsigned)value;
}
static uint64_t now(clockid_t clock) {
    struct timespec t; if(clock_gettime(clock,&t))fail("clock_gettime");
    return (uint64_t)t.tv_sec*1000000000u+(uint64_t)t.tv_nsec;
}
static uint32_t random32(uint32_t *s) { uint32_t x=*s; x^=x<<13; x^=x>>17; x^=x<<5; return *s=x; }
static void page(unsigned char *out,unsigned index,int profile) {
    uint32_t state=0x13579bdfu^((index+1)*0x9e3779b9u);
    int kind=profile==0?0:profile==1?1:profile==2?2:(int)(index%4);
    for(unsigned i=0;i<PAGE_BYTES/4;i++) {
        uint32_t value;
        if(kind==0)value=0;
        else if(kind==1)value=i%8==0 ? (i/8)%17 : 0x12c00000u+((random32(&state)&2047u)<<3);
        else if(kind==2)value=random32(&state);
        else value=0x61626364u+(i%7);
        memcpy(out+4*i,&value,4);
    }
}
static uint64_t checksum(uint64_t value,const unsigned char *data) {
    for(unsigned i=0;i<PAGE_BYTES;i++) {value^=data[i];value*=UINT64_C(1099511628211);}
    return value;
}
static int compare_u64(const void *a,const void *b) {
    uint64_t x=*(const uint64_t *)a,y=*(const uint64_t *)b;return (x>y)-(x<y);
}
static void require_unused(dev_t device) {
    FILE *f=fopen("/proc/swaps","r"); if(!f)fail("open swaps");
    char line[4096],path[2048];
    while(fgets(line,sizeof(line),f)) {
        struct stat s;
        if(sscanf(line,"%2047s",path)==1 && !stat(path,&s) && S_ISBLK(s.st_mode) && s.st_rdev==device) {
            errno=EBUSY;fail("device is active swap");
        }
    }
    if(ferror(f))fail("read swaps");
    fclose(f);
    f=fopen("/proc/self/mountinfo","r");if(!f)fail("open mountinfo");
    while(fgets(line,sizeof(line),f)) {
        unsigned maj,min;
        if(sscanf(line,"%*u %*u %u:%u",&maj,&min)==2 && makedev(maj,min)==device) {
            errno=EBUSY;fail("device is mounted");
        }
    }
    if(ferror(f))fail("read mountinfo");
    fclose(f);
}

int main(int argc,char **argv) {
    if(argc!=5 && argc!=6) {
        fprintf(stderr,"usage: %s NEW_INDEX EXPECTED_MAJOR EXPECTED_MINOR zero|pointer|random|mixed [--write]\n",argv[0]);return 2;
    }
    unsigned index=number(argv[1]),expected_major=number(argv[2]),expected_minor=number(argv[3]);
    if(index==0 || index>31) {errno=EINVAL;fail("zram0/invalid index forbidden");}
    int write_requested=argc==6;
    if(write_requested && strcmp(argv[5],"--write")) {errno=EINVAL;fail("invalid write opt-in");}
    int profile=!strcmp(argv[4],"zero")?0:!strcmp(argv[4],"pointer")?1:!strcmp(argv[4],"random")?2:!strcmp(argv[4],"mixed")?3:-1;
    if(profile<0) {errno=EINVAL;fail("invalid corpus profile");}
    if(getuid()!=0 || sysconf(_SC_PAGESIZE)!=PAGE_BYTES) {errno=EPERM;fail("require root and4096byte pages");}
    char path[128],sys[128];
    snprintf(path,sizeof(path),"/dev/block/zram%u",index);
    snprintf(sys,sizeof(sys),"/sys/block/zram%u/dev",index);
    FILE *f=fopen(sys,"r");if(!f)fail("open sysfs device identity");
    unsigned maj,min;if(fscanf(f,"%u:%u",&maj,&min)!=2) {errno=EINVAL;fail("parse sysfs device identity");}fclose(f);
    struct stat s;if(lstat(path,&s))fail("stat device");
    if(!S_ISBLK(s.st_mode) || major(s.st_rdev)!=expected_major || minor(s.st_rdev)!=expected_minor || maj!=expected_major || min!=expected_minor) {
        errno=EINVAL;fail("sysfs/node/expected device identity mismatch");
    }
    require_unused(s.st_rdev);
    /* Exclusive block-device claim rejects mounted/swap devices and prevents
       their adoption while this file descriptor is held. No symlink traversal. */
    int fd=open(path,(write_requested?O_RDWR:O_RDONLY)|O_CLOEXEC|O_EXCL|O_NOFOLLOW);
    if(fd<0)fail("open exclusive device");
    struct stat opened;if(fstat(fd,&opened))fail("stat opened device");
    if(!S_ISBLK(opened.st_mode) || opened.st_rdev!=s.st_rdev ||
       major(opened.st_rdev)!=expected_major || minor(opened.st_rdev)!=expected_minor) {
        errno=EINVAL;fail("opened device identity mismatch");
    }
    uint64_t bytes=0;if(ioctl(fd,BLKGETSIZE64,&bytes))fail("block size ioctl");
    if(bytes!=CORPUS_BYTES) {errno=EINVAL;fail("require exact4MiB scratch device");}
    snprintf(sys,sizeof(sys),"/sys/block/zram%u/mm_stat",index);
    f=fopen(sys,"r");if(!f)fail("open zram stats");
    uint64_t original;if(fscanf(f,"%"SCNu64,&original)!=1) {errno=EINVAL;fail("parse zram stats");}fclose(f);
    if(original!=0) {errno=EBUSY;fail("scratch device already contains data");}
    if(!write_requested) {printf("{\"preflight\":true,\"index\":%u,\"bytes\":%u,\"wrote\":false}\n",index,CORPUS_BYTES);close(fd);return 0;}
    unsigned char input[PAGE_BYTES],output[PAGE_BYTES];uint64_t latencies[PAGES],cpus=0;
    uint64_t expected=UINT64_C(14695981039346656037),actual=expected;
    uint64_t cpu0=now(CLOCK_PROCESS_CPUTIME_ID),wall0=now(CLOCK_MONOTONIC);
    for(unsigned i=0;i<PAGES;i++) {
        page(input,i,profile);expected=checksum(expected,input);
        int cpu=sched_getcpu();if(cpu>=0 && cpu<64)cpus|=UINT64_C(1)<<cpu;
        uint64_t begin=now(CLOCK_MONOTONIC);
        if(pwrite(fd,input,PAGE_BYTES,(off_t)i*PAGE_BYTES)!=PAGE_BYTES)fail("write scratch page");
        latencies[i]=now(CLOCK_MONOTONIC)-begin;
    }
    uint64_t write_ns=now(CLOCK_MONOTONIC)-wall0,write_cpu_ns=now(CLOCK_PROCESS_CPUTIME_ID)-cpu0;
    cpu0=now(CLOCK_PROCESS_CPUTIME_ID);wall0=now(CLOCK_MONOTONIC);
    for(unsigned i=0;i<PAGES;i++) {
        if(pread(fd,output,PAGE_BYTES,(off_t)i*PAGE_BYTES)!=PAGE_BYTES)fail("read scratch page");
        page(input,i,profile);if(memcmp(input,output,PAGE_BYTES)) {errno=EIO;fail("scratch readback mismatch");}
        actual=checksum(actual,output);
    }
    uint64_t read_ns=now(CLOCK_MONOTONIC)-wall0,read_cpu_ns=now(CLOCK_PROCESS_CPUTIME_ID)-cpu0;
    if(actual!=expected) {errno=EIO;fail("corpus checksum mismatch");}
    require_unused(s.st_rdev);if(close(fd))fail("close scratch device");
    qsort(latencies,PAGES,sizeof(latencies[0]),compare_u64);
    printf("{\"index\":%u,\"profile\":\"%s\",\"bytes\":%u,\"pages\":%u,\"write_ns\":%"PRIu64",\"write_cpu_ns\":%"PRIu64",\"read_ns\":%"PRIu64",\"read_cpu_ns\":%"PRIu64",\"write_page_p50_ns\":%"PRIu64",\"write_page_p95_ns\":%"PRIu64",\"write_cpu_mask\":%"PRIu64",\"checksum\":\"%016"PRIx64"\",\"readback_verified\":true}\n",
        index,argv[4],CORPUS_BYTES,PAGES,write_ns,write_cpu_ns,read_ns,read_cpu_ns,latencies[PAGES/2],latencies[(PAGES*95+99)/100-1],cpus,actual);
    return 0;
}
