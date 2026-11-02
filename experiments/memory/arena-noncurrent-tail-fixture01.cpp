// Native synthetic-dependency model. Exact Realloc bodies are inserted offline.
#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>
#define ALWAYS_INLINE
#define DCHECK_GE(a,b) assert((a)>=(b))
#define DCHECK_EQ(a,b) assert((a)==(b))
#define DCHECK(a) assert(a)
#define DCHECK_ALIGNED(p,n) assert(reinterpret_cast<uintptr_t>(p)%(n)==0)
static size_t copied=0;
static void* ModelMemcpy(void* dst,const void* src,size_t count) {
  copied+=count;
  return count ? std::memcpy(dst,src,count) : dst;
}
#define memcpy ModelMemcpy
static size_t RoundUp(size_t n,size_t a) {return (n+a-1)&~(a-1);}
enum ArenaAllocKind {kArenaAllocMisc};
struct ArenaAllocatorStats {
  static inline size_t charged=0;
  static void RecordAlloc(size_t n,ArenaAllocKind) {charged+=n;}
};
struct Arena {
  alignas(16) std::array<uint8_t,65536> memory{};
  size_t bytes_allocated_=0,size_=65536;
  Arena* next_=nullptr;
  size_t GetBytesAllocated() const {return bytes_allocated_;}
  size_t Size() const {return size_;}
  uint8_t* Begin() {return memory.data();}
};
struct ModelBase {
  static constexpr size_t kAlignment=8;
  Arena* arena_head_;
  uint8_t *ptr_,*end_;
  bool memory_tool=false;
  std::vector<std::unique_ptr<uint8_t[]>> fallback;
  explicit ModelBase(Arena* head,size_t used):arena_head_(head),
      ptr_(head->Begin()+used),end_(head->Begin()+head->Size()) {}
  bool IsRunningOnMemoryTool() {return memory_tool;}
  void* Alloc(size_t n,ArenaAllocKind kind) {
    n=RoundUp(n,8);ArenaAllocatorStats::RecordAlloc(n,kind);
    fallback.emplace_back(new uint8_t[n]{});return fallback.back().get();
  }
};
struct Original : ModelBase {
  using ModelBase::ModelBase;
/* ORIGINAL_REALLOC_BODY */
};
#define KAIDROID_ARENA_NONCURRENT_TAIL_REALLOC 1
struct Candidate : ModelBase {
  using ModelBase::ModelBase;
/* CANDIDATE_REALLOC_BODY */
};
#undef KAIDROID_ARENA_NONCURRENT_TAIL_REALLOC
#define KAIDROID_ARENA_NONCURRENT_TAIL_REALLOC 0
struct DefaultOff : ModelBase {
  using ModelBase::ModelBase;
/* CANDIDATE_REALLOC_BODY */
};
struct Outcome {size_t charged,copied,used;bool same;};
template<class Allocator>
Outcome older_case(size_t old_size,size_t new_size,size_t free_tail,
                   bool final_block=true,bool tool=false,size_t older_index=0) {
  const size_t aligned_old=RoundUp(old_size,8);
  auto arenas=std::make_unique<Arena[]>(older_index+2);
  Arena* head=&arenas[0];
  for(size_t i=0;i<older_index+1;++i) arenas[i].next_=&arenas[i+1];
  Arena* older=&arenas[older_index+1];
  older->size_=65536;
  older->bytes_allocated_=65536-free_tail;
  const size_t intervening=final_block ? 0 : 8;
  uint8_t* input=older->Begin()+older->bytes_allocated_-aligned_old-intervening;
  std::memset(input,0x5a,old_size);
  // Padding is outside the old logical array; exercise explicit zeroing on growth.
  if(aligned_old>old_size) std::memset(input+old_size,0xa5,aligned_old-old_size);
  if(intervening) std::memset(input+aligned_old,0xcc,intervening);
  Allocator allocator(head,256);allocator.memory_tool=tool;
  auto* old_bump=allocator.ptr_;auto* old_end=allocator.end_;
  ArenaAllocatorStats::charged=0;copied=0;
  auto* result=static_cast<uint8_t*>(allocator.Realloc(input,old_size,new_size));
  for(size_t i=0;i<old_size;++i) assert(result[i]==0x5a);
  for(size_t i=old_size;i<new_size;++i) assert(result[i]==0);
  if(intervening) for(size_t i=0;i<intervening;++i) assert(input[aligned_old+i]==0xcc);
  assert(allocator.arena_head_==head && allocator.ptr_==old_bump && allocator.end_==old_end);
  return {ArenaAllocatorStats::charged,copied,older->bytes_allocated_,result==input};
}
int main() {
  // An actual services-declaration-sized example: 728 ArtMethods +4-byte prefix.
  constexpr size_t old_size=4+728*28,new_size=4+729*28;
  auto baseline=older_case<Original>(old_size,new_size,32);
  auto candidate=older_case<Candidate>(old_size,new_size,32);
  auto off=older_case<DefaultOff>(old_size,new_size,32);
  assert(!baseline.same && !off.same && candidate.same);
  assert(baseline.charged==20416 && candidate.charged==24);
  assert(baseline.copied==20388 && candidate.copied==0);
  assert(candidate.used==65528 && baseline.used==65504 && off.used==65504);
  assert(off.charged==baseline.charged && off.copied==baseline.copied);
  for(bool tool:{false,true}) for(bool last:{false,true}) for(size_t free:{0u,8u,24u,32u,64u}) {
    auto a=older_case<Original>(60,88,free,last,tool);
    auto b=older_case<Candidate>(60,88,free,last,tool);
    auto c=older_case<DefaultOff>(60,88,free,last,tool);
    bool eligible=!tool && last && free>=24;
    assert(b.same==eligible);
    assert(a.charged==c.charged && a.copied==c.copied);
    assert(b.charged==(eligible ? 24 : 88));
    assert(b.copied==(eligible ? 0 : 60));
    assert(b.used==65536-free+(eligible ? 24 : 0));
    assert(a.used==65536-free && c.used==a.used);
  }
  auto last_in_bound=older_case<Candidate>(60,88,32,true,false,15);
  auto beyond_bound=older_case<Candidate>(60,88,32,true,false,16);
  assert(last_in_bound.same && !beyond_bound.same);
  // A block followed by another live block must remain on allocate/copy.
  assert(!older_case<Candidate>(60,88,64,false).same);
  // Existing current-arena growth is preserved.
  {
    auto head=std::make_unique<Arena>();Candidate a(head.get(),64);
    auto* input=head->Begin();std::memset(input,0x3c,60);
    ArenaAllocatorStats::charged=0;copied=0;
    assert(a.Realloc(input,60,88)==input && a.ptr_==head->Begin()+88);
    assert(ArenaAllocatorStats::charged==24 && copied==0);
    for(size_t i=0;i<60;++i) assert(input[i]==0x3c);
    for(size_t i=60;i<88;++i) assert(input[i]==0);
  }
  // Null/foreign inputs cannot be adopted as an old arena tail.
  {
    auto head=std::make_unique<Arena>();Candidate a(head.get(),64);
    copied=0;ArenaAllocatorStats::charged=0;
    assert(a.Realloc(nullptr,0,32)!=nullptr && copied==0);
    alignas(8) uint8_t foreign[64]{};
    assert(a.Realloc(foreign,32,64)!=foreign && copied==32);
  }
  uint32_t seed=0x243f6a88;
  for(size_t trial=0;trial<1000;++trial) {
    seed=seed*1664525u+1013904223u;
    size_t old_bytes=1+(seed%1024),new_bytes=old_bytes+1+((seed>>10)%96);
    size_t free=((seed>>18)%17)*8;
    bool last=(seed&1),tool=(seed&2);
    auto a=older_case<Original>(old_bytes,new_bytes,free,last,tool);
    auto b=older_case<Candidate>(old_bytes,new_bytes,free,last,tool);
    auto c=older_case<DefaultOff>(old_bytes,new_bytes,free,last,tool);
    const size_t delta=RoundUp(new_bytes,8)-RoundUp(old_bytes,8);
    bool eligible=last && !tool && delta>0 && free>=delta;
    assert(b.same==eligible && a.charged==c.charged && a.copied==c.copied);
    assert(b.used==65536-free+(eligible ? delta : 0));
    assert(a.used==65536-free && c.used==a.used);
  }
  std::cout<<"{\"result\":\"PASS\",\"fuzz_cases\":1000,"
    "\"example_baseline_charge_bytes\":20416,\"example_candidate_charge_bytes\":24,"
    "\"example_avoided_copy_bytes\":20388,\"target_execution\":false}"<<std::endl;
}
