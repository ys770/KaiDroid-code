"""Prepare a default-off older-arena tail realloc prototype, entirely offline."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'work/memory/reconstruction-source-inputs05/source/art/libartbase/base/arena_allocator.h'
SOURCE_SHA = 'fae95dd18870bda8ba7f0b090834fc02b25775d997cfec033630472739eb7562'
FLAG = 'KAIDROID_ARENA_NONCURRENT_TAIL_REALLOC'
DEFINE = '''// BEGIN KAIDROID_NONCURRENT_TAIL_DEFINE
#ifndef KAIDROID_ARENA_NONCURRENT_TAIL_REALLOC
#define KAIDROID_ARENA_NONCURRENT_TAIL_REALLOC 0
#endif
#if KAIDROID_ARENA_NONCURRENT_TAIL_REALLOC != 0 && KAIDROID_ARENA_NONCURRENT_TAIL_REALLOC != 1
#error "KAIDROID_ARENA_NONCURRENT_TAIL_REALLOC must be 0 or 1"
#endif
// END KAIDROID_NONCURRENT_TAIL_DEFINE

'''
BRANCH = '''// BEGIN KAIDROID_NONCURRENT_TAIL_BRANCH
#if KAIDROID_ARENA_NONCURRENT_TAIL_REALLOC
    // A non-current arena's allocated prefix is final until we explicitly
    // extend it. Reuse only that prefix's last allocation, never a live middle
    // block. Memory-tool red zones keep the original allocation/copy path.
    if (ptr != nullptr && arena_head_ != nullptr && !IsRunningOnMemoryTool()) {
      const size_t aligned_new_size = RoundUp(new_size, kAlignment);
      if (aligned_new_size > aligned_ptr_size) {
        const size_t size_delta = aligned_new_size - aligned_ptr_size;
        size_t examined = 0;
        for (Arena* arena = arena_head_->next_;
             arena != nullptr && examined != 16u;
             arena = arena->next_, ++examined) {
          const size_t used = arena->GetBytesAllocated();
          if (used >= aligned_ptr_size && used <= arena->Size() &&
              reinterpret_cast<uint8_t*>(ptr) == arena->Begin() + used - aligned_ptr_size &&
              size_delta <= arena->Size() - used) {
            // Preserve the zero-initialized growth contract, including any
            // padding that now becomes part of the caller's logical array.
            memset(reinterpret_cast<uint8_t*>(ptr) + ptr_size, 0, new_size - ptr_size);
            arena->bytes_allocated_ = used + size_delta;
            ArenaAllocatorStats::RecordAlloc(size_delta, kind);
            return ptr;
          }
        }
      }
    }
#endif
// END KAIDROID_NONCURRENT_TAIL_BRANCH
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def project_off(text):
    for tag in ('DEFINE', 'BRANCH'):
        begin = '// BEGIN KAIDROID_NONCURRENT_TAIL_' + tag + '\n'
        end = '// END KAIDROID_NONCURRENT_TAIL_' + tag + '\n'
        if text.count(begin) != 1 or text.count(end) != 1:
            raise ValueError('Unique inserted region required')
        start = text.index(begin)
        stop = text.index(end, start) + len(end)
        if tag == 'DEFINE':
            stop += 1  # The inserted include-to-namespace separator.
        text = text[:start] + text[stop:]
    return text


def realloc_body(text):
    start = text.index('  void* Realloc(void* ptr,')
    stop = text.index('\n  template <typename T>', start)
    return text[start:stop]


def prepare(output):
    raw = SOURCE.read_bytes()
    if sha(raw) != SOURCE_SHA:
        raise ValueError('Exact source header required')
    original = raw.decode()
    namespace = 'namespace art {\n'
    fallback = '    auto* new_ptr = Alloc(new_size, kind);  // Note: Alloc will take care of aligning new_size.\n'
    if original.count(namespace) != 1 or original.count(fallback) != 1:
        raise ValueError('Source insertion boundary changed')
    candidate = original.replace(namespace, DEFINE + namespace).replace(fallback, BRANCH + fallback)
    if project_off(candidate) != original:
        raise ValueError('Default-off source projection differs')
    output.mkdir(parents=True, exist_ok=False)
    (output / 'arena_allocator.h').write_bytes(candidate.encode())
    patch = ''.join(difflib.unified_diff(original.splitlines(True), candidate.splitlines(True),
                    fromfile='a/art/libartbase/base/arena_allocator.h',
                    tofile='b/art/libartbase/base/arena_allocator.h', n=0))
    (output / 'candidate.patch').write_bytes(patch.encode())
    # Compile the exact extracted Realloc bodies in an ordinary-file/state model.
    # Dependencies and pool behavior are synthetic; full ART is not built here.
    prelude = (ROOT / 'experiments/memory/arena-noncurrent-tail-fixture01.cpp').read_text()
    original_fn = realloc_body(original)
    candidate_fn = realloc_body(candidate)
    fixture = prelude.replace('/* ORIGINAL_REALLOC_BODY */', original_fn)
    fixture = fixture.replace('/* CANDIDATE_REALLOC_BODY */', candidate_fn)
    (output / 'fixture.cpp').write_bytes(fixture.encode())
    manifest = dict(classification='offline_default_off_allocator_prototype', source_sha256=SOURCE_SHA,
                    candidate_sha256=sha(candidate.encode()), patch_sha256=sha(patch.encode()),
                    fixture_sha256=sha(fixture.encode()), default_off_projection_identical=True,
                    flag=FLAG, default_enabled=False, scan_limit=16,
                    new_class_fields=False, target_compiled=False, installed=False,
                    measured_phone_savings=False, ready_for_build=False)
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.output), indent=2))
