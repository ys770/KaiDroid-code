"""Prepare default-off phase-only ART source patches offline; never compile or install."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FLAG = 'KAIDROID_SERVICES_PHASE_DIAGNOSTICS'
ACQUISITION_SHA = '163af73b3e723850f68cac7820ccb0cf8db9539bcc8365e8f1ffe3fc2560cd2b'
SOURCES = {
    '55': ('work/memory/madvise-random01/source/art/runtime/oat_file_manager.cc',
           '9b2d2869e0138fc00810a276a63c653c423d3173f5d3a8ac521dd62ceb15e521'),
    '56': ('work/memory/services-image55-host02/apply/art/runtime/oat_file_manager.cc',
           'f35f5abc6310b349fb57aed5091ea5a677bb07ac523aeb86d17522195de1c09f'),
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def guarded(body):
    return '#if ' + FLAG + '\n' + body + '#endif  // ' + FLAG + '\n'


HELPER = '''namespace {
// Saturating 32-bit IDs avoid a 64-bit atomic on ARM32. Contention or exhaustion
// produces an explicit invalid-ID sentinel; it never changes the load path.
static_assert(ATOMIC_INT_LOCK_FREE == 2, "Phase diagnostics require lock-free int atomics");
static_assert(sizeof(uint32_t) == sizeof(unsigned int), "Phase diagnostic ID width");
uint32_t NextServicesPhaseId() {
  static std::atomic<uint32_t> next{0};
  uint32_t value = next.load(std::memory_order_relaxed);
  for (unsigned int attempt = 0; attempt != 8; ++attempt) {
    if (value == UINT32_MAX) {
      return UINT32_MAX;
    }
    if (next.compare_exchange_weak(value, value + 1, std::memory_order_relaxed)) {
      return value;
    }
  }
  return UINT32_MAX;
}

struct ServicesPhaseRecord {
  uint32_t id = UINT32_MAX;
  uint64_t start_ns = 0;
  uint64_t phase_start_ns = 0;
  uint64_t decision_ns = 0;
  uint64_t open_ns = 0;
  uint64_t add_ns = 0;
  uint64_t fallback_ns = 0;
  bool decision = false;
  bool opened = false;
  bool add_attempted = false;
  bool added = false;
  bool fallback_used = false;
};
}  // namespace

'''


def transform(text, image):
    """Insert guarded diagnostics only. Return additions for exact off projection."""
    additions = []

    def insert(anchor, body, before=False):
        nonlocal text
        if text.count(anchor) != 1:
            raise ValueError('Unique source anchor required: ' + anchor[:80])
        text = text.replace(anchor, body + anchor if before else anchor + body, 1)
        additions.append(body)

    config = ('#ifndef ' + FLAG + '\n#define ' + FLAG + ' 0\n#endif\n'
              '#if ' + FLAG + ' != 0 && ' + FLAG + ' != 1\n'
              '#error "KAIDROID_SERVICES_PHASE_DIAGNOSTICS must be 0 or 1"\n#endif\n')
    insert('#include "oat_file_manager.h"\n', config + guarded(
        '#include <atomic>\n#include <cstdint>\n#include "base/time_utils.h"\n' +
        ('#include "gc/heap.h"\n#include "oat.h"\n' if image == '55' else '')))
    insert('static constexpr bool kEnableAppImage = true;\n', guarded(HELPER))
    insert('  if (source_oat_file != nullptr) {\n    bool added_image_space = false;\n', guarded('''    // Exact reviewed services OAT only. This condition observes; it does not
    // replace or broaden ShouldLoadAppImage's policy or validation.
    const OatHeader& phase_header = source_oat_file->GetOatHeader();
    const bool phase_enabled = runtime->GetHeap() != nullptr &&
        runtime->GetHeap()->IsLowMemoryMode() && source_oat_file->IsExecutable() &&
        source_oat_file->GetLocation() == "/system/framework/oat/arm/services.odex" &&
        phase_header.IsValid() && phase_header.GetChecksum() == 307763368u &&
        source_oat_file->Size() == 12699918u &&
        phase_header.GetExecutableOffset() == 2895872u;
    ServicesPhaseRecord phase;
    if (phase_enabled) {
      phase.id = NextServicesPhaseId();
      phase.start_ns = NanoTime();
    }
'''))
    insert('      if (ShouldLoadAppImage(check_collision_result,\n', guarded('''      if (phase_enabled) {
        phase.phase_start_ns = NanoTime();
      }
'''), before=True)
    insert('''      if (ShouldLoadAppImage(check_collision_result,
                             source_oat_file,
                             context.get(),
                             &error_msg)) {
''', guarded('''        if (phase_enabled) {
          phase.decision = true;
          phase.decision_ns = NanoTime() - phase.phase_start_ns;
          phase.phase_start_ns = NanoTime();
        }
'''))
    insert('        image_space = oat_file_assistant.OpenImageSpace(source_oat_file);\n', guarded('''        if (phase_enabled) {
          phase.open_ns = NanoTime() - phase.phase_start_ns;
          phase.opened = image_space != nullptr;
        }
'''))
    insert('      if (image_space != nullptr) {\n', guarded('''      if (phase_enabled && !phase.decision) {
        phase.decision_ns = NanoTime() - phase.phase_start_ns;
      }
'''), before=True)
    insert('            added_image_space = runtime->GetClassLinker()->AddImageSpace(image_space.get(),\n', guarded('''            if (phase_enabled) {
              phase.add_attempted = true;
              phase.phase_start_ns = NanoTime();
            }
'''), before=True)
    insert('                                                                         /*out*/&temp_error_msg);\n', guarded('''            if (phase_enabled) {
              phase.add_ns = NanoTime() - phase.phase_start_ns;
              phase.added = added_image_space;
            }
'''))
    insert('      dex_files = oat_file_assistant.LoadDexFiles(*source_oat_file, dex_location);\n', guarded('''      if (phase_enabled) {
        phase.fallback_used = true;
        phase.phase_start_ns = NanoTime();
      }
'''), before=True)
    insert('      dex_files = oat_file_assistant.LoadDexFiles(*source_oat_file, dex_location);\n', guarded('''      if (phase_enabled) {
        phase.fallback_ns = NanoTime() - phase.phase_start_ns;
      }
'''))
    insert('    if (dex_files.empty()) {\n      error_msgs->push_back("Failed to open dex files from " + source_oat_file->GetLocation());\n', guarded('''    // All image/GC/class critical scopes above have ended. Logging overhead is
    // outside measured phases; it can still perturb subsequent boot activity.
    if (phase_enabled) {
      const uint64_t end_ns = NanoTime();
      LOG(INFO) << "KV_SERVICES_PHASE_V1 source=services55-oat125818a8"
                << " id=" << phase.id << " id_valid=" << (phase.id != UINT32_MAX)
                << " start_ns=" << phase.start_ns << " end_ns=" << end_ns
                << " decision=" << phase.decision << " decision_ns=" << phase.decision_ns
                << " opened=" << phase.opened << " open_ns=" << phase.open_ns
                << " add_attempted=" << phase.add_attempted << " added=" << phase.added
                << " add_ns=" << phase.add_ns << " fallback=" << phase.fallback_used
                << " fallback_ns=" << phase.fallback_ns << " dex_count=" << dex_files.size()
                << " dex_empty=" << dex_files.empty() << " phase_complete=1";
    }
'''), before=True)
    return text, additions


def prepare(output):
    receipt_path = ROOT / 'work/memory/reconstruction-source-inputs01/receipt.json'
    if sha(receipt_path) != ACQUISITION_SHA:
        raise ValueError('Exact reviewed source acquisition receipt required')
    receipt = json.loads(receipt_path.read_text())
    compile_path = ROOT / 'work/memory/libart-compile03/compile-record.json'
    if sha(compile_path) != receipt['compile_record_sha256']:
        raise ValueError('Compile receipt differs')
    compile_record = json.loads(compile_path.read_text())
    for row in receipt['files']:
        path = ROOT / 'work/memory/reconstruction-source-inputs01/source' / row['path']
        if sha(path) != row['sha256'] or path.stat().st_size != row['size']:
            raise ValueError('Acquired source differs: ' + row['path'])
        if row['compile03_read_input_sha256'] is not None:
            key = '/opt/kaidroid/kaidroid-build-20261023/aosp/' + row['path']
            if compile_record['read_inputs'][key] != row['sha256']:
                raise ValueError('Header is not bound to compile03')
    prepared = []
    for image, (relative, pin) in SOURCES.items():
        path = ROOT / relative
        if sha(path) != pin:
            raise ValueError('Exact original/candidate manager required')
        original = path.read_text()
        candidate, additions = transform(original, image)
        projected = candidate
        for body in reversed(additions):
            if projected.count(body) != 1:
                raise ValueError('Diagnostic insertion closure differs')
            projected = projected.replace(body, '', 1)
        if projected != original:
            raise ValueError('Default-off source projection differs')
        patch = ''.join(difflib.unified_diff(original.splitlines(True), candidate.splitlines(True),
                    fromfile='a/art/runtime/oat_file_manager.cc', tofile='b/art/runtime/oat_file_manager.cc'))
        prepared.append((image, original, candidate, patch, pin))
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    for image, original, candidate, patch, pin in prepared:
        source = output / ('image' + image) / 'art/runtime/oat_file_manager.cc'
        source.parent.mkdir(parents=True)
        source.write_bytes(candidate.encode())
        patch_path = output / ('services-phase-image' + image + '-01.patch')
        patch_path.write_bytes(patch.encode())
        rows.append(dict(image=image, original_sha256=pin, candidate_sha256=sha(source),
                         patch_sha256=sha(patch_path), default_off_projection_identical=True))
    result = dict(classification='offline_phase_diagnostic_patch_for_review',
                  source_acquisition_receipt_sha256=sha(receipt_path),
                  compile_record_sha256=sha(compile_path), sources=rows,
                  compile_flag=FLAG, default_enabled=False, compiled=False, installed=False,
                  allocation_attribution=False, stage_B_compiled_TU_binding_proven=False,
                  ready_for_build=False, savings_proven=False, generator_sha256=sha(Path(__file__)))
    (output / 'result.json').write_bytes((json.dumps(result, indent=2) + '\n').encode())
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.output_dir)))
