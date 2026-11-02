"""Prepare a pinned LoadedArsc sparse name-lookup fix without editing AOSP."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

BASE_SHA = '44ff1883795923dd968033e3900f69bccb663901c99217e3fb537ee60772a5dc'
OLD = '''    size_t entry_count = dtohl(type->entryCount);
    for (size_t entry_idx = 0; entry_idx < entry_count; entry_idx++) {
      const uint32_t* entry_offsets = reinterpret_cast<const uint32_t*>(
          reinterpret_cast<const uint8_t*>(type) + dtohs(type->header.headerSize));
      const uint32_t offset = dtohl(entry_offsets[entry_idx]);
      if (offset != ResTable_type::NO_ENTRY) {
        const ResTable_entry* entry = reinterpret_cast<const ResTable_entry*>(
            reinterpret_cast<const uint8_t*>(type) + dtohl(type->entriesStart) + offset);
        if (dtohl(entry->key.index) == static_cast<uint32_t>(key_idx)) {
          // The package ID will be overridden by the caller (due to runtime assignment of package
          // IDs for shared libraries).
          return make_resid(0x00, type_idx + type_id_offset_ + 1, entry_idx);
        }
      }
    }
'''
NEW = '''    const size_t entry_count = dtohl(type->entryCount);
    const size_t offsets_start = dtohs(type->header.headerSize);
    const size_t entries_start = dtohl(type->entriesStart);
    const size_t chunk_size = dtohl(type->header.size);
    if (offsets_start > entries_start || entries_start > chunk_size ||
        entry_count > (entries_start - offsets_start) / sizeof(uint32_t)) {
      continue;
    }
    const uint8_t* offsets = reinterpret_cast<const uint8_t*>(type) + offsets_start;
    for (size_t slot = 0; slot < entry_count; slot++) {
      uint32_t entry_idx;
      uint32_t offset;
      if (type->flags & ResTable_type::FLAG_SPARSE) {
        const auto* sparse = reinterpret_cast<const ResTable_sparseTypeEntry*>(offsets);
        entry_idx = dtohs(sparse[slot].idx);
        offset = uint32_t{dtohs(sparse[slot].offset)} * 4u;
      } else {
        entry_idx = slot;
        offset = dtohl(reinterpret_cast<const uint32_t*>(offsets)[slot]);
      }
      if (offset == ResTable_type::NO_ENTRY) {
        continue;
      }
      const ResTable_entry* entry = GetEntryFromOffset(type, offset);
      if (entry != nullptr && dtohl(entry->key.index) == static_cast<uint32_t>(key_idx)) {
        // The package ID will be assigned by the caller, including for shared libraries.
        return make_resid(0x00, type_idx + type_id_offset_ + 1, entry_idx);
      }
    }
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    raw = a.source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != BASE_SHA:
        raise ValueError('Unexpected source hash')
    source = raw.decode('utf-8')
    if source.count(OLD) != 1:
        raise ValueError('Expected exactly one dense-only name lookup loop')
    updated = source.replace(OLD, NEW)
    a.output.mkdir(parents=True, exist_ok=False)
    (a.output / 'LoadedArsc.cpp').write_bytes(updated.encode('utf-8'))
    (a.output / 'change.patch').write_text(''.join(difflib.unified_diff(
        source.splitlines(True), updated.splitlines(True),
        fromfile='a/libs/androidfw/LoadedArsc.cpp', tofile='b/libs/androidfw/LoadedArsc.cpp')))
    report = dict(base_sha256=BASE_SHA, candidate_sha256=hashlib.sha256(updated.encode()).hexdigest(),
                  sparse_indices_preserved=True, checked_entry_lookup=True, built=False, installed=False)
    (a.output / 'candidate.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
