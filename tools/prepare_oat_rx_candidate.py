"""Generate a reviewable, unbuilt two-artifact RX advice candidate offline."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

ORIGINAL='f8cc7ff272f5688e259bc2dd8aafe1b37649399922d4248c1e1c0f12405d9800'
ANCHOR='''                                                      MADV_RANDOM);
  }
  const OatDexFile* oat_dex_file = dex_file.GetOatDexFile();'''
INSERT='''                                                      MADV_RANDOM);

    // Experimental RX-only advice for two reviewed N139DL OAT artifacts.
    // Logical locations are not physical filenames; also require the exact
    // reviewed header/size tuple before advising code owned by this OatFile.
    const OatDexFile* loaded_oat_dex_file = dex_file.GetOatDexFile();
    const OatFile* loaded_oat_file = loaded_oat_dex_file != nullptr
        ? loaded_oat_dex_file->GetOatFile() : nullptr;
    if (loaded_oat_file != nullptr && loaded_oat_file->IsExecutable()) {
      const std::string& location = loaded_oat_file->GetLocation();
      const bool services = location == "/system/framework/oat/arm/services.odex";
      const bool framework = location == "/system/framework/boot-framework.oat";
      if (services || framework) {
        const OatHeader& header = loaded_oat_file->GetOatHeader();
        const uint32_t checksum = services ? 1705782879u : 3542819386u;
        const size_t oat_size = services ? 12699918u : 9437174u;
        const uint32_t code_offset = services ? 2895872u : 2023424u;
        if (header.IsValid() && header.GetChecksum() == checksum &&
            loaded_oat_file->Size() == oat_size &&
            header.GetExecutableOffset() == code_offset) {
          // Existing helper rounds inward. Do not include R metadata, BSS,
          // relro, VDEX reservations or the final partial code page.
          const int saved_errno = errno;
          DexLayoutSection::MadviseLargestPageAlignedRegion(
              loaded_oat_file->Begin() + code_offset, loaded_oat_file->End(), MADV_RANDOM);
          errno = saved_errno;
        }
      }
    }
  }
  const OatDexFile* oat_dex_file = dex_file.GetOatDexFile();'''


def generate(original):
    if hashlib.sha256(original).hexdigest()!=ORIGINAL:raise ValueError('Exact source identity required')
    text=original.decode()
    if text.count(ANCHOR)!=1 or text.count('#include <cstdlib>')!=1:raise ValueError('Source anchor differs')
    candidate=text.replace('#include <cstdlib>','#include <cerrno>\n#include <cstdlib>',1).replace(ANCHOR,INSERT,1)
    return candidate.encode()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True)
    a=p.parse_args();raw=a.source.read_bytes();candidate=generate(raw)
    out=a.output_dir.resolve()
    if not out.is_relative_to(Path.cwd().resolve()):raise ValueError('Keep outputs in workspace')
    out.mkdir(parents=True,exist_ok=False)
    (out/'original.cc').write_bytes(raw);(out/'candidate.cc').write_bytes(candidate)
    patch=''.join(difflib.unified_diff(raw.decode().splitlines(True),candidate.decode().splitlines(True),
                                     fromfile='a/art/runtime/oat_file.cc',tofile='b/art/runtime/oat_file.cc'))
    # Unified-diff blank context lines require a single prefix space. Check
    # added source payloads separately rather than stripping patch context.
    for line in patch.splitlines():
        if line.startswith('+') and not line.startswith('+++') and line[1:].rstrip(' \t')!=line[1:]:
            raise ValueError('Trailing whitespace in added source')
    (out/'candidate.patch').write_bytes(patch.encode())
    report=dict(original_sha256=ORIGINAL,candidate_sha256=hashlib.sha256(candidate).hexdigest(),
        patch_sha256=hashlib.sha256(patch.encode()).hexdigest(),scope=['cerrno include','one existing function; existing DEX/layout code retained'],
        bound_system_image_sha256='b9d55804123a82064e3e0c806767e119cf2d628929eeb9c9e1482d886a475471',
        future_preopt_changes_require_new_artifact_review=True,
        built=False,installed=False,host_controls_pending=True,
        limits=['CRC/size/offset is an experimental owner filter, not authentication.',
                'Logical default boot location is source/host-helper verified; live selection still unobserved.',
                'No target compile, ABI/code-diff gate, VM flags or runtime performance evidence yet.'])
    (out/'candidate.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))


if __name__=='__main__':main()
