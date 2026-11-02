"""Verify exact installed-library ADN dispatch, offline. Never sends a request.

Requires pyelftools and capstone. Fixed ranges are guarded by the whole-file hash.
This is a dispatch proof only, not a wire-format or response validation.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--library", type=Path, default=Path("work/radio-vendor-closure/vendor/lib/libril-qc-hal-qmi.so"))
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()
blob = a.library.read_bytes()
digest = hashlib.sha256(blob).hexdigest()
if digest != "47965523c6b7ca56d9c930198c4f9acc6a9c7b34d12100b0ff068f9305b293dd":
    raise ValueError("Library differs from handset-bound candidate; rederive ranges")
elf = ELFFile(io.BytesIO(blob))


def read(address, length):
    for segment in elf.iter_segments():
        if segment["p_type"] == "PT_LOAD" and segment["p_vaddr"] <= address and address + length <= segment["p_vaddr"] + segment["p_filesz"]:
            offset = segment["p_offset"] + address - segment["p_vaddr"]
            return blob[offset:offset + length]
    raise ValueError("Address outside file-backed LOAD segments")


def instructions(address, length, mode):
    engine = Cs(CS_ARCH_ARM, mode)
    engine.detail = True
    result = list(engine.disasm(read(address, length), address))
    if sum(i.size for i in result) != length:
        raise ValueError("Incomplete code range decode")
    return result


dynsym = elf.get_section_by_name(".dynsym")
relocations = {r["r_offset"]: dynsym.get_symbol(r["r_info_sym"]).name
               for r in elf.get_section_by_name(".rel.plt").iter_relocations()}
results = []
for low, compare, branch, block, call, plt, suffix in [
    (0xdd, 0xf18ac4, 0xf18ace, 0xf18b3a, 0xf18b44, 0xff2620, "12getAdnRecordEi"),
    (0xde, 0xf18ad2, 0xf18adc, 0xf18b50, 0xf18b62, 0xff2630, "15updateAdnRecordEiPhj"),
]:
    code = instructions(compare, branch + 2 - compare, CS_MODE_THUMB)
    if [(i.mnemonic, i.op_str) for i in code[:4]] != [
        ("movs", "r0, #0x%x" % low), ("movt", "r0, #8"),
        ("ldr", "r1, [sp, #0xac]"), ("cmp", "r1, r0")]:
        raise ValueError("Unexpected request comparison")
    if code[-1].mnemonic != "beq" or code[-1].operands[0].imm != block:
        raise ValueError("Dispatch branch target mismatch")
    body = instructions(block, call + 4 - block, CS_MODE_THUMB)
    if body[-1].mnemonic != "blx" or body[-1].operands[0].imm != plt:
        raise ValueError("Dispatch call target mismatch")
    # Resolve the actual ARM PLT instructions to their GOT relocation, rather
    # than assuming a linker-specific entry size or relocation ordering.
    thunk = instructions(plt, 12, CS_MODE_ARM)
    if [i.mnemonic for i in thunk] != ["add", "add", "ldr"]:
        raise ValueError("Unexpected PLT implementation")
    if thunk[0].op_str != "ip, pc, #0, #12" or not thunk[1].op_str.startswith("ip, ip,") or not thunk[2].op_str.startswith("pc, [ip,"):
        raise ValueError("Unexpected PLT register flow")
    got = plt + 8 + thunk[1].operands[2].imm + thunk[2].operands[1].mem.disp
    symbol = relocations[got]
    if not symbol.endswith(suffix):
        raise ValueError("PLT relocation does not name the expected handler")
    target = next(s for s in dynsym.iter_symbols() if s.name == symbol)
    if target["st_shndx"] == "SHN_UNDEF":
        raise ValueError("Handler is not defined in this binary")
    results.append({
        "request_id": hex(0x80000 | low), "comparison": hex(compare),
        "equal_branch": hex(branch), "dispatch_block": hex(block),
        "call": hex(call), "plt": hex(plt), "got_relocation": hex(got),
        "handler_symbol": symbol, "handler_thumb_address": hex(target["st_value"]),
        "comparison_bytes": read(compare, branch + 2 - compare).hex(),
        "call_bytes": read(call, 4).hex(),
    })
report = {"library_sha256": digest, "scope": "Offline dispatch and PLT/GOT resolution in the exact handset-matched library",
          "requests": results, "header_fully_validated": False,
          "response_layout_validated": False, "request_sent": False,
          "capacity_semantics_validated": False}
a.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print("Verified read/update dispatch IDs and handler relocations; no request sent.")
