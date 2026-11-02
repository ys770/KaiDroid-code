"""Execute the pinned radio library's notification serializer on synthetic data.

Offline ARM emulation only. Allocation and checked memcpy are modeled; no radio,
Binder, SIM, filesystem writes on the handset, or proprietary payloads involved.
Requires unicorn and pyelftools. This does NOT validate request headers.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--library", type=Path, default=Path("work/radio-vendor-closure/vendor/lib/libril-qc-hal-qmi.so"))
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
blob = args.library.read_bytes()
digest = hashlib.sha256(blob).hexdigest()
if digest != "47965523c6b7ca56d9c930198c4f9acc6a9c7b34d12100b0ff068f9305b293dd":
    raise ValueError("Unexpected library")
elf = ELFFile(io.BytesIO(blob))
symbols = elf.get_section_by_name(".dynsym")
target = next(s for s in symbols.iter_symbols() if s.name.endswith("19constructOemHookRawEPjiPhj"))
if target["st_value"] != 0xf2736d or target["st_size"] != 384:
    raise ValueError("Unexpected serializer symbol")


def run(payload, allocation_fails=False):
    machine = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    segments = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
    top = max(s["p_vaddr"] + s["p_memsz"] for s in segments)
    machine.mem_map(0, (top + 4095) & ~4095)
    for segment in segments:
        machine.mem_write(segment["p_vaddr"], segment.data())
    # Isolated synthetic heap/stack/control region; not real process addresses.
    base = 0x30000000
    machine.mem_map(base, 0x20000)
    output_length, input_buffer, allocation = base + 0x100, base + 0x1000, base + 0x4000
    canary, sentinel = base + 0x200, base + 0x300
    machine.mem_write(canary, struct.pack("<I", 0x12345678))
    machine.mem_write(output_length, struct.pack("<I", 0xdeadbeef))
    machine.mem_write(input_buffer, payload or b"\0")
    # Resolve the one imported data object used by the stack protector.
    found = False
    for relocation in elf.get_section_by_name(".rel.dyn").iter_relocations():
        if relocation["r_info_sym"] and symbols.get_symbol(relocation["r_info_sym"]).name == "__stack_chk_guard":
            machine.mem_write(relocation["r_offset"], struct.pack("<I", canary))
            found = True
    if not found:
        raise ValueError("Stack guard relocation missing")
    allocations = []
    copies = []
    returned = []

    def hook(uc, address, size, unused):
        if address == sentinel:
            returned.append(True)
            uc.emu_stop()
        elif address == 0xfd56d0:  # operator new[] PLT
            length = uc.reg_read(UC_ARM_REG_R0)
            if length > 0x4000:
                raise ValueError("Unexpected allocation size")
            allocations.append(length)
            uc.reg_write(UC_ARM_REG_R0, 0 if allocation_fails else allocation)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        elif address == 0xfd4f80:  # __memcpy_chk PLT
            dst, src, length, bound = [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
            if length > bound or not allocation <= dst <= dst + length <= allocation + allocations[0]:
                raise ValueError("Serializer copy exceeds destination")
            uc.mem_write(dst, bytes(uc.mem_read(src, length)))
            copies.append({"offset": dst - allocation, "length": length})
            uc.reg_write(UC_ARM_REG_R0, dst)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        elif not 0xf2736c <= address < 0xf274e0:
            raise ValueError("Unexpected executed address " + hex(address))

    machine.hook_add(UC_HOOK_CODE, hook)
    machine.reg_write(UC_ARM_REG_SP, base + 0x1f000)
    machine.reg_write(UC_ARM_REG_LR, sentinel | 1)
    for reg, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3),
                          (output_length, 0x8040b, input_buffer if payload else 0, len(payload))):
        machine.reg_write(reg, value)
    machine.emu_start(target["st_value"], sentinel + 2, count=3000)
    if not returned:
        raise ValueError("Serializer did not return within instruction budget")
    length = struct.unpack("<I", machine.mem_read(output_length, 4))[0]
    pointer = machine.reg_read(UC_ARM_REG_R0)
    expected = struct.pack("<I", 0x404) + b"QOEMHOOK" + struct.pack("<II", 0x8040b, len(payload)) + payload
    if allocation_fails:
        if pointer != 0 or length != 0 or copies:
            raise ValueError("Unexpected allocation-failure behavior")
        encoded = b""
    else:
        encoded = bytes(machine.mem_read(pointer, length))
        if pointer != allocation or encoded != expected:
            raise ValueError("Actual serializer output differs from expected framing")
    return {"synthetic_payload_bytes": len(payload), "allocation_fails": allocation_fails,
            "allocated_bytes": allocations, "result_bytes": length,
            "output_sha256": hashlib.sha256(encoded).hexdigest(),
            "output_hex_if_small": encoded.hex() if len(encoded) <= 24 else None,
            "copies": copies}


cases = [run(b""), run(b"\x01\x00\xff\x7f"), run(bytes(range(256))), run(b"test", True)]
report = {"scope": "Actual ARM notification serializer with modeled allocation/memcpy and synthetic inputs; not a live radio test",
          "library_sha256": digest, "function": hex(target["st_value"]), "cases": cases,
          "notification_id": "0x8040b", "envelope_prefix_u32_le": "0x404",
          "marker": "QOEMHOOK", "header_bytes": 20,
          "request_header_validated": False, "capacity_payload_validated": False,
          "record_payload_validated": False, "hardware_validated": False}
args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print("PASS: actual serializer, three synthetic lengths and modeled allocation failure; no phone access")
