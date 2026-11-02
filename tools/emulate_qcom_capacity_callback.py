"""Execute original capacity callback with modeled shared pointers/HIDL endpoint.

Verifies payload copying and error forwarding, not field semantics or live radio.
No request is sent; synthetic values are not measured SIM capacities.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_C1_C0_2, UC_ARM_REG_FPEXC

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()
blob = Path("work/radio-vendor-closure/vendor/lib/libril-qc-hal-qmi.so").read_bytes()
digest = hashlib.sha256(blob).hexdigest()
if digest != "47965523c6b7ca56d9c930198c4f9acc6a9c7b34d12100b0ff068f9305b293dd":
    raise ValueError("Unexpected library")
elf = ELFFile(io.BytesIO(blob))
symbols = elf.get_section_by_name(".dynsym")


def case(has_message=True, has_response=True, has_data=True, error=0):
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    segs = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
    end = max(s["p_vaddr"] + s["p_memsz"] for s in segs)
    uc.mem_map(0, (end + 4095) & ~4095)
    for s in segs:
        uc.mem_write(s["p_vaddr"], s.data())
    base = 0x30000000
    uc.mem_map(base, 0x20000)
    closure, service, vtable, callback = base+0x1000, base+0x2000, base+0x3000, base+0x4000
    payload, count_obj, canary, sentinel = base+0x5000, base+0x6000, base+0x100, base+0x200
    synthetic = struct.pack("<10I", *range(101, 111))
    uc.mem_write(closure, struct.pack("<II", service, 77))
    uc.mem_write(service, struct.pack("<I", vtable))
    uc.mem_write(vtable+0x34, struct.pack("<I", callback | 1))
    uc.mem_write(payload, struct.pack("<I", error))
    uc.mem_write(count_obj+4, synthetic)
    uc.mem_write(canary, struct.pack("<I", 0x12345678))
    for r in elf.get_section_by_name(".rel.dyn").iter_relocations():
        if r["r_info_sym"] and symbols.get_symbol(r["r_info_sym"]).name == "__stack_chk_guard":
            uc.mem_write(r["r_offset"], struct.pack("<I", canary))
    uc.reg_write(UC_ARM_REG_C1_C0_2, 0xf << 20)
    uc.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
    vectors, responses, done = {}, [], []

    def ret(value=0):
        uc.reg_write(UC_ARM_REG_R0, value)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def hook(machine, address, size, unused):
        r0, r1, r2, r3 = [machine.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
        if address == sentinel:
            done.append(True); machine.emu_stop()
        elif address == 0x4d8456: ret(int(has_message))
        elif address == 0x8364a8: ret(int(has_response))
        elif address == 0xbb7aa6: ret(payload)
        elif address == 0xcb3c5e: ret(int(has_data))
        elif address == 0xf2db6c: ret()  # cast shared_ptr modeled, object returned below
        elif address == 0x4c4f4c: ret(count_obj)
        elif address == 0x69e80e: vectors[r0] = b""; ret()
        elif address == 0x69d668:
            if r2 != 40: raise ValueError("Unexpected capacity payload length")
            vectors[r0] = bytes(machine.mem_read(r1, r2)); ret()
        elif address == 0xf18f42: vectors[r0] = b""; ret()
        elif address == 0xff2600: ret()  # modeled endpoint reference
        elif address == 0xf18f2c: ret(1)
        elif address == 0xf183b4: ret(service)
        elif address == callback:
            vector = struct.unpack("<I", machine.mem_read(machine.reg_read(UC_ARM_REG_SP), 4))[0]
            responses.append({"serial": r2, "error": r3, "payload_hex": vectors[vector].hex()})
            ret()
        elif address == 0x4dae8c: ret(1)  # successful modeled HIDL transport status
        elif address in (0xfd6e90, 0xff2610, 0x69e8e6, 0x4da656): ret()
        elif not (0xf2d7dc <= address < 0xf2db24 or 0xf2db98 <= address < 0xf2dba8):
            raise ValueError("Unexpected executed address " + hex(address))

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.reg_write(UC_ARM_REG_SP, base+0x1f000)
    uc.reg_write(UC_ARM_REG_LR, sentinel | 1)
    for register, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3),
                              (closure, base+0x7000, 1, base+0x7100)):
        uc.reg_write(register, value)
    uc.emu_start(0xf2d7dd, sentinel+2, count=10000)
    if not done: raise ValueError("Callback exceeded instruction bound")
    expected = [] if not has_message or not has_response else [
        {"serial": 77, "error": error, "payload_hex": synthetic.hex() if has_data else ""}]
    if responses != expected: raise ValueError("Unexpected callback result: " + repr(responses))
    return {"message_present": has_message, "response_present": has_response,
            "data_present": has_data, "error": error, "callbacks": responses}


cases = [case(), case(has_data=False, error=1), case(error=1),
         case(has_response=False), case(has_message=False)]
report = {"scope": __doc__, "library_sha256": digest, "callback_address": "0xf2d7dd",
          "cases": cases, "field_meanings_verified": False, "request_sent": False,
          "warning": "Nonzero error can accompany a 40-byte payload; consumers must check error before accepting capacity"}
a.output.write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
print("PASS: 40-byte payload copy, error+data, error without data, missing message and missing response; no live request")
