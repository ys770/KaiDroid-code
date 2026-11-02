"""Offline execution of the exact radio record serializer on synthetic objects.

String accessors, allocation, logging and libc copying are modeled. This tests
record framing, not real modem contents, string encoding, or libc++ object ABI.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()
path = Path("work/radio-vendor-closure/vendor/lib/libril-qc-hal-qmi.so")
blob = path.read_bytes()
digest = hashlib.sha256(blob).hexdigest()
if digest != "47965523c6b7ca56d9c930198c4f9acc6a9c7b34d12100b0ff068f9305b293dd":
    raise ValueError("Unexpected library")
elf = ELFFile(io.BytesIO(blob))


def fixture(records):
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    segments = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
    end = max(s["p_vaddr"] + s["p_memsz"] for s in segments)
    uc.mem_map(0, (end + 4095) & ~4095)
    for s in segments:
        uc.mem_write(s["p_vaddr"], s.data())
    base = 0x30000000
    uc.mem_map(base, 0x20000)
    obj, outlen, strings_base, heap, sentinel = base + 0x1000, base + 0x100, base + 0x3000, base + 0x8000, base + 0x200
    uc.mem_write(obj, struct.pack("<I", len(records)))
    strings = {}
    cursor = strings_base

    def string_object(address, value):
        nonlocal cursor
        strings[address] = (cursor, value)
        uc.mem_write(cursor, value + b"\0")
        cursor += len(value) + 1

    expected = bytearray(struct.pack("<H", len(records)))
    for index, record in enumerate(records):
        rec = obj + 4 + index * 0x6c
        uc.mem_write(rec, struct.pack("<I", record["id"]))
        string_object(rec + 4, record["name"])
        string_object(rec + 0x10, record["number"])
        uc.mem_write(rec + 0x1c, struct.pack("<I", len(record["emails"])))
        uc.mem_write(rec + 0x38, struct.pack("<I", len(record["anrs"])))
        expected.extend(struct.pack("<H", record["id"]))
        for value in (record["name"], record["number"]):
            expected.extend(struct.pack("<H", len(value)) + value)
        for offset, values in ((0x20, record["emails"]), (0x3c, record["anrs"])):
            expected.extend(struct.pack("<H", len(values)))
            for n, value in enumerate(values):
                string_object(rec + offset + 12 * n, value)
                expected.extend(struct.pack("<H", len(value)) + value)
    allocations, writes_outside, returned = [], [], []

    def ret(value):
        uc.reg_write(UC_ARM_REG_R0, value)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def hook(machine, address, size, unused):
        r0, r1, r2, r3 = [machine.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
        if address == sentinel:
            returned.append(True)
            machine.emu_stop()
        elif address == 0x4beb28:  # string empty(), modeled by field address
            ret(int(not strings[r0][1]))
        elif address == 0x4982d4:  # string c_str(), modeled by field address
            ret(strings[r0][0])
        elif address in (0xfd5070, 0xfd5080):  # strlen/check variant
            raw = bytes(machine.mem_read(r0, 1024))
            length = raw.index(0)
            if address == 0xfd5080 and length >= r1:
                raise ValueError("String exceeds modeled bound")
            ret(length)
        elif address == 0xfd5280:  # modeled zero-filled qcril allocation
            if r0 > 0x4000 or allocations:
                raise ValueError("Unexpected allocation")
            allocations.append(r0)
            machine.mem_write(heap, b"\0" * r0 + b"\xa5" * 16)
            ret(heap)
        elif address == 0xfd4f80:
            if r2 > r3 or not heap <= r0 <= r0 + r2 <= heap + allocations[0]:
                raise ValueError("Copy exceeds allocation")
            machine.mem_write(r0, bytes(machine.mem_read(r1, r2)))
            ret(r0)
        elif address in (0xfd4ef0, 0xfd4f00, 0xfd4f10, 0xf17f90, 0xfd4f20):
            ret(0)  # diagnostic logging only
        elif not 0xf274ec <= address < 0xf27c0c:
            raise ValueError("Unexpected execution " + hex(address))

    def write_hook(machine, access, address, size, value, unused):
        if allocations and heap <= address < heap + 0x4000 and address + size > heap + allocations[0]:
            writes_outside.append({"offset": address - heap, "bytes": size, "value": value})

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.hook_add(UC_HOOK_MEM_WRITE, write_hook)
    uc.reg_write(UC_ARM_REG_SP, base + 0x1f000)
    uc.reg_write(UC_ARM_REG_LR, sentinel | 1)
    uc.reg_write(UC_ARM_REG_R0, outlen)
    uc.reg_write(UC_ARM_REG_R1, obj)
    uc.emu_start(0xf274ed, sentinel + 2, count=100000)
    if not returned:
        raise ValueError("Serializer exceeded instruction budget")
    size = struct.unpack("<I", uc.mem_read(outlen, 4))[0]
    if uc.reg_read(UC_ARM_REG_R0) != heap or size != allocations[0]:
        raise ValueError("Unexpected output pointer/length")
    output = bytes(uc.mem_read(heap, size))
    if output != bytes(expected) + b"\0" * len(records):
        raise ValueError("Unexpected field framing or reported padding")
    expected_outside = [{"offset": 2, "bytes": 1, "value": 0}] if not records else []
    if writes_outside != expected_outside:
        raise ValueError("Unexpected red-zone writes")
    return {"record_count": len(records), "allocated_and_reported_bytes": size,
            "encoded_field_bytes": len(expected), "modeled_zero_padding_bytes": len(records),
            "writes_outside_allocation": writes_outside, "output_hex": output.hex()}


empty = {"id": 7, "name": b"", "number": b"", "emails": [], "anrs": []}
full = {"id": 513, "name": b"Test", "number": b"+15550100", "emails": [b"a@example.test", b"b@example.test"], "anrs": [b"123", b"456"]}
cases = [fixture([]), fixture([empty]), fixture([full]), fixture([empty, full])]
report = {"scope": __doc__, "library_sha256": digest,
          "function": "0xf274ed", "record_stride_in_synthetic_object": 108,
          "string_encoding_verified": False, "modem_record_validity_verified": False,
          "allocation_zero_fill_modeled_not_verified": True, "cases": cases}
a.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print("PASS: original serializer framing for 0/1/2 records; zero-record terminator exceeds allocation by one byte in offline harness")
