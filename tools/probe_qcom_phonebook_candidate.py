"""Bind offline Qualcomm phonebook indicators to image33; no modem requests/writes."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--adb", required=True)
p.add_argument("--boot-id", required=True)
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
root = Path(__file__).resolve().parents[1]
base = [a.adb, "-s", "DEVICE_SERIAL_REQUIRED", "shell"]


def read(name, command):
    result = subprocess.run(base + [command], capture_output=True, timeout=45, check=True)
    (a.output / (name + ".stdout")).write_bytes(result.stdout)
    (a.output / (name + ".stderr")).write_bytes(result.stderr)
    return result.stdout.decode("utf-8", errors="replace").strip()


def guard(name):
    values = read(name, "getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u").split()
    if values != ["33", a.boot_id, "0"]:
        raise ValueError("Unexpected image/boot/access identity")


guard("before")
local_path = "work/radio-vendor-closure/vendor/lib/libril-qc-hal-qmi.so"
data = (root / local_path).read_bytes()
digest = hashlib.sha256(data).hexdigest()
installed_hash = read("library-hash", "sha256sum /vendor/lib/libril-qc-hal-qmi.so").split()[0]
if digest != installed_hash:
    raise ValueError("Offline candidate differs from installed engineering library")
indicators = [
    "QCRIL_EVT_PBM_GET_PB_CAPACITY", "QCRIL_EVT_HOOK_GET_ADN_RECORD",
    "QCRIL_EVT_HOOK_UPDATE_ADN_RECORD", "QCRIL_EVT_HOOK_UNSOL_ADN_INIT_DONE",
    "qcril_qmi_pbm_get_adn_record_hndlr", "qcril_qmi_pbm_update_adn_record_hndlr",
    "qcril_qmi_pbm_add_or_modify_adn_record", "qcril_qmi_pbm_delete_adn_record",
]
strings = {m.group().decode("ascii"): m.start() for m in re.finditer(rb"[ -~]{8,}", data)}
found = {name: strings[name] for name in indicators if name in strings}
services = read("lshal", "lshal")
radio_state = read("qcrild", "getprop init.svc.vendor.qcrild")
sim_state = read("sim-state", "getprop gsm.sim.state")
hook = "vendor.qti.hardware.radio.qcrilhook@1.0::IQtiOemHook/oemhook0"
rows = [line.strip() for line in services.splitlines() if hook in line]
guard("after")
report = {
    "scope": "Read-only identity/hash/service inventory plus offline string indicators; no OEM-hook request sent",
    "image": 33, "boot_id": a.boot_id,
    "local_library": local_path, "sha256": digest,
    "installed_library_hash_matches": True,
    "qcrild_state": radio_state, "sim_state": sim_state,
    "oemhook_lshal_rows": rows,
    "exact_string_offsets_not_call_graph": found,
    "request_ids_and_wire_format_verified": False,
    "capacity_response_verified": False,
    "extended_write_support_verified": False,
}
(a.output / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2))
