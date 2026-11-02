"""Audit captured donor capacity ABI against captured build-host sources, offline.

No SIM reads, contact records, device changes, or fabricated capacity responses.
Private source inputs remain in ignored work/. Output contains hashes/findings.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def audit(root):
    inputs = {
        "dex": "work/tcl-contacts-sim-calls01/classes.dex",
        "wrapper": "work/tcl-ui-callsite01/PhoneBookWrapper.java",
        "consumers": "work/tcl-ui-callsite01/ContactUtils.java",
        "menu": "work/tcl-contacts-sim-calls01/QuickContactActivity.java",
        "donor_backend_dex": "work/contacts-capacity-backend01/mediatek-telephony.dex",
        **{name: "work/contacts-capacity-backend01/" + name for name in (
            "IIccPhoneBook.aidl", "IccPhoneBookInterfaceManager.java",
            "UiccPhoneBookController.java", "TelephonyServiceManager.java",
            "MtkUsimPhoneBookManager.java", "SimContactsOperation.java",
            "ContactSaveService.java", "IccProvider.java")},
    }
    blobs = {k: (root / p).read_bytes() for k, p in inputs.items()}
    hashes = {k: hashlib.sha256(v).hexdigest() for k, v in blobs.items()}
    # Offset from the independently saved dexdump, valid ONLY for this pinned DEX.
    if hashes["dex"] != "62251896c53a4b8ee15cc9b85aa755e74abc70483f5d660eedee93b3a0614213":
        raise ValueError("Donor DEX changed; rederive array-data offset")
    ident, width, count = struct.unpack_from("<HHI", blobs["dex"], 0x555524)
    if (ident, width, count) != (0x300, 4, 10):
        raise ValueError("Unexpected DEX array-data payload")
    fallback = list(struct.unpack_from("<10i", blobs["dex"], 0x55552c))
    if fallback != [0, 0, 0, 0, 0, 0, 14, 40, 40, 40]:
        raise ValueError("Fallback does not match saved decompilation")
    if hashes["donor_backend_dex"] != "4e7e933709dce6d99d40baa2658887f2480ae1f595003e007c47b163298cdd50":
        raise ValueError("Donor backend changed; rederive method offset")
    # dexdump: const/4 v0, 6 followed by new-array v0, v0, [I.
    if blobs["donor_backend_dex"][0xe5494:0xe549a] != bytes.fromhex("12602300a905"):
        raise ValueError("Backend capacity allocation changed")
    text = {k: v.decode("utf-8") for k, v in blobs.items() if not k.endswith("dex")}
    aidl = text["IIccPhoneBook.aidl"]
    manager = text["IccPhoneBookInterfaceManager.java"]
    if "getAdnRecordsCapacityForSubscriber" in aidl:
        raise ValueError("Backend changed; reassess capacity support")
    for needle in ("getAdnRecordsSizeForSubscriber", "getAdnRecordsInEfForSubscriber"):
        if needle not in aidl:
            raise ValueError("Expected backend API missing: " + needle)
    if 'new ServiceRegisterer("simphonebook")' not in text["TelephonyServiceManager.java"]:
        raise ValueError("Backend service registration changed")
    if "request.wait();" not in manager or "efid = updateEfForIccType(efid);" not in manager:
        raise ValueError("Loading behavior changed; inspect source")
    menu = text["menu"]
    method = menu[menu.index("public boolean onPrepareOptionsMenu(Menu menu)"):]
    if method.index("ContactUtils.getAdnRecordsCapacity(this, 1)") > method.index("getAccountType()"):
        raise ValueError("Menu ordering changed")
    provider = text["IccProvider.java"]
    if "addIccRecordToEf(efType, tag, number, null, pin2, subId)" not in provider:
        raise ValueError("Provider insert changed; reassess email writes")
    if 'getAsString("anrs")' in provider or 'getAsString("newEmails")' in provider:
        raise ValueError("Provider capabilities changed; reassess extended writes")
    return {
        "scope": "Offline source and pinned donor DEX audit; not runtime SIM validation",
        "inputs": {k: {"path": p, "sha256": hashes[k]} for k, p in inputs.items()},
        "donor_fallback": fallback,
        "capacity_fields_proven_by_consumers": {
            "0": "total ADN", "1": "used ADN", "2": "total email",
            "3": "used email", "4": "total additional numbers", "5": "used additional numbers",
        },
        "donor_backend_capacity_array_length": 6,
        "fallback_only_fields_not_returned_by_this_backend": [6, 7, 8, 9],
        "donor_backend_sources": ["queryPhbStorageInfo", "queryUPBAvailable"],
        "aosp_provider_insert_passes_null_email": True,
        "aosp_provider_extended_email_anr_writes_implemented": False,
        "capacity_fix_alone_enables_full_sim_editing": False,
        "aosp_record_size_fields": ["single record byte length", "EF byte length", "record count"],
        "service_name": "simphonebook",
        "binder_interface": "com.android.internal.telephony.IIccPhoneBook",
        "direct_array_substitution_valid": False,
        "menu_queries_both_slots_before_account_type_check": True,
        "record_load_requires_read_contacts": True,
        "record_load_may_block_waiting_for_async_result": True,
        "record_load_remaps_adn_to_pbr_for_usim": True,
        "capacity_backend_implemented": False,
        "runtime_validated": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.root)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("Capacity ABI audit passed; backend adaptation and runtime validation remain pending.")
