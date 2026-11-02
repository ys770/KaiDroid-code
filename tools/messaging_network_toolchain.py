"""Pin the compiler/runtime and SDK inputs for exact Messaging DEX reproduction."""
import hashlib
from pathlib import Path

PINS = {
    "jdk/bin/java.exe": "a2277b9e1a6a5369dea7cc412cf369cc14dcbcea11ce88a1403fa0abe6293908",
    "jdk/bin/javac.exe": "7b98b2a471b66818c152df1fe6b36b36169f94a54e1a644840a62913f8dc0966",
    "jdk/lib/modules": "4e789ca5d82d2ea64a35c586492a7c5ae66d045fd33be74b19b5e3913853e636",
    "sdk/build-tools/35.0.0/lib/d8.jar": "305622ad00535684534eb8f742cbf5e628a9abc09d8ea4d39d1babb95bf0cee5",
    "sdk/platforms/android-30/android.jar": "96ccfdc84d15fad4e22d76cbb8ef38b150a4b56327957067875ca7e18113a424",
}


def verify(jdk, sdk):
    roots = {"jdk": Path(jdk).resolve(), "sdk": Path(sdk).resolve()}
    inputs = {}
    for name, expected in PINS.items():
        kind, relative = name.split("/", 1)
        path = roots[kind] / relative
        with path.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != expected:
            raise ValueError("Messaging compiler/SDK input mismatch: " + name +
                             "; require original JetBrains JBR21.0.3 and SDK35/Android30")
        inputs[name] = {"path": str(path), "sha256": actual}
    return {"compiler": "JetBrains JBR javac21.0.3", "release": 8,
            "d8_min_api": 30, "inputs": inputs}
