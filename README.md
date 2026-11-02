# KaiDroid

Android 11 port development for the Nokia 2760 Flip / N139DL, with a keypad
interface modeled on TCL flip phones.

This is a public source snapshot with independently reviewed screenshots and
fresh Git history. The private research history, device evidence, credentials,
workstation paths, firmware dumps, signing keys, and proprietary application
binaries are excluded.

Vendor-specific UART binary patch generators and disassembly evidence are also
withheld from this initial source snapshot. See [NOTICE](NOTICE) for attribution;
a license for original KaiDroid additions is awaiting the owner's selection.

- `device/nokia/n139dl/`: product configuration, input mapping, initialization,
  overlays, memory tracking, display helpers, and SELinux policy inputs.
- `framework/`: keypad widgets, soft keys, dialogs, title editing, SystemUI
  adaptations, and framework patches.
- `compat/`: Java compatibility adapters.
- `tools/`: development, analysis, extraction, and patch-generation source.
- `experiments/`: display, memory, messaging, and IMS experiment source.
- `tests/`: a self-contained subset of synthetic regression tests.
- `docs/contracts/`: source/API contracts needed by framework staging.
- `screenshots/`: selected interface captures cleared for public sharing.

## Build scope

This is an experimental source collection, not a complete Android checkout or
a firmware release. Building requires the matching Android source and separately
supplied device/vendor inputs. Proprietary donor APKs and firmware are not
redistributed here. UI parity and full hardware support remain incomplete.

Historical lab scripts retain their validation logic, but real device serials
and boot IDs have been replaced with placeholders, and machine paths use generic
roots. They require explicit adaptation and independently acquired inputs;
they are not ready-made instructions for installing an image on another phone.

The Android product contains engineering/debug settings. Existing source
copyright and license notices are retained; this snapshot does not grant rights
to omitted third-party firmware or applications.

## Local checks

The bundled Python tests require Python 3.10 or newer and no phone:

```sh
python -m unittest discover -s tests -p 'test_*.py' -v
```

They cover resource parsing/remapping, API resolution, memory accounting,
DMA/ION parsing, and APK manifest guards. Hardware validation and private
capture-dependent tests are not part of this public test subset.
