"""Retarget the exact validated external mount rules in an isolated namespace."""
import hashlib
from pathlib import Path
from types import ModuleType

PIN='c8d41bfde094ecbd574a33b7220b0ddc6cb2c139817db1804f7ca5de2e0166b9'
source=(Path(__file__).parent/'tcl_dialog_external_storage.py').read_bytes()
if hashlib.sha256(source).hexdigest()!=PIN:raise ValueError('Frozen native external-storage validator changed')
marker=b"expected_root='/kaidroid-tcl-dialog-build09'"
if source.count(marker)!=1:raise ValueError('Frozen storage backing rule changed')
source=source.replace(marker,b"expected_root='/kaidroid-tcl-ime-handover-image59'")
rules=ModuleType('image59_private_storage_rules')
exec(compile(source,'image59_private_storage_rules','exec'),rules.__dict__)
rules.STORAGE_STAGE='engineering-tcl-ime-handover-stage-59'
rules.STORAGE_BACKING='/mnt/ext1/kaidroid-tcl-ime-handover-image59'
verify=rules.verify_external_storage
sample=rules.external_sample
