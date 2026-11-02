"""Read exact cached providers and image55 bytes offline; never link or execute target code."""
import argparse
import hashlib
from io import BytesIO
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from elftools.elf.elffile import ELFFile
from audit_libart_surface54 import surface

ROOT = Path(__file__).resolve().parents[1]
HOST = '/opt/kaidroid/kaidroid-build-20261023'
REL = 'out-eng-02/soong/.intermediates/art/runtime/libart/'
RAW = 'c3e9e8e5cf4af03aa053c98c509b2cbec6375e8bf6632bb7b0b57fa171894d88'
RECEIPT = '85170d172d6bd29ff255f8ec4e1930e19957201d61ee5e737b4ec49ae9dd6b99'
TIME = '_ZN3art8NanoTimeEv'
STREAM = '_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEElsEy'
COMPARE = '_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7compareEjjPKcj'
ACCESSORS = {
    'oat.o': ['_ZNK3art9OatHeader11GetChecksumEv', '_ZNK3art9OatHeader19GetExecutableOffsetEv', '_ZNK3art9OatHeader7IsValidEv'],
    'oat_file.o': ['_ZNK3art7OatFile12GetOatHeaderEv', '_ZNK3art7OatFile3EndEv', '_ZNK3art7OatFile5BeginEv'],
}


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            digest.update(block)
    return digest.hexdigest()


def symbol_versions(elf):
    versions = {0: 'LOCAL', 1: 'GLOBAL'}
    bases = []
    definitions = elf.get_section_by_name('.gnu.version_d')
    if definitions:
        for definition, aux in definitions.iter_versions():
            names = [row.name for row in aux]
            index = int(definition['vd_ndx']) & 0x7fff
            if index == 1 and int(definition['vd_flags']) & 1 and len(names) == 1:
                if bases:
                    raise ValueError('Duplicate base version definition')
                bases.append(names[0])  # Legal SONAME base node, not a version for all GLOBAL symbols.
                continue
            if not names or index in versions:
                raise ValueError('Duplicate/empty version definition')
            versions[index] = names[0]
    needs = elf.get_section_by_name('.gnu.version_r')
    if needs:
        for _, aux in needs.iter_versions():
            for row in aux:
                index = int(row['vna_other']) & 0x7fff
                if index in versions:
                    raise ValueError('Duplicate version requirement')
                versions[index] = row.name
    return versions, bases


def provider_surface(raw, wanted):
    elf = ELFFile(BytesIO(raw))
    if (elf.elfclass, elf.little_endian, elf['e_machine'], elf['e_type']) != (32, True, 'EM_ARM', 'ET_DYN'):
        raise ValueError('Provider must be ARM32 little-endian shared ELF')
    versions, bases = symbol_versions(elf)
    table = elf.get_section_by_name('.dynsym')
    versym = elf.get_section_by_name('.gnu.version')
    result = []
    for index, symbol in enumerate(table.iter_symbols()):
        if symbol.name not in wanted or symbol['st_shndx'] == 'SHN_UNDEF':
            continue
        value = versym.get_symbol(index)['ndx'] if versym else 1
        if isinstance(value, str):
            value = {'VER_NDX_LOCAL': 0, 'VER_NDX_GLOBAL': 1}[value]
        value = int(value)
        row = dict(name=symbol.name, binding=symbol['st_info']['bind'], type=symbol['st_info']['type'],
                   visibility=symbol['st_other']['visibility'], version=versions[value & 0x7fff], version_hidden=bool(value & 0x8000))
        if row['binding'] not in ('STB_GLOBAL', 'STB_WEAK') or row['type'] != 'STT_FUNC' or row['visibility'] not in ('STV_DEFAULT', 'STV_PROTECTED') or row['version_hidden']:
            raise ValueError('Provider symbol not externally available: ' + symbol.name)
        result.append(row)
    return dict(elfclass=32, machine='EM_ARM', version_base_nodes=bases, exports=result)


def audit(llvm_nm):
    providers = ROOT / 'work/memory/services-phase-link-provider-inputs01'
    receipt = providers / 'receipt.json'
    if sha(receipt) != RECEIPT:
        raise ValueError('Exact provider acquisition receipt required')
    rows = json.loads(receipt.read_text())
    compile_record = json.loads((ROOT / 'work/memory/libart-compile03/compile-record.json').read_text())
    cache_path = ROOT / 'work/memory/libart-dryrun02/inputs/cache-before.json'
    cache = json.loads(cache_path.read_text())
    by_name = {}
    for row in rows:
        name = Path(row['source']).name
        path = providers / name
        if row['source'] != row['resolved'] or sha(path) != row['sha256'] or path.stat().st_size != row['size']:
            raise ValueError('Provider transfer/path differs')
        if name.endswith('.o'):
            key = row['source'][len(HOST + '/' + REL):]
            expected = cache[key]['sha256']
        else:
            expected = compile_record['read_inputs'][row['source']]
        if row['sha256'] != expected or name in by_name:
            raise ValueError('Provider is not the original link input')
        by_name[name] = row
    if set(by_name) != {'libartbase.so', 'libc++.so', *ACCESSORS}:
        raise ValueError('Exact four providers required')
    definitions = {}
    for name, symbols in ACCESSORS.items():
        process = subprocess.run([str(llvm_nm), '--defined-only', '--format=posix', str(providers / name)],
                                 capture_output=True, text=True, timeout=60, check=True)
        found = {line.split()[0]: line.split()[1] for line in process.stdout.splitlines() if len(line.split()) == 4}
        if any(found.get(symbol) != 'T' for symbol in symbols):
            raise ValueError('Accessor definition missing from pinned object')
        definitions[name] = dict(source=by_name[name], definitions={symbol: found[symbol] for symbol in symbols})
    dynamic = {}
    for name, wanted in [('libartbase.so', [TIME]), ('libc++.so', [STREAM, COMPARE])]:
        parsed = provider_surface((providers / name).read_bytes(), wanted)
        if {row['name'] for row in parsed['exports']} != set(wanted) or any(row['version'] != 'GLOBAL' for row in parsed['exports']):
            raise ValueError('Expected unversioned dynamic provider differs')
        dynamic[name] = dict(source=by_name[name], surface=parsed)
    raw = ROOT / 'work/engineering-system-55.raw.img'
    if sha(raw) != RAW:
        raise ValueError('Exact intended image55 required')
    sys.path.insert(0, str(ROOT / 'work/kyocera-extfs-python'))
    from dissect.extfs import ExtFS
    with raw.open('rb') as stream:
        fs = ExtFS(stream)
        image_paths = {'libartbase.so': '/system/apex/com.android.art.release/lib/libartbase.so', 'libc++.so': '/system/lib/libc++.so'}
        for name, path in image_paths.items():
            value = hashlib.sha256(fs.get(path).open().read()).hexdigest()
            if value != by_name[name]['sha256']:
                raise ValueError('Build provider differs from intended image: ' + name)
            dynamic[name]['image_path'] = path
            dynamic[name]['image_sha256'] = value
        link = fs.get('/system/apex/com.android.art.release/lib/libc++.so').link
        if link != '/system/lib/libc++.so':
            raise ValueError('ART libc++ image symlink differs')
    baselines = {}
    for image, relative in [('55', 'work/memory/libart-surface54-baseline01/libart.so'), ('56', 'work/memory/libart-compile03/stripped.bin')]:
        path = ROOT / relative
        expected = {'55': 'cbb433722989b7b3dd6e4f63e3ad001e91637d13deb232cc9ab16cd379ff8e62',
                    '56': '5a8bb496549fefb2651e5783979e10a08887dba8de34a7ad59b3b62a5c584258'}[image]
        if sha(path) != expected:
            raise ValueError('Exact accepted libart baseline required')
        parsed = surface(path.read_bytes())
        imports = [row for row in parsed['imports'] if row['name'] in (TIME, STREAM, COMPARE)]
        if len(imports) != 3 or any(row['version'] != 'GLOBAL' for row in imports):
            raise ValueError('Existing baseline dynamic requirements differ')
        baselines[image] = dict(path=relative, sha256=sha(path), imports_total=len(parsed['imports']),
                               exports_total=len(parsed['exports']), existing_dynamic_requirements=imports,
                               ordered_needed=parsed['needed'])
    return dict(classification='offline_provider_availability_screen', receipt_sha256=RECEIPT,
        cache_receipt_sha256=sha(cache_path), raw_image55_sha256=RAW, object_providers=definitions,
        shared_providers=dynamic, art_libcxx_symlink=link, baselines=baselines,
        reader=dict(path=str(llvm_nm), sha256=sha(llvm_nm)),
        all_nine_names_have_expected_byte_pinned_providers=True, selected_link_resolution_proven=False,
        live_runtime_namespace_proven=False, compiled_TU_source_provenance_complete=False,
        linked=False, installed=False, savings_proven=False, analyzer_sha256=sha(Path(__file__)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--llvm-nm', type=Path, default=Path('/opt/android-sdk/ndk/27.0.12077973/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-nm.exe'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    result = audit(args.llvm_nm)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(classification=result['classification'], provider_names=9, linked=False)))
