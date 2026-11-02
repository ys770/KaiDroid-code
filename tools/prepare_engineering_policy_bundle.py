"""Reproduce engineering E013 from captured inputs and compile against a selected platform.

Produces private staging inputs only. Does not alter AOSP, select policy at boot,
or authorize installation. Keep the adapted libcutils and init/context changes paired.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('stock', 'compat', 'mapping', 'platform', 'compiler', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--extra-policy', type=Path, action='append', default=[],
                        help='Generated system_ext/product CIL and mappings selected by init')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    recipes = root / 'device/nokia/n139dl/sepolicy/experiments'
    expected = {
        'vendor_sepolicy.cil': '0bc3789bac840546d4a5dd7e94b76f623596973a1cf91991cc428f14f9476862',
        'plat_pub_versioned.cil': 'a00ddfe8b71b2f4d5c77a491db6c2e0add171f60e896ad18d3e4375c998a1076',
    }
    # Validate every fixed source before creating output. No retail substitution.
    for name, sha in expected.items():
        if digest(args.stock / name) != sha:
            raise ValueError('Engineering capture mismatch: ' + name)
    compat_data = args.compat.read_bytes()
    compat_sha = digest(args.compat)
    if compat_sha == '70a54391a9cdea7ad7297cae8c3e4dbb89af7ade9aca6d43e9f9e420acb0db37':
        # The reviewed recipes pin the CRLF copy. Canonicalize only the exact
        # upstream LF input, never arbitrary or edited policy.
        compat_data = compat_data.replace(b'\n', b'\r\n')
    if hashlib.sha256(compat_data).hexdigest() != 'c35da4f6e965d4809003e95a26af0032efa5754bbe8c2e599178db8ef7062e4a':
        raise ValueError('Compatibility input mismatch')
    if digest(args.mapping) not in (
            '0f394665082236674e9a7cd478c9746f5b54abdd4cad01cb75b07f91a8a9b8bb',
            '71327621085b31d500e909ce5ee16c178c5b52afc28d9b894b98b88e6ea4a3e1'):
        raise ValueError('Mapping input mismatch')
    for path in (args.platform, args.compiler):
        if not path.is_file():
            raise ValueError('Missing input: ' + str(path))
    args.output.mkdir(parents=True, exist_ok=False)
    current = args.output / 'assertions-separated'
    for name in expected:
        subprocess.run([sys.executable, str(root / 'tools/separate_legacy_assertions.py'),
                        str(args.stock / name), '--output', str(current / name)], check=True)
    recipe_hashes = {}
    for number in range(1, 14):
        matches = list(recipes.glob(f'E{number:03d}-*.json'))
        if len(matches) != 1:
            raise ValueError('Ambiguous/missing recipe: ' + str(number))
        recipe = matches[0]
        if number == 5:
            (current / '29.0.compat.cil').write_bytes(compat_data)
        destination = args.output / f'E{number:03d}'
        subprocess.run([sys.executable, str(root / 'tools/apply_policy_recipe.py'),
                        '--recipe', str(recipe), '--input', str(current),
                        '--output', str(destination)], check=True)
        current = destination
        recipe_hashes[recipe.name] = digest(recipe)
    final_expected = {
        'vendor_sepolicy.cil': '1eb3258c9827cd589365338ef0d3d73ca4fb08375fe981a8b2a665d6f963a59f',
        'plat_pub_versioned.cil': 'b4998d758fb2fd6cfa9484e81b4eb8a17f7f85d259dcd5dd11d596a77ed6e3cc',
        '29.0.compat.cil': '0f3b926c8e2335f96fea8d3b70aa4ffc777bf0f168bc70a0036ffd02af50b841',
    }
    for name, sha in final_expected.items():
        if digest(current / name) != sha:
            raise ValueError('Candidate differs from reviewed E013: ' + name)
    mappings = args.output / 'stock-mappings'
    subprocess.run([sys.executable, str(root / 'tools/prepare_stock_mapping_additions.py'),
                    '--stock', str(args.stock / '29.0.cil'), '--upstream', str(args.mapping),
                    '--output', str(mappings)], check=True)
    companions = [mappings / 'stock-only-mapping.cil'] + [recipes / name for name in (
        'stock-core-services.cil', 'cne-named-services.cil', 'aosp-vendor-file-types.cil')]
    runtime = args.output / 'runtime'
    runtime.mkdir()
    for name in final_expected:
        contents = (current / name).read_bytes().replace(b'\r\n', b'\n')
        if name == '29.0.compat.cil':
            contents += b'\n' + b'\n'.join(p.read_bytes().replace(b'\r\n', b'\n') for p in companions)
        (runtime / name).write_bytes(contents)
    current = runtime
    runtime_hashes = {name: digest(current / name) for name in final_expected}
    subprocess.run([sys.executable, str(root / 'tools/compile_policy_bundle.py'),
                    '--compiler', str(args.compiler), '--output', str(args.output / 'compiled'),
                    str(args.platform), str(args.mapping), str(current / '29.0.compat.cil'),
                    str(current / 'plat_pub_versioned.cil'), str(current / 'vendor_sepolicy.cil'),
                    *[str(p) for p in args.extra_policy]], check=True)
    (args.output / 'bundle.json').write_text(json.dumps({
        'stock_sha256': expected, 'recipe_sha256': recipe_hashes,
        'compat_source_sha256': compat_sha, 'mapping_source_sha256': digest(args.mapping),
        'recipe_candidate_sha256': final_expected, 'candidate_sha256': runtime_hashes,
        'companion_sha256': {p.name: digest(p) for p in companions}, 'platform_sha256': digest(args.platform),
        'scope': 'Reproduced and strictly compiled; not selected by init or installed.',
        'required_pairings': ['adapted VNDK29 libcutils', 'ashmem node labels',
                              'sysdata file context', 'platform data init actions',
                              'exact radio property context', 'init policy selection'],
    }, indent=2) + '\n')
    print('Reproduced E013 and compiled selected platform:', args.output)


if __name__ == '__main__':
    main()
