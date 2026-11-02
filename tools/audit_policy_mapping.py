"""Compare captured versioned SELinux names with an upstream mapping, not compile policy."""
import argparse
import hashlib
import json
import re
from pathlib import Path


def names(path, suffix):
    data = path.read_bytes()
    text = re.sub(r';[^\n]*', '', data.decode())
    atoms = set(re.findall(r'(?<![\w.-])[\w.-]+' + re.escape(suffix) + r'(?![\w.-])', text))
    return atoms, hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor-policy', type=Path, required=True)
    parser.add_argument('--mapping', type=Path, required=True)
    parser.add_argument('--suffix', default='_29_0')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    vendor, vendor_hash = names(args.vendor_policy, args.suffix)
    upstream, mapping_hash = names(args.mapping, args.suffix)
    delta = sorted(vendor - upstream)
    result = {'vendor_sha256': vendor_hash, 'mapping_sha256': mapping_hash,
              'version_suffix': args.suffix, 'vendor_versioned_names': len(vendor),
              'names_not_in_upstream_mapping': delta,
              'scope': 'Lexical versioned-name comparison. Names may have other definitions; this is not a policy compiler, unresolved-symbol proof, or permission equivalence check.'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'versioned_names': len(vendor), 'not_in_upstream_mapping': len(delta)}, indent=2))


if __name__ == '__main__':
    main()
