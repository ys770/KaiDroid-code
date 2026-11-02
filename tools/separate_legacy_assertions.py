"""Separate legacy compile-time assertions for a platform-upgrade diagnostic.

Preserves all non-assertion statements byte-for-byte. Never modifies originals.
The output is not approved policy: compile against the NEW platform assertions.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path


def forms(text):
    depth, start, quoted, escaped, comment = 0, None, False, False, False
    for offset, char in enumerate(text):
        if comment:
            if char == '\n':
                comment = False
            continue
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
            continue
        if char == ';':
            comment = True
        elif char == '"':
            quoted = True
        elif char == '(':
            if depth == 0:
                start = offset
            depth += 1
        elif char == ')':
            depth -= 1
            if depth < 0:
                raise ValueError('Unbalanced CIL')
            if depth == 0:
                yield start, offset + 1
    if depth or quoted:
        raise ValueError('Unterminated CIL form/string')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Use a new output file')
    data = args.source.read_bytes()
    text = data.decode('utf-8')
    pieces, assertions, keep, cursor = [], [], [], 0
    for start, end in forms(text):
        form = text[start:end]
        pieces.append(text[cursor:start])
        if re.match(r'\(\s*neverallow(?:x)?\s', form):
            assertions.append({'line': text.count('\n', 0, start) + 1, 'form': form})
            pieces.append(''.join('\n' if c == '\n' else ' ' for c in form))
        else:
            pieces.append(form)
            keep.append(form)
        cursor = end
    pieces.append(text[cursor:])
    result = ''.join(pieces)
    # Verify that no access-granting, type, attribute, or other statement changed.
    if [result[a:b] for a, b in forms(result)] != keep:
        raise ValueError('Non-assertion statements changed')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(result.encode('utf-8'))
    args.output.with_suffix('.assertions.json').write_text(json.dumps({
        'source_sha256': hashlib.sha256(data).hexdigest(),
        'output_sha256': hashlib.sha256(result.encode()).hexdigest(),
        'preserved_forms': len(keep), 'separated_assertions': assertions,
        'scope': 'Legacy assertions separated for diagnostic compilation; new platform assertions remain mandatory. No runtime access rule changed.'
    }, indent=2) + '\n')
    print('Preserved', len(keep), 'forms; separated', len(assertions), 'legacy assertions')


if __name__ == '__main__':
    main()
