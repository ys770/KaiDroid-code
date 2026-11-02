"""Apply a reviewed, hash-bound CIL recipe to new offline candidate files only."""
import argparse
import hashlib
import json
from pathlib import Path
from separate_legacy_assertions import forms


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe', type=Path, required=True)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    recipe = json.loads(args.recipe.read_text())
    if args.output.exists():
        raise ValueError('Output must be a new directory')
    prepared, audit = {}, []
    for name, spec in recipe['files'].items():
        if Path(name).name != name or '/' in name or '\\' in name or name in ('.', '..'):
            raise ValueError('Recipe filename must be a basename')
        data = (args.input / name).read_bytes()
        if digest(data) != spec['input_sha256']:
            raise ValueError('Input hash mismatch: ' + name)
        text = data.decode('utf-8')
        edits = {edit['old']: edit for edit in spec['edits']}
        if len(edits) != len(spec['edits']):
            raise ValueError('Duplicate edit key')
        counts = dict.fromkeys(edits, 0)
        pieces, cursor = [], 0
        for start, end in forms(text):
            form = text[start:end]
            pieces.append(text[cursor:start])
            if form in edits:
                edit = edits[form]
                counts[form] += 1
                replacement = edit['new']
                if replacement:
                    spans = list(forms(replacement))
                    if spans != [(0, len(replacement))]:
                        raise ValueError('Replacement must be one complete CIL form')
                pieces.append(replacement or ''.join('\n' if c == '\n' else ' ' for c in form))
            else:
                pieces.append(form)
            cursor = end
        pieces.append(text[cursor:])
        for old, count in counts.items():
            if count != edits[old]['count']:
                raise ValueError('Unexpected match count for ' + old)
        output = ''.join(pieces).encode('utf-8')
        prepared[name] = output
        audit.append({'file': name, 'input_sha256': digest(data), 'output_sha256': digest(output),
                      'edits': spec['edits']})
    args.output.mkdir(parents=True)
    for name, data in prepared.items():
        (args.output / name).write_bytes(data)
    (args.output / 'recipe-result.json').write_text(json.dumps({
        'recipe_sha256': digest(args.recipe.read_bytes()), 'files': audit,
        'scope': 'Offline candidate only; not build-wired, loaded, or hardware-validated.'
    }, indent=2) + '\n')
    print('Prepared', len(prepared), 'hash-bound candidate files:', args.output)


if __name__ == '__main__':
    main()
