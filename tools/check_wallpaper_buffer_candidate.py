"""Compile exact baseline/candidate wallpaper methods with host-only API/GL models."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from prepare_wallpaper_buffer_candidate import ENGINE, RENDERER, PINS, candidate


def method(text, signature):
    start = text.index(signature)
    end = text.index('{', start) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


def run(source_root, candidate_root, output):
    original = {}
    changed = {}
    for path, pin in PINS.items():
        raw = (source_root / path).read_bytes()
        if hashlib.sha256(raw).hexdigest() != pin:
            raise ValueError('Original source pin changed')
        original[path] = raw.decode()
        changed[path] = (candidate_root / path).read_bytes().decode()
        if changed[path] != candidate(path, original[path]):
            raise ValueError('Candidate scope/content changed')
    fixture = Path(__file__).resolve().parents[1] / 'tests/fixtures/memory_wallpaper_host01.java'
    template = fixture.read_text()
    reports = []
    for name, sources in [('baseline', original), ('candidate', changed)]:
        is_candidate = name == 'candidate'
        substitutions = {
            '@CANDIDATE@': str(is_candidate).lower(),
            '@ENGINE_METHOD@': method(sources[ENGINE], '        private void updateSurfaceSize() {'),
            '@CHANGED_METHOD@': method(sources[RENDERER], '    public void onSurfaceChanged(int width, int height) {'),
            '@DRAW_METHOD@': method(sources[RENDERER], '    public void onDrawFrame() {'),
            '@VIEWPORT_FIELDS@': ('private int mViewportWidth; private int mViewportHeight;' if is_candidate else ''),
        }
        generated = template
        for key, value in substitutions.items():
            if generated.count(key) != 1:
                raise ValueError('Fixture placeholder mismatch')
            generated = generated.replace(key, value)
        directory = output / name
        directory.mkdir(parents=True, exist_ok=True)
        java = directory / 'WallpaperCandidateHost.java'
        java.write_text(generated)
        compiled = subprocess.run(['javac', '-Xlint:all', '-Werror', str(java)], capture_output=True, text=True)
        if compiled.returncode:
            raise RuntimeError(compiled.stderr)
        result = subprocess.run(['java', '-cp', str(directory), 'WallpaperCandidateHost'], capture_output=True, text=True, check=True)
        reports.append(dict(name=name, compile_exit=compiled.returncode, run_exit=result.returncode,
                            generated_java_sha256=hashlib.sha256(java.read_bytes()).hexdigest(),
                            result=json.loads(result.stdout)))
    report = dict(fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),
                  source_hashes=[dict(path=path,
                                      original_sha256=hashlib.sha256(original[path].encode()).hexdigest(),
                                      candidate_sha256=hashlib.sha256(changed[path].encode()).hexdigest())
                                 for path in PINS],
                  scope_gate=True, runs=reports,
                  limits=['Exact extracted sizing/change/draw methods; modeled Android APIs and intercepted GL only.',
                          'No Android target API/DEX verification, real EGL/texture filtering, lifecycle threading or device performance acceptance.',
                          'Baseline smaller-holder case deliberately confirms the old renderer resets to intrinsic viewport.'])
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--candidate-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.source_root, args.candidate_root, args.output), indent=2))
