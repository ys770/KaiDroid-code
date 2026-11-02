"""Prepare a held two-file wallpaper experiment from pinned source snapshots."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

ENGINE = 'frameworks/base/packages/SystemUI/src/com/android/systemui/ImageWallpaper.java'
RENDERER = 'frameworks/base/packages/SystemUI/src/com/android/systemui/glwallpaper/ImageWallpaperRenderer.java'
PINS = {ENGINE: 'c84eee0d89fb73c0b957d60e787d623f59ae984b03d77dfa0f08cd8cd286ff8c',
        RENDERER: '25f3379863b282d2f56bd840f8cbab271a59876251110a7b954693848d2ab38b'}


def once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('Replacement scope is not unique')
    return text.replace(before, after, 1)


def candidate(path, text):
    if path == ENGINE:
        text = once(text, 'import android.graphics.Rect;', 'import android.app.ActivityManager;\nimport android.graphics.Rect;')
        text = once(text, 'import android.view.SurfaceHolder;', 'import android.view.Display;\nimport android.view.SurfaceHolder;')
        return once(text, '            holder.setFixedSize(width, height);', '''            // Bounded low-RAM experiment: preserve the reviewed WMS frames in both rotations.
            // Keep the source bitmap and all wallpaper offsets/zoom policy unchanged.
            Display display = getDisplayContext().getDisplay();
            if (ActivityManager.isLowRamDeviceStatic() && display != null
                    && display.getDisplayId() == Display.DEFAULT_DISPLAY
                    && width == 1243 && height == 1024
                    && Float.compare(getDisplayContext().getResources().getFloat(
                            com.android.internal.R.dimen.config_wallpaperMaxScale), 1.10f) == 0) {
                Display.Mode[] modes = display.getSupportedModes();
                if (modes != null && modes.length == 1
                        && modes[0].getPhysicalWidth() == 240
                        && modes[0].getPhysicalHeight() == 320) {
                    width = 429;
                    height = 353;
                }
            }
            holder.setFixedSize(width, height);''')
    if path == RENDERER:
        text = once(text, '    private final Rect mSurfaceSize = new Rect();',
                    '    private final Rect mSurfaceSize = new Rect();\n    private int mViewportWidth;\n    private int mViewportHeight;')
        text = once(text, '''    public void onSurfaceChanged(int width, int height) {
        glViewport(0, 0, width, height);''', '''    public void onSurfaceChanged(int width, int height) {
        mViewportWidth = width;
        mViewportHeight = height;
        glViewport(0, 0, width, height);''')
        return once(text, '        glViewport(0, 0, mSurfaceSize.width(), mSurfaceSize.height());',
                    '''        boolean boundedSurface = mSurfaceSize.width() == 1243
                && mSurfaceSize.height() == 1024
                && mViewportWidth == 429 && mViewportHeight == 353;
        glViewport(0, 0,
                boundedSurface ? mViewportWidth : mSurfaceSize.width(),
                boundedSurface ? mViewportHeight : mSurfaceSize.height());''')
    raise ValueError('Unowned source')


def prepare(source_root, output, patch_path):
    records = []
    patch = ''
    for path, expected in PINS.items():
        raw = (source_root / path).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Source pin changed: ' + path)
        original = raw.decode()
        changed = candidate(path, original)
        target = output / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(changed.encode())
        delta = ''.join(difflib.unified_diff(original.splitlines(True), changed.splitlines(True),
                                           fromfile='a/' + path, tofile='b/' + path))
        if any(line[1:].rstrip('\r\n').endswith((' ', '\t')) for line in delta.splitlines(True)
               if line.startswith('+') and not line.startswith('+++')):
            raise ValueError('Added source contains trailing whitespace')
        patch += delta
        records.append(dict(path=path, original_sha256=expected,
                            candidate_sha256=hashlib.sha256(changed.encode()).hexdigest()))
    patch_path.parent.mkdir(parents=True, exist_ok=True)
    patch_path.write_bytes(patch.encode())
    report = dict(files=records, patch_sha256=hashlib.sha256(patch.encode()).hexdigest(),
                  scope=['Engine imports and one existing surface-sizing function',
                         'Renderer two integer fields and existing change/draw methods'],
                  built=False, installed=False,
                  limits=['Offline source candidate; no shared AOSP/output change.',
                          'No pixel equality, actual allocator size, physical RAM saving or hardware acceptance demonstrated.',
                          'Dimensions are an experiment guard, not authentication of wallpaper contents.',
                          'Freeze source wallpaper file/hash and image/APK/settings before any paired hardware trial.'])
    (output / 'candidate.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--patch', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source_root, args.output, args.patch), indent=2))
