"""Generate a gated Android 11 RGB565 client-target experiment, without installing."""
import argparse
import hashlib
import json
from pathlib import Path

SOURCE_SHA = 'eeb14fe832f9dda882fdf3c9d09ef35526f11505c1de755152e1680a024f4c7e'
OLD = '''    status = native_window_set_buffers_format(window, HAL_PIXEL_FORMAT_RGBA_8888);
    ALOGE_IF(status != NO_ERROR, "Unable to set BQ format to RGBA888: %d", status);'''
NEW = '''    // Engineering N139DL SPI composer expects an actual RGB565 target.
    // Opt in only for physical displays; preserve virtual-display behavior.
    const bool rgb565 = !mDisplay.isVirtual() &&
            base::GetBoolProperty("ro.kaidroid.rgb565_client_target", false);
    const int format = rgb565 ? HAL_PIXEL_FORMAT_RGB_565 : HAL_PIXEL_FORMAT_RGBA_8888;
    status = native_window_set_buffers_format(window, format);
    ALOGE_IF(status != NO_ERROR, "Unable to set BQ format %d: %d", format, status);'''


def prepare(source, output):
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA:
        raise ValueError('Unreviewed RenderSurface source')
    text = data.decode('utf-8')
    if text.count(OLD) != 1 or text.count('#include <android-base/stringprintf.h>') != 1:
        raise ValueError('Unexpected patch anchors')
    text = text.replace('#include <android-base/stringprintf.h>',
                        '#include <android-base/properties.h>\n#include <android-base/stringprintf.h>')
    result = text.replace(OLD, NEW).encode('utf-8')
    output.mkdir(parents=True, exist_ok=False)
    (output/'RenderSurface.cpp').write_bytes(result)
    report = {'source_sha256': SOURCE_SHA, 'candidate_sha256': hashlib.sha256(result).hexdigest(),
              'enable_property': 'ro.kaidroid.rgb565_client_target=true',
              'default_enabled': False, 'virtual_displays_changed': False,
              'compiled': False, 'physical_output_validated': False}
    (output/'manifest.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.output), indent=2))
