"""Prepare a pinned Android11 TextView manual-marquee integration offline.

Never modifies the input source or shared build checkout. Full platform build,
hidden-API policy and physical text/focus/timing validation remain required.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

SOURCE_SHA256 = 'f6b3bf402c3ec891ecb49e41e0e4f6a6c1219c62337ab483793f64f636d3dbf8'


def prepare(data):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('Unexpected TextView source hash')
    source = data.decode('utf-8')
    edits = [
        ('    private Marquee mMarquee;\n',
         '    private Marquee mMarquee;\n'
         '    private boolean mKaidroidManualMarquee;\n'
         '    private boolean mKaidroidForceMarquee;\n'),
        ('(mMarquee == null || mMarquee.isStopped()) && (isFocused() || isSelected())',
         '(mMarquee == null || mMarquee.isStopped())\n'
         '                && (isFocused() || isSelected() || mKaidroidForceMarquee)'),
        ('            if (mMarquee == null) mMarquee = new Marquee(this);\n'
         '            mMarquee.start(mMarqueeRepeatLimit);',
         '            if (mMarquee == null) mMarquee = new Marquee(this);\n'
         '            if (mKaidroidForceMarquee) mMarquee.mKaidroidForced = true;\n'
         '            mMarquee.start(mMarqueeRepeatLimit);'),
        ('    private void stopMarquee() {\n',
         '    private void stopMarquee() {\n'
         '        if (mKaidroidManualMarquee && mKaidroidForceMarquee) return;\n'),
        ('    private boolean canMarquee() {\n',
         '    /** @hide */\n'
         '    protected void setManualMarquee(boolean manual) {\n'
         '        mKaidroidManualMarquee = manual;\n'
         '    }\n\n'
         '    /** @hide */\n'
         '    protected void forceStartStopMarquee(boolean start) {\n'
         '        if (mEllipsize != TextUtils.TruncateAt.MARQUEE) return;\n'
         '        mKaidroidForceMarquee = start;\n'
         '        if (start) startMarquee();\n'
         '        else stopMarquee();\n'
         '    }\n\n'
         '    private boolean canMarquee() {\n'),
        ('        private byte mStatus = MARQUEE_STOPPED;\n',
         '        private byte mStatus = MARQUEE_STOPPED;\n'
         '        private boolean mKaidroidForced;\n'),
        ('mPixelsPerMs = MARQUEE_DP_PER_SECOND * density / 1000f;',
         '// Captured PJEP cadence: 30 density pixels per 1500 ms.\n'
         '            mPixelsPerMs = MARQUEE_DP_PER_SECOND * density / 1500f;'),
        ('if (textView != null && (textView.isFocused() || textView.isSelected())) {',
         'if (textView != null\n'
         '                    && (textView.isFocused() || textView.isSelected() || mKaidroidForced)) {'),
    ]
    for old, new in edits:
        if source.count(old) != 1:
            raise ValueError('TextView anchor not unique: ' + old)
        source = source.replace(old, new, 1)
    return source.encode('utf-8')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    data = a.source.read_bytes()
    candidate = prepare(data)
    project = Path(__file__).resolve().parents[1]
    widget = project / 'framework/core/java/android/widget/MarqueeTextView.java'
    widget_data = widget.read_bytes()
    a.output.mkdir(parents=True)
    (a.output / 'TextView.java').write_bytes(candidate)
    (a.output / 'MarqueeTextView.java').write_bytes(widget_data)
    patch = ''.join(difflib.unified_diff(data.decode().splitlines(True),
                                       candidate.decode().splitlines(True),
                                       fromfile='a/core/java/android/widget/TextView.java',
                                       tofile='b/core/java/android/widget/TextView.java'))
    (a.output / 'textview.patch').write_text(patch, encoding='utf-8', newline='\n')
    report = dict(source_sha256=SOURCE_SHA256,
                  candidate_sha256=hashlib.sha256(candidate).hexdigest(),
                  widget_sha256=hashlib.sha256(widget_data).hexdigest(),
                  platform_compiled=False, installed=False, physical_parity=False)
    (a.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
