"""Prepare the captured TCL numbered-preference behavior against pinned AOSP sources.

Offline only. The donor's index mutation is intentional here: disassembly shows
both increments also affect the final highlight comparison. Physical parity is
still required, including recycled rows and summary/title visibility.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

HASHES = {
    'PreferenceFragment.java': '647035475025271e70ac1dad35b053ccf2cceeefe48b8cb5dec4d72568d186ab',
    'PreferenceScreen.java': '33b4fce37f14aee5db0b0a401163ba3e7d4aa417d3b6eee8a77d933c2fdbe92f',
    'PreferenceGroupAdapter.java': '54de8ebbc188e197d631ad30ef1f1a18a5a58e3fe9fe9e14d19208fbbfcdae0c',
}


def replace(source, old, new):
    if source.count(old) != 1:
        raise ValueError('Nonunique source anchor: ' + old)
    return source.replace(old, new, 1)


def prepare(name, data):
    if hashlib.sha256(data).hexdigest() != HASHES[name]:
        raise ValueError('Unexpected source: ' + name)
    source = data.decode()
    if name == 'PreferenceFragment.java':
        source = replace(source, '    private boolean mHavePrefs;',
                         '    private boolean mKaidroidDisplayIndex;\n    private boolean mHavePrefs;')
        source = replace(source, '    private void bindPreferences() {', '''    /** @hide */
    protected void setDisplayIndex(boolean display) {
        mKaidroidDisplayIndex = display;
    }

    private void bindPreferences() {''')
        source = replace(source, 'preferenceScreen.bind(getListView());',
                         'preferenceScreen.bind(getListView(), mKaidroidDisplayIndex);')
    elif name == 'PreferenceScreen.java':
        source = replace(source, '    public void bind(ListView listView) {', '''    /** @hide */
    public void bind(ListView listView, boolean displayIndex) {
        listView.setOnItemClickListener(this);
        ((PreferenceGroupAdapter) getRootAdapter()).setDisplayIndex(displayIndex);
        listView.setAdapter(getRootAdapter());
        onAttachedToActivity();
    }

    public void bind(ListView listView) {''')
    else:
        source = replace(source, 'import android.widget.ListView;',
                         'import android.widget.ListView;\nimport android.widget.TextView;')
        source = replace(source, '    private int mHighlightedPosition = -1;',
                         '    private boolean mKaidroidDisplayIndex;\n    private int mHighlightedPosition = -1;')
        source = replace(source, '    public View getView(int position, View convertView, ViewGroup parent) {', '''    /** @hide */
    public void setDisplayIndex(boolean display) {
        mKaidroidDisplayIndex = display;
    }

    public View getView(int position, View convertView, ViewGroup parent) {''')
        source = replace(source, '        View result = preference.getView(convertView, parent);', '''        View result = preference.getView(convertView, parent);
        if (mKaidroidDisplayIndex) {
            TextView title = (TextView) result.findViewById(android.R.id.title);
            if (title != null && title.getVisibility() == View.VISIBLE) {
                position++;
                title.setText(String.valueOf(position) + ". " + preference.getTitle());
                result.setPadding(10, 0, 0, 0);
            }
            TextView summary = (TextView) result.findViewById(android.R.id.summary);
            if (summary != null && summary.getVisibility() == View.VISIBLE) {
                // Preserve the captured donor's second increment and title dependency.
                android.text.TextPaint paint = title.getPaint();
                position++;
                summary.setPadding((int) paint.measureText(String.valueOf(position) + ". "),
                        0, 0, 0);
            }
        }''')
    return source.encode()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    candidates = [(name, (a.source / name).read_bytes()) for name in HASHES]
    candidates = [(name, data, prepare(name, data)) for name, data in candidates]
    a.output.mkdir(parents=True)
    rows, patches = [], []
    for name, data, candidate in candidates:
        (a.output / name).write_bytes(candidate)
        rows.append(dict(file=name, source_sha256=HASHES[name],
                         candidate_sha256=hashlib.sha256(candidate).hexdigest()))
        patches.extend(difflib.unified_diff(data.decode().splitlines(True),
                       candidate.decode().splitlines(True),
                       fromfile='a/core/java/android/preference/' + name,
                       tofile='b/core/java/android/preference/' + name))
    (a.output / 'preferences.patch').write_text(''.join(patches), newline='\n')
    report = dict(files=rows, platform_compiled=False, installed=False, physical_parity=False)
    (a.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
