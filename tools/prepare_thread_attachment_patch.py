"""Prepare pinned AOSP TelephonyProvider changes for TCL thread attachment metadata."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

HASHES = {
    'MmsSmsDatabaseHelper.java': '01e07517f5caecc21d8d1a1db8a9232223496ba56c70fe8429319bf8e520dcf9',
    'MmsSmsProvider.java': 'a59dd5366814d417171de11adf8155968f0ea07b44e054661fbf5aa2b8d2e333'}
MIGRATION_SQL = 'ALTER TABLE threads ADD COLUMN attachment_info TEXT'


def once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('Source anchor missing or ambiguous: '+old[:70])
    return source.replace(old, new, 1)


def transform(name, source):
    if name == 'MmsSmsDatabaseHelper.java':
        source = once(source, 'static final int DATABASE_VERSION = 67;',
                      'static final int DATABASE_VERSION = 68;')
        source = once(source, '\n                   Threads.HAS_ATTACHMENT + " INTEGER DEFAULT 0);");',
                      '\n                   Threads.HAS_ATTACHMENT + " INTEGER DEFAULT 0," +\n'
                      '                   "attachment_info TEXT);");')
        anchor = 'public void onUpgrade(SQLiteDatabase db, int oldVersion, int currentVersion) {'
        source = once(source, anchor, anchor + '''
        // KaiDroid's additive TCL thread-label migration. SQLiteOpenHelper owns
        // the transaction. Never enter the legacy dropAll fallback on failure.
        if (currentVersion == 68) {
            if (oldVersion != 67) {
                throw new IllegalStateException("Unsupported KaiDroid SMS schema migration: "
                        + oldVersion + " -> " + currentVersion);
            }
            db.execSQL("''' + MIGRATION_SQL + '''");
            return;
        }
''')
    elif name == 'MmsSmsProvider.java':
        anchor = '''        if (ProviderUtil.shouldRemoveCreator(values, callerUid)) {
            // CREATOR should not be changed by non-SYSTEM/PHONE apps'''
        source = once(source, anchor, '''        // TCL stores the latest attachment label on the thread, not sms/pdu.
        // Keep the provider's existing write permissions and URI validation.
        if (values.containsKey("attachment_info")) {
            if (values.size() != 1) {
                throw new IllegalArgumentException("Attachment metadata update must be isolated");
            }
            return mOpenHelper.getWritableDatabase().update(TABLE_THREADS, values,
                    concatSelections(selection, "_id=" + threadIdString), selectionArgs);
        }
''' + anchor)
    else:
        raise ValueError('Unexpected source file')
    return source


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True, help='Directory containing the two exact AOSP source files')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if a.output.exists():
        raise FileExistsError(a.output)
    outputs = {}; report = {}; patches = []
    prefix = 'packages/providers/TelephonyProvider/src/com/android/providers/telephony/'
    for name, expected in HASHES.items():
        data = (a.source/name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('Source drift: '+name)
        original = data.decode('utf-8'); changed = transform(name, original)
        outputs[name] = changed
        patches.extend(difflib.unified_diff(original.splitlines(True), changed.splitlines(True),
                       fromfile='a/'+prefix+name, tofile='b/'+prefix+name))
        report[name] = dict(before=expected, after=hashlib.sha256(changed.encode()).hexdigest())
    a.output.mkdir(parents=True)
    for name, changed in outputs.items():
        (a.output/name).write_text(changed, encoding='utf-8', newline='\n')
    (a.output/'thread-attachment.patch').write_text(''.join(patches), newline='\n')
    (a.output/'report.json').write_text(json.dumps(dict(files=report, applied=False,
        platform_compiled=False, deployed=False, schema_from=67, schema_to=68), indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
