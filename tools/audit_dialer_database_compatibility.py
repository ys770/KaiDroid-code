"""Compare actual decoded Dialer smart-dial CREATE schemas without device writes."""
import argparse
import hashlib
import json
import re
import sqlite3
from pathlib import Path

HELPER = 'smali/com/android/dialer/database/DialerDatabaseHelper.smali'
ANNOTATED = 'smali/com/android/dialer/calllog/database/AnnotatedCallLogDatabaseHelper.smali'


def schema(root):
    text = (root / HELPER).read_text(encoding='utf-8')
    matches = re.findall(r'const-string [^,]+, "(CREATE TABLE smartdial_table [^"\n]+)"', text)
    if len(matches) != 1:
        raise ValueError('Expected one exact smartdial CREATE statement')
    with sqlite3.connect(':memory:') as db:
        db.execute(matches[0])
        columns = [dict(name=r[1], type=r[2], not_null=bool(r[3]), default=r[4])
                   for r in db.execute('PRAGMA table_info(smartdial_table)')]
    return matches[0], columns


def audit(existing, donor):
    old_sql, old = schema(existing)
    new_sql, new = schema(donor)
    names = {r['name'] for r in old}
    missing = [r for r in new if r['name'] not in names]
    with sqlite3.connect(':memory:') as db:
        db.execute(old_sql)
        try:
            db.execute('SELECT type,label FROM smartdial_table')
        except sqlite3.OperationalError as error:
            failure = str(error)
        else:
            raise ValueError('Expected donor projection to fail on old schema')
    # Keep this report separate from a migration: no installed file is modified.
    return dict(existing_columns=old, donor_columns=new, missing_donor_columns=missing,
        reproduced_query_failure=failure, migration_implemented=False,
        input_sha256={label: {name: hashlib.sha256((root/name).read_bytes()).hexdigest()
                            for name in (HELPER, ANNOTATED)}
                      for label, root in [('existing', existing), ('donor', donor)]},
        limitations=['Host SQLite projection test, not Android app execution.',
                     'Database snapshots, annotated cache compatibility and all app workflows still required.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--existing', type=Path, required=True)
    parser.add_argument('--donor', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = audit(args.existing, args.donor)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'missing_donor_columns': report['missing_donor_columns'],
                      'reproduced_query_failure': report['reproduced_query_failure']}))
