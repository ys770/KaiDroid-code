"""Add donor smart-dial fields on open without deleting rows or changing schema version."""
import argparse
import hashlib
import json
import shutil
from pathlib import Path
from rewrite_apk_version_code import rewrite as rewrite_version

HELPER = 'smali/com/android/dialer/database/DialerDatabaseHelper.smali'
CACHE_REWRITES = {
    'smali/com/android/dialer/calllog/database/AnnotatedCallLogDatabaseHelper.smali':
        {'annotated_call_log.db': ('kaidroid_tcl_annotated_call_log.db', 1)},
    'smali/com/android/dialer/calllog/CallLogFramework.smali':
        {'callLogFrameworkForceRebuild': ('kaidroidTclCallLogFrameworkForceRebuild', 2)},
    'smali/com/android/dialer/calllog/RefreshAnnotatedCallLogWorker.smali':
        {'callLogFrameworkForceRebuild': ('kaidroidTclCallLogFrameworkForceRebuild', 2)},
    'smali/com/android/dialer/calllog/datasources/systemcalllog/SystemCallLogDataSource.smali':
        {'systemCallLogLastTimestampProcessed': ('kaidroidTclSystemCallLogLastTimestampProcessed', 3)},
}


def isolate_cache(decoded, output):
    changes = {}
    for name, mapping in CACHE_REWRITES.items():
        original = (decoded/name).read_text(encoding='utf-8')
        changed = original
        for old, (new, expected) in mapping.items():
            if changed.count('"'+old+'"') != expected or new in changed:
                raise ValueError('Unexpected cache identity sites: '+name)
            changed = changed.replace('"'+old+'"', '"'+new+'"')
        (output/name).write_text(changed, encoding='utf-8', newline='\n')
        changes[name] = {old:dict(replacement=new,sites=count) for old,(new,count) in mapping.items()}
    return changes

ON_OPEN = '''
.method public onOpen(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 5

    invoke-super {p0, p1}, Landroid/database/sqlite/SQLiteOpenHelper;->onOpen(Landroid/database/sqlite/SQLiteDatabase;)V
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->beginTransaction()V
    :try_start_tx
    const-string v0, "PRAGMA table_info(smartdial_table)"
    const/4 v1, 0x0
    invoke-virtual {p1, v0, v1}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;
    move-result-object v0
    :try_start_cursor
    const/4 v2, 0x0
    const/4 v3, 0x0
    :column_loop
    invoke-interface {v0}, Landroid/database/Cursor;->moveToNext()Z
    move-result v1
    if-eqz v1, :columns_done
    const/4 v1, 0x1
    invoke-interface {v0, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;
    move-result-object v1
    const-string v4, "type"
    invoke-virtual {v4, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v4
    or-int/2addr v2, v4
    const-string v4, "label"
    invoke-virtual {v4, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v4
    or-int/2addr v3, v4
    goto :column_loop
    :columns_done
    :try_end_cursor
    .catchall {:try_start_cursor .. :try_end_cursor} :catch_cursor
    invoke-interface {v0}, Landroid/database/Cursor;->close()V
    if-nez v2, :has_type
    const-string v1, "ALTER TABLE smartdial_table ADD COLUMN type INTEGER"
    invoke-virtual {p1, v1}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V
    :has_type
    if-nez v3, :has_label
    const-string v1, "ALTER TABLE smartdial_table ADD COLUMN label TEXT"
    invoke-virtual {p1, v1}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V
    :has_label
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V
    :try_end_tx
    .catchall {:try_start_tx .. :try_start_cursor} :catch_tx
    .catchall {:try_end_cursor .. :try_end_tx} :catch_tx
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V
    return-void

    :catch_cursor
    move-exception v1
    :try_start_close
    invoke-interface {v0}, Landroid/database/Cursor;->close()V
    throw v1
    :try_end_close
    .catchall {:try_start_close .. :try_end_close} :catch_tx

    :catch_tx
    move-exception v0
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V
    throw v0
.end method
'''


def prepare(decoded, output, expected):
    original = (decoded / HELPER).read_bytes()
    if hashlib.sha256(original).hexdigest() != expected:
        raise ValueError('Donor helper identity mismatch')
    source = original.decode('utf-8')
    if '.method public onOpen(' in source or '.method protected onOpen(' in source:
        raise ValueError('Existing onOpen requires review')
    if '.super Landroid/database/sqlite/SQLiteOpenHelper;' not in source:
        raise ValueError('Unexpected superclass')
    shutil.copytree(decoded, output)
    (output / HELPER).write_text(source + ON_OPEN, encoding='utf-8', newline='\n')
    cache_changes = isolate_cache(decoded, output)
    manifest = output/'AndroidManifest.xml'
    updated, version_offset = rewrite_version(manifest.read_bytes(), 2301121, 2900001)
    manifest.write_bytes(updated)
    report = dict(helper=HELPER, original_sha256=expected,
        patched_sha256=hashlib.sha256((output/HELPER).read_bytes()).hexdigest(),
        database_version_unchanged=True, columns_added=['type INTEGER','label TEXT'],
        no_drop_or_row_update=True, android_runtime_verified=False,
        cache_changes=cache_changes,
        version_code=2900001,version_code_offset=version_offset,
        annotated_cache_requirement='Donor derived cache and refresh markers use separate names; original annotated cache remains untouched.',
        installed=False)
    (output/'schema-patch.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--decoded',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--helper-sha256',required=True)
    a=p.parse_args()
    print(json.dumps(prepare(a.decoded,a.output,a.helper_sha256)))
