"""Exercise the emitted SQLite migration on populated synthetic databases."""
import sqlite3
import unittest
from prepare_thread_attachment_patch import MIGRATION_SQL, transform


class AttachmentMigration(unittest.TestCase):
    def database(self):
        db = sqlite3.connect(':memory:')
        db.executescript('''CREATE TABLE threads (_id INTEGER PRIMARY KEY, snippet TEXT);
          CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, body TEXT);
          CREATE TABLE pdu (_id INTEGER PRIMARY KEY, thread_id INTEGER, sub TEXT);
          INSERT INTO threads VALUES(1,'existing'),(2,'other');
          INSERT INTO sms VALUES(10,1,'unchanged');
          INSERT INTO pdu VALUES(20,1,'unchanged MMS');
          PRAGMA user_version=67;''')
        return db

    def test_existing_rows_and_scoped_metadata_roundtrip(self):
        db = self.database()
        before_sms = db.execute('SELECT * FROM sms').fetchall()
        before_mms = db.execute('SELECT * FROM pdu').fetchall()
        with db:
            db.execute(MIGRATION_SQL)
            db.execute('PRAGMA user_version=68')
        self.assertEqual(db.execute('SELECT * FROM threads').fetchall(),[(1,'existing',None),(2,'other',None)])
        for label in ('SMS', 'Photo', 'Video', 'Audio', 'Contact', 'Slideshow', None):
            db.execute('UPDATE threads SET attachment_info=? WHERE _id=? AND snippet=?', (label,1,'existing'))
            self.assertEqual(db.execute('SELECT attachment_info FROM threads WHERE _id=1').fetchone(),(label,))
            self.assertEqual(db.execute('SELECT attachment_info FROM threads WHERE _id=2').fetchone(),(None,))
        self.assertEqual(db.execute('SELECT * FROM sms').fetchall(), before_sms)
        self.assertEqual(db.execute('SELECT * FROM pdu').fetchall(), before_mms)
        db.close()

    def test_failed_migration_rolls_back_without_data_loss(self):
        db = self.database()
        db.execute('BEGIN')
        with self.assertRaises(sqlite3.OperationalError):
            try:
                db.execute(MIGRATION_SQL)
                db.execute(MIGRATION_SQL)
            except Exception:
                db.rollback()
                raise
        self.assertEqual(db.execute('PRAGMA user_version').fetchone(),(67,))
        self.assertEqual(db.execute('SELECT * FROM threads').fetchall(),[(1,'existing'),(2,'other')])
        self.assertEqual([r[1] for r in db.execute('PRAGMA table_info(threads)')],['_id','snippet'])
        db.close()

    def test_schema_guard_precedes_legacy_upgrade_body(self):
        source = ('static final int DATABASE_VERSION = 67;\n'
                  '                   Threads.HAS_ATTACHMENT + " INTEGER DEFAULT 0);");\n'
                  'public void onUpgrade(SQLiteDatabase db, int oldVersion, int currentVersion) {\n'
                  'dropAll(db);\n}')
        out = transform('MmsSmsDatabaseHelper.java', source)
        self.assertLess(out.index('if (oldVersion != 67)'), out.index('dropAll(db);'))
        self.assertIn('db.execSQL("'+MIGRATION_SQL+'");\n            return;', out)


if __name__ == '__main__':
    unittest.main()
