import unittest
from rewrite_clock_identity_smali import java_hash,rewrite_method,rewrite

class ClockIdentityTests(unittest.TestCase):
    def test_java_hash(self):
        self.assertEqual(java_hash('com.android.deskclock.ALARM_SNOOZE'),-0x2501dba7)
        self.assertEqual(java_hash('com.android.deskclock.ALARM_DISMISS'),0x62f7ea57)
        self.assertEqual(java_hash('Aa'),java_hash('BB'))
    def test_sparse_and_direct_hashes(self):
        old='com.android.deskclock.ALARM_SNOOZE';new='com.kaidroid.tclclock.ALARM_SNOOZE'
        text='''invoke-virtual {p2}, Ljava/lang/String;->hashCode()I
const-string v0, "%s"
const v1, %s
.sparse-switch
        %s -> :target
        0x0 -> :other
    .end sparse-switch'''%(old,hex(java_hash(old)),hex(java_hash(old)))
        out,updates=rewrite_method(text,{old:new})
        self.assertEqual(len(updates),2)
        self.assertIn('"'+new+'"',out)
        self.assertIn('const v1, '+hex(java_hash(new)),out)
        rows=out.split('.sparse-switch\n')[1].split('.end sparse-switch')[0].strip().splitlines()
        keys=[int(row.split(' -> ')[0],0) for row in rows]
        self.assertEqual(keys,sorted(keys))
        self.assertEqual(rewrite_method(out,{old:new})[0],out)
    def test_no_hash_rewrite_without_hash_dispatch(self):
        out,updates=rewrite_method('const v0, 0x62f7ea57\nconst-string v1, "com.android.deskclock.ALARM_DISMISS"',{'com.android.deskclock.ALARM_DISMISS':'com.kaidroid.tclclock.ALARM_DISMISS'})
        self.assertIn('0x62f7ea57',out);self.assertEqual(updates,[])
    def test_class_descriptor_and_field(self):
        source='.class public Lcom/android/deskclock/DeskClock;\n.field public static final AUTH:Ljava/lang/String; = "com.android.deskclock"\n'
        out,_=rewrite(source,{'com.android.deskclock':'com.kaidroid.tclclock'})
        self.assertIn('Lcom/android/deskclock/DeskClock;',out)
        self.assertIn('"com.kaidroid.tclclock"',out)

if __name__=='__main__':unittest.main()
