"""Exercise actual candidate focus-selection methods with minimal host view stand-ins.

Not Android layout, reflection/hidden-API, permission-grant or physical-key testing.
"""
import argparse
import subprocess
from pathlib import Path


def extract(text, declaration):
    start = text.index(declaration)
    end = text.index('{', start) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'jdk', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    text = a.source.read_text(encoding='utf-8')
    methods = '\n'.join(extract(text, d) for d in (
        'private Button compactFocusedButton()', 'private void focusCompactChoice()'))
    harness = r'''
public class CompactPermissionFocusTest {
    static final int DENY_BUTTON=1, DENY_AND_DONT_ASK_AGAIN_BUTTON=2,
        NO_UPGRADE_BUTTON=3, NO_UPGRADE_AND_DONT_ASK_AGAIN_BUTTON=4,
        NO_UPGRADE_OT_BUTTON=5, NO_UPGRADE_OT_AND_DONT_ASK_AGAIN_BUTTON=6;
    static class View { static final int VISIBLE=0, GONE=8; }
    class Root extends View {
        View focus;
        View findFocus() { return focus; }
        void clearFocus() { focus=null; }
    }
    class Button extends View {
        int visibility=GONE; boolean enabled=true, shown=true;
        int getVisibility(){return visibility;}
        boolean isEnabled(){return enabled;}
        boolean isShown(){return shown && visibility==VISIBLE;}
        boolean requestFocus(){mRootView.focus=this;return true;}
    }
    Root mRootView=new Root(); Button[] mButtons=new Button[7];
    void updateCompactLabel(){}
    static int checks;
    static void check(boolean result) {checks++; if(!result)throw new AssertionError(checks);}
    void run() {
        for(int i=0;i<mButtons.length;i++)mButtons[i]=new Button();
        mButtons[0].visibility=View.VISIBLE; // affirmative is never the initial fallback
        focusCompactChoice();check(mRootView.focus==null);
        for(int i=1;i<mButtons.length;i++) {
            mButtons[i].visibility=View.VISIBLE;
            focusCompactChoice();check(mRootView.focus==mButtons[i]);
            check(compactFocusedButton()==mButtons[i]);
            mButtons[i].enabled=false;check(compactFocusedButton()==null);
            focusCompactChoice();check(mRootView.focus==null);
            mButtons[i].enabled=true;mButtons[i].visibility=View.GONE;
        }
        mButtons[1].visibility=View.VISIBLE;mButtons[2].visibility=View.VISIBLE;
        focusCompactChoice();check(mRootView.focus==mButtons[1]);
        mButtons[1].shown=false;check(compactFocusedButton()==null);
        mRootView.focus=new View();check(compactFocusedButton()==null);
        mRootView.focus=mButtons[0];check(compactFocusedButton()==mButtons[0]);
    }
    public static void main(String[] args) {
        new CompactPermissionFocusTest().run();
        System.out.println(checks+" focus checks passed; Android runtime unverified");
    }
'''
    a.output.mkdir(parents=True, exist_ok=False)
    source = a.output / 'CompactPermissionFocusTest.java'
    source.write_text(harness + methods + '\n}\n', encoding='utf-8')
    subprocess.run([str(a.jdk / 'bin/javac.exe'), str(source)], check=True)
    subprocess.run([str(a.jdk / 'bin/java.exe'), '-cp', str(a.output),
                    'CompactPermissionFocusTest'], check=True)


if __name__ == '__main__':
    main()
