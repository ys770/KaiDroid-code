"""Prepare isolated original-Kika footer/inset candidate from exact AOSP source; never install."""
import argparse
import hashlib
import json
from pathlib import Path

BASE='0b36035b542f7bccba0c8c95d443dce0d59a82b1c91d01a81519f99ae50dfd6d'
HELPER='''package android.inputmethodservice;

import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;

/** Original TCL IME footer geometry, bounded to the captured stock Kika. */
final class TclImeFooterLayout {
    static final String KIKA = "com.iqqijni.dvt912key";
    // Original DecorView constructs its menu layout with30 physical pixels.
    static final int FOOTER = 30;

    static boolean reserveFooter(String owner, View root) {
        if (!KIKA.equals(owner) || root == null) return false;
        ViewGroup.LayoutParams raw = root.getLayoutParams();
        if (!(raw instanceof ViewGroup.MarginLayoutParams)) return false;
        ViewGroup.MarginLayoutParams params = (ViewGroup.MarginLayoutParams) raw;
        if (params.bottomMargin != FOOTER) {
            params.bottomMargin = FOOTER;
            root.setLayoutParams(params);
        }
        return true;
    }

    static boolean updateSymbolsShown(String owner, FrameLayout candidates, boolean previous) {
        if (!KIKA.equals(owner)) return false;
        if (candidates == null || candidates.getVisibility() != View.VISIBLE) return previous;
        View first = candidates.getChildAt(0);
        if (!(first instanceof ViewGroup)) return previous;
        ViewGroup group = (ViewGroup) first;
        if (group.getChildCount() <= 1) return previous;
        View symbols = group.getChildAt(1);
        if (symbols == null) return previous;
        if (symbols.getVisibility() == View.VISIBLE) return true;
        if (symbols.getVisibility() == View.GONE) return false;
        return previous;
    }

    static int adjustedTop(String owner, int top, boolean symbolsShown) {
        return KIKA.equals(owner) && symbolsShown ? top - FOOTER : top;
    }
}
'''


def sha(data):return hashlib.sha256(data).hexdigest()


def source(data):
    if sha(data)!=BASE:raise ValueError('Require exact exported AOSP InputMethodService source')
    text=data.decode('utf-8')
    edits={
        '    private IBinder mCurHideInputToken;':'    private IBinder mCurHideInputToken;\n    private boolean mTclSymbolsShown;',
        '        mWindow.setContentView(mRootView);':'        mWindow.setContentView(mRootView);\n        TclImeFooterLayout.reserveFooter(getPackageName(), mRootView);',
        '            info.contentInsets.top = mTmpInsets.contentTopInsets;\n            info.visibleInsets.top = mTmpInsets.visibleTopInsets;':
        '            info.contentInsets.top = TclImeFooterLayout.adjustedTop(\n                    getPackageName(), mTmpInsets.contentTopInsets, mTclSymbolsShown);\n            info.visibleInsets.top = TclImeFooterLayout.adjustedTop(\n                    getPackageName(), mTmpInsets.visibleTopInsets, mTclSymbolsShown);',
        '    public void onComputeInsets(Insets outInsets) {\n        int[] loc = mTmpLocation;':
        '    public void onComputeInsets(Insets outInsets) {\n        mTclSymbolsShown = TclImeFooterLayout.updateSymbolsShown(\n                getPackageName(), mCandidatesFrame, mTclSymbolsShown);\n        int[] loc = mTmpLocation;',
    }
    for old,new in edits.items():
        if text.count(old)!=1:raise ValueError('Unreviewed AOSP source shape: '+old)
        text=text.replace(old,new)
    return text.encode()


def single_unit(data):
    """Keep both nonpublic helper and IMS in one existing bind destination.

    Avoid creating a new file inside the shared read-only AOSP source mount.
    The helper body remains byte-identical to the SDK-tested source.
    """
    patched=source(data)
    for required in (b'import android.view.View;',b'import android.view.ViewGroup;',b'import android.widget.FrameLayout;'):
        if patched.count(required)!=1:raise ValueError('Existing IMS imports do not cover helper')
    return patched.rstrip()+b'\n\n'+HELPER[HELPER.index('/**'):].encode()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--aosp-source',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--single-unit',action='store_true')
    a=p.parse_args();data=a.aosp_source.read_bytes()
    files={'core/java/android/inputmethodservice/InputMethodService.java':single_unit(data) if a.single_unit else source(data)}
    if not a.single_unit:files['core/java/android/inputmethodservice/TclImeFooterLayout.java']=HELPER.encode()
    a.output.mkdir(parents=True,exist_ok=False)
    for name,data in files.items():
        path=a.output/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
    report=dict(scope='Isolated candidate; SDK and native review required before build',aosp_source_sha256=BASE,
        files={n:sha(b) for n,b in files.items()},original_framework_sha256='70cc25b51f2067508b7dfa415084440321359054a881377b093dfddecd97afe8',
        single_existing_source_bind=a.single_unit,sdk_tested_helper_source_sha256=sha(HELPER.encode()),
        original_footer_physical_pixels=30,bounded_to_package='com.iqqijni.dvt912key',
        original_view_visibility_state_semantics_retained=True,full_native_source_compiled=False,
        native09_or_image54_modified=False,installed=False,full_parity=False)
    (a.output/'contract.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()
