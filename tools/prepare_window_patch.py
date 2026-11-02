"""Prepare a hash-bound experimental Android 11 shared-window patch; never apply it."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path


HANDLED_KEY_BLOCK = '            if (handled) {\n                if (mKaiDroidMenuBar != null) mKaiDroidMenuBar.onWindowCallbackHandledKey(event);\n                return true;\n            }'


def replace(text, old, new, count=1):
    if text.count(old) != count:
        raise ValueError("Unexpected source anchor count: " + old[:70])
    return text.replace(old, new)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("Output already exists")
    pin = json.loads((Path(__file__).resolve().parents[1] / "docs/contracts/tcl-window-methods.json").read_text())["platform_source"]
    original = {}
    for entry in pin["files"]:
        data = (args.source / entry["path"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError("Source hash mismatch: " + entry["path"])
        original[entry["path"]] = data.decode()
    changed = dict(original)
    window = "core/java/android/view/Window.java"
    changed[window] = replace(changed[window],
        "public static final int FEATURE_MAX = FEATURE_ACTIVITY_TRANSITIONS;",
        "public static final int FEATURE_MAX = 15;\n\n    /** @hide */\n    public static final int FEATURE_KAIDROID_MENU_BAR = 14;\n    /** @hide */\n    public static final int FEATURE_KAIDROID_NO_MENU_BAR = 15;")
    activity = "core/java/android/app/Activity.java"
    for signature in ("@LayoutRes int layoutResID", "View view", "View view, ViewGroup.LayoutParams params"):
        anchor = "public void setContentView(" + signature + ") {"
        changed[activity] = replace(changed[activity], anchor, anchor + "\n        ((com.android.internal.policy.PhoneWindow) getWindow()).enableMenuBar(true);")
    api = """
    /** @hide */
    public android.widget.MenuBar getMenuBar() {
        return ((com.android.internal.policy.DecorView) getWindow().getDecorView()).getMenuBar();
    }
    /** @hide */
    public void addMenuBar() {
        ((com.android.internal.policy.DecorView) getWindow().getDecorView()).addMenuBar();
    }
    /** @hide */
    public void removeMenuBar() {
        ((com.android.internal.policy.DecorView) getWindow().getDecorView()).removeMenuBar();
    }
"""
    for path in (activity, "core/java/android/app/Dialog.java"):
        end = changed[path].rfind("}")
        changed[path] = changed[path][:end] + api + changed[path][end:]
    phone = "core/java/com/android/internal/policy/PhoneWindow.java"
    code = """
    private boolean mKaiDroidMenuEnabled;
    /** @hide */
    public void enableMenuBar(boolean enabled) { mKaiDroidMenuEnabled = enabled; }
    private void updateKaiDroidMenuBar() {
        if (hasFeature(FEATURE_KAIDROID_MENU_BAR)) mKaiDroidMenuEnabled = true;
        else if (hasFeature(FEATURE_KAIDROID_NO_MENU_BAR)) mKaiDroidMenuEnabled = false;
        if (mKaiDroidMenuEnabled) mDecor.addMenuBar();
        else mDecor.removeMenuBar();
    }
"""
    anchor = "    @Override\n    public void setContentView(int layoutResID) {"
    changed[phone] = replace(changed[phone], anchor, code + anchor)
    anchor = "            mContentParent.removeAllViews();\n        }\n\n        if (hasFeature(FEATURE_CONTENT_TRANSITIONS)) {"
    changed[phone] = replace(changed[phone], anchor,
        anchor.replace("\n\n        if", "\n        updateKaiDroidMenuBar();\n\n        if"), 2)
    decor = "core/java/com/android/internal/policy/DecorView.java"
    code = """
    private android.widget.MenuBar mKaiDroidMenuBar;
    private int kaiDroidBarHeight() {
        return Math.round(30 * getResources().getDisplayMetrics().density);
    }
    /** @hide */
    public android.widget.MenuBar getMenuBar() { return mKaiDroidMenuBar; }
    /** @hide */
    public void addMenuBar() {
        if (mKaiDroidMenuBar != null) return;
        mKaiDroidMenuBar = new android.widget.MenuBar(getContext()) {
            @Override protected void onVisibilityChanged(View changedView, int visibility) {
                super.onVisibilityChanged(changedView, visibility);
                // Ignore ancestor visibility and construction/attachment callbacks.
                // Only this bar's own visibility changes its reserved content space.
                if (changedView == this && mKaiDroidMenuBar == this
                        && getParent() == DecorView.this) {
                    DecorView.this.updateColorViews(null, false);
                    DecorView.this.requestApplyInsets();
                }
            }
        };
        FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, kaiDroidBarHeight(), Gravity.BOTTOM);
        mKaiDroidMenuBar.setFitsSystemWindows(false);
        addView(mKaiDroidMenuBar, params);
        updateColorViews(null, false);
        requestApplyInsets();
    }
    /** @hide */
    public void removeMenuBar() {
        if (mKaiDroidMenuBar == null) return;
        android.widget.MenuBar old = mKaiDroidMenuBar;
        mKaiDroidMenuBar = null;
        old.clearSoftKeyState();
        old.dismissOptionMenu();
        removeView(old);
        updateColorViews(null, false);
        requestApplyInsets();
    }
"""
    anchor = "    ViewGroup mContentRoot;"
    changed[decor] = replace(changed[decor], anchor, anchor + "\n" + code)
    anchor = "        int consumedLeft = consumingNavBar ? mLastLeftInset : 0;"
    addition = """
        final int contentBottom = consumedBottom + (mKaiDroidMenuBar != null
                && mKaiDroidMenuBar.getVisibility() != GONE ? kaiDroidBarHeight() : 0);
        if (mKaiDroidMenuBar != null) {
            FrameLayout.LayoutParams barParams = (FrameLayout.LayoutParams) mKaiDroidMenuBar.getLayoutParams();
            if (barParams.bottomMargin != consumedBottom) {
                barParams.bottomMargin = consumedBottom;
                mKaiDroidMenuBar.setLayoutParams(barParams);
            }
        }
"""
    changed[decor] = replace(changed[decor], anchor, anchor + addition)
    changed[decor] = replace(changed[decor], "lp.bottomMargin != consumedBottom", "lp.bottomMargin != contentBottom")
    changed[decor] = replace(changed[decor], "lp.bottomMargin = consumedBottom;", "lp.bottomMargin = contentBottom;")
    anchor = "            if (handled) {\n                return true;\n            }\n        }\n\n        return isDown ? mWindow.onKeyDown"
    addition = HANDLED_KEY_BLOCK + """
        }
        if (mKaiDroidMenuBar != null) {
            boolean barHandled = isDown ? mKaiDroidMenuBar.onKeyDown(keyCode, event)
                    : event.getAction() == KeyEvent.ACTION_UP && mKaiDroidMenuBar.onKeyUp(keyCode, event);
            if (barHandled) return true;
        }

        return isDown ? mWindow.onKeyDown"""
    changed[decor] = replace(changed[decor], anchor, addition)
    patch = "".join("".join(difflib.unified_diff(original[path].splitlines(True), changed[path].splitlines(True),
                   fromfile="a/" + path, tofile="b/" + path)) for path in sorted(changed))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(patch, newline="\n")
    print("Prepared patch for", len(changed), "pinned files; not applied or platform-compiled")


if __name__ == "__main__":
    main()
