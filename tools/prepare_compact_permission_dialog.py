"""Prepare a pinned compact-screen PermissionController view adaptation offline.

Native visibility, permission result handling and permission policy stay intact.
The optional framework soft-key bridge delegates only to visible native buttons.
"""
import argparse
import hashlib
import json
from pathlib import Path

BASE = '8db829a653964c792c4590b7d4824bfc2fe1a16909fd1fed1a810213e5e82b68'

METHODS = r'''
    // KaiDroid compact handheld presentation; no permission-policy decisions here.
    private Object mCompactMenuBar;
    private java.lang.reflect.Method mCompactSetLabel;
    private java.lang.reflect.Method mCompactSetListener;

    private boolean isCompactKeypad() {
        android.content.res.Configuration config = mActivity.getResources().getConfiguration();
        return config.screenWidthDp > 0 && config.screenWidthDp <= 320
                && config.screenHeightDp > 0 && config.screenHeightDp <= 480;
    }

    private int compactDp(int value) {
        return Math.round(value * mActivity.getResources().getDisplayMetrics().density);
    }

    private void compactView(View view) {
        view.setMinimumHeight(0);
        view.setPadding(0, 0, 0, 0);
        ViewGroup.LayoutParams params = view.getLayoutParams();
        if (params != null) {
            params.width = ViewGroup.LayoutParams.MATCH_PARENT;
            params.height = ViewGroup.LayoutParams.WRAP_CONTENT;
            if (params instanceof ViewGroup.MarginLayoutParams) {
                ((ViewGroup.MarginLayoutParams) params).setMargins(0, 0, 0, 0);
                ((ViewGroup.MarginLayoutParams) params).setMarginStart(0);
                ((ViewGroup.MarginLayoutParams) params).setMarginEnd(0);
            }
        }
        if (view instanceof android.widget.LinearLayout) {
            ((android.widget.LinearLayout) view).setGravity(android.view.Gravity.TOP);
        }
        if (view instanceof TextView) {
            TextView text = (TextView) view;
            text.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 14);
            text.setPadding(compactDp(6), compactDp(4), compactDp(6), compactDp(4));
            text.setMinHeight(0);
        }
        if (view instanceof Button) {
            ((Button) view).setMinHeight(compactDp(36));
            view.setMinimumHeight(compactDp(36));
            view.setFocusable(true);
            view.setFocusableInTouchMode(true);
        } else if (view instanceof ImageView && params != null) {
            params.width = compactDp(24);
            params.height = compactDp(24);
        } else if (view instanceof android.widget.Space && params != null) {
            params.height = 0;
        }
        if (view instanceof ViewGroup) {
            ViewGroup group = (ViewGroup) view;
            for (int i = 0; i < group.getChildCount(); i++) compactView(group.getChildAt(i));
        }
    }

    private Button compactFocusedButton() {
        View focused = mRootView.findFocus();
        for (Button button : mButtons) {
            if (button != null && button == focused && button.isShown() && button.isEnabled()) {
                return button;
            }
        }
        return null;
    }

    private void updateCompactLabel() {
        if (mCompactMenuBar == null) return;
        Button button = compactFocusedButton();
        try {
            mCompactSetLabel.invoke(mCompactMenuBar, 1,
                    button == null ? "" : button.getText().toString());
        } catch (ReflectiveOperationException failure) {
            android.util.Log.w("CompactPermissionDialog", "Cannot update soft-key label", failure);
        }
    }

    private void attachCompactSoftKeys() {
        try {
            mCompactMenuBar = mActivity.getClass().getMethod("getMenuBar").invoke(mActivity);
            if (mCompactMenuBar == null) return;
            Class<?> listenerClass = Class.forName("android.widget.MenuBar$MenuBarListener");
            mCompactSetLabel = mCompactMenuBar.getClass().getMethod("setSoftKeyName",
                    int.class, String.class);
            mCompactSetListener = mCompactMenuBar.getClass().getMethod("setMenuBarListener",
                    listenerClass);
            Object listener = java.lang.reflect.Proxy.newProxyInstance(
                    listenerClass.getClassLoader(), new Class<?>[] {listenerClass},
                    (proxy, method, arguments) -> {
                        String name = method.getName();
                        if (name.equals("hashCode")) return System.identityHashCode(proxy);
                        if (name.equals("equals")) return proxy == arguments[0];
                        if (name.equals("toString")) return "CompactPermissionSoftKeys";
                        if (!mRootView.isAttachedToWindow() || !mRootView.hasWindowFocus()) {
                            return method.getReturnType() == boolean.class ? false : null;
                        }
                        if (name.equals("onClickCSK")) {
                            Button button = compactFocusedButton();
                            if (button != null) button.performClick();
                            return true;
                        }
                        if (name.equals("onClickRSK")) {
                            onBackPressed();
                            return true;
                        }
                        return method.getReturnType() == boolean.class ? false : null;
                    });
            mCompactSetListener.invoke(mCompactMenuBar, listener);
            mCompactSetLabel.invoke(mCompactMenuBar, 0, "");
            mCompactSetLabel.invoke(mCompactMenuBar, 2, mActivity.getString(android.R.string.cancel));
            updateCompactLabel();
        } catch (ReflectiveOperationException failure) {
            mCompactMenuBar = null;
            android.util.Log.w("CompactPermissionDialog", "Native buttons remain available", failure);
        }
    }

    private void setupCompactDialog() {
        compactView(mRootView);
        mRootView.setPadding(compactDp(4), compactDp(4), compactDp(4), compactDp(4));
        mRootView.findViewById(R.id.grant_singleton).setFocusable(false);
        mRootView.findViewById(R.id.grant_dialog).setFocusable(false);
        // The original inset background assumes smartphone padding. After
        // compacting, use the same theme's color over the actual content bounds.
        View dialog = mRootView.findViewById(R.id.grant_dialog);
        android.content.res.TypedArray colors = dialog.getContext().obtainStyledAttributes(
                new int[] {android.R.attr.colorBackground});
        dialog.setBackgroundColor(colors.getColor(0, android.graphics.Color.WHITE));
        colors.recycle();
        mRootView.getViewTreeObserver().addOnGlobalFocusChangeListener(
                (oldFocus, newFocus) -> updateCompactLabel());
        mRootView.addOnAttachStateChangeListener(new View.OnAttachStateChangeListener() {
            @Override public void onViewAttachedToWindow(View view) {
                attachCompactSoftKeys();
                mRootView.post(() -> {
                    if (mRootView.isAttachedToWindow()) focusCompactChoice();
                });
            }
            @Override public void onViewDetachedFromWindow(View view) {
                if (mCompactMenuBar != null) {
                    try {
                        mCompactSetListener.invoke(mCompactMenuBar, new Object[] {null});
                    } catch (ReflectiveOperationException failure) {
                        android.util.Log.w("CompactPermissionDialog", "Cannot clear soft keys", failure);
                    }
                }
                mCompactMenuBar = null;
            }
        });
    }

    private void focusCompactChoice() {
        // Select a non-granting choice initially; preserve every native visibility rule.
        int[] choices = {DENY_BUTTON, DENY_AND_DONT_ASK_AGAIN_BUTTON,
                NO_UPGRADE_BUTTON, NO_UPGRADE_AND_DONT_ASK_AGAIN_BUTTON,
                NO_UPGRADE_OT_BUTTON, NO_UPGRADE_OT_AND_DONT_ASK_AGAIN_BUTTON};
        for (int choice : choices) {
            Button button = mButtons[choice];
            if (button != null && button.getVisibility() == View.VISIBLE && button.isEnabled()) {
                button.requestFocus();
                updateCompactLabel();
                return;
            }
        }
        // No denial button: do not preselect an affirmative action.
        mRootView.clearFocus();
        updateCompactLabel();
    }
'''


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Unexpected source anchor: ' + old[:70])
    return text.replace(old, new, 1)


def prepare(data):
    if hashlib.sha256(data).hexdigest() != BASE:
        raise ValueError('Unrecognized PermissionController source')
    text = data.decode()
    text = replace_once(text, '        mRootView.setMinimumHeight(h);',
                        '        mRootView.setMinimumHeight(isCompactKeypad() ? 0 : h);')
    text = replace_once(text, '        if (mGroupName != null) {',
                        '        if (isCompactKeypad()) setupCompactDialog();\n\n        if (mGroupName != null) {')
    text = replace_once(text, '        // No-op', '''        if (isCompactKeypad()) {
            outLayoutParams.width = LayoutParams.MATCH_PARENT;
            outLayoutParams.height = LayoutParams.MATCH_PARENT;
        }''')
    anchor = '            mButtons[pos].setVisibility(mButtonVisibilities[pos] ? View.VISIBLE : View.GONE);\n        }'
    text = replace_once(text, anchor, anchor + '\n        if (isCompactKeypad()) focusCompactChoice();')
    text = replace_once(text, '    private void updateDescription() {', METHODS + '\n    private void updateDescription() {')
    return text.encode()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    data = prepare(args.source.read_bytes())
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / args.source.name).write_bytes(data)
    report = dict(source_sha256=BASE, candidate_sha256=hashlib.sha256(data).hexdigest(),
                  built=False, installed=False, permission_policy_changed=False)
    (args.output / 'candidate.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
