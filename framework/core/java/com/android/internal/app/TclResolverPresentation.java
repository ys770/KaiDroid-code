package com.android.internal.app;

import android.content.Context;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.SoundEffectConstants;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AbsListView;
import android.widget.ArrayAdapter;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import java.util.ArrayList;
import java.util.List;

/**
 * PJEP numbered resolver layout. The host supplies real resolved targets and
 * performs selection through the platform resolver; this view never launches intents.
 * The window-owned MenuBar supplies the separate 30px Select footer.
 */
public final class TclResolverPresentation extends FrameLayout {
    /** PJEP uses the chooser's outer title, independently of a SEND preview title. */
    public static CharSequence chooserHeading(Intent chooser, CharSequence fallback) {
        CharSequence title=chooser.getCharSequenceExtra(Intent.EXTRA_TITLE);
        return title!=null ? title : fallback;
    }

    public interface Selection { void select(String key); }

    public static final class Entry {
        public final String key;
        public final CharSequence label;
        public Entry(String key, CharSequence label) {
            if (key == null || label == null) throw new IllegalArgumentException("Null target");
            this.key = key; this.label = label;
        }
    }

    private final LinearLayout sheet;
    private final TextView title;
    private final ListView list;
    private final ArrayList<Entry> entries = new ArrayList<>();
    private final ArrayAdapter<Entry> adapter;
    private final Selection selection;
    private final int selectorColor;
    private int selected;
    private int armedCode = -1;
    private String armedKey;
    private final boolean[] wrappedDirection = new boolean[2];

    public TclResolverPresentation(Context context, CharSequence heading, int color, Selection selection) {
        super(context);
        this.selection = selection;
        selectorColor = color;
        sheet = new LinearLayout(context);
        sheet.setOrientation(LinearLayout.VERTICAL);
        title = new TextView(context);
        title.setText(heading);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 18);
        title.setTextColor(Color.BLACK);
        title.setGravity(Gravity.CENTER);
        GradientDrawable background = new GradientDrawable();
        background.setColor(0xfff0f0f0);
        background.setCornerRadii(new float[]{6,6,6,6,0,0,0,0});
        title.setBackground(background);
        sheet.addView(title, new LinearLayout.LayoutParams(-1,36));
        list = new ListView(context);
        int listId=getResources().getIdentifier("resolver_list","id","android");
        if (listId!=0) list.setId(listId);
        list.setPadding(0,0,0,0);
        list.setDivider(new ColorDrawable(0xfff0f0f0));
        list.setDividerHeight(1);
        list.setSelector(new ColorDrawable(Color.TRANSPARENT));
        list.setCacheColorHint(Color.TRANSPARENT);
        list.setItemsCanFocus(true);
        list.setOnKeyListener(this::key);
        adapter = new ArrayAdapter<Entry>(context, android.R.layout.simple_list_item_1, entries) {
            @Override public View getView(int position, View convert, ViewGroup parent) {
                LinearLayout row;
                TextView text;
                if (convert instanceof LinearLayout) {
                    row = (LinearLayout) convert;
                    text = (TextView) row.getChildAt(0);
                } else {
                    row = new LinearLayout(getContext());
                    row.setOrientation(LinearLayout.VERTICAL);
                    row.setGravity(Gravity.LEFT);
                    row.setBackgroundColor(Color.WHITE);
                    row.setFocusable(true);
                    text = new TextView(getContext());
                    text.setId(android.R.id.text1);
                    text.setDuplicateParentStateEnabled(true);
                    text.setTextSize(TypedValue.COMPLEX_UNIT_SP,16);
                    text.setTextColor(new ColorStateList(new int[][]{
                        new int[]{android.R.attr.state_focused}, new int[]{}
                    }, new int[]{Color.WHITE,Color.BLACK}));
                    StateListDrawable selector = new StateListDrawable();
                    selector.addState(new int[]{android.R.attr.state_focused},new ColorDrawable(selectorColor));
                    selector.addState(new int[]{},new ColorDrawable(Color.WHITE));
                    text.setBackground(selector);
                    text.setPadding(10,0,0,0);
                    text.setGravity(Gravity.CENTER_VERTICAL);
                    text.setMaxLines(1);
                    row.addView(text,new LinearLayout.LayoutParams(-1,34));
                    row.setOnKeyListener(TclResolverPresentation.this::key);
                }
                Entry entry = getItem(position);
                text.setText((position+1)+". "+entry.label);
                row.setTag(entry.key);
                row.setLayoutParams(new AbsListView.LayoutParams(-1,34));
                row.setOnClickListener(view -> activate((String)view.getTag()));
                row.setOnFocusChangeListener((view,focused) -> {
                    if (focused) {
                        int index = indexOf((String)view.getTag());
                        if (index >= 0) selected = index;
                    }
                });
                return row;
            }
        };
        list.setAdapter(adapter);
        list.setOnItemClickListener((parent,view,position,id) -> activate(entries.get(position).key));
        sheet.addView(list,new LinearLayout.LayoutParams(-1,0));
        addView(sheet,new FrameLayout.LayoutParams(-1,-2,Gravity.BOTTOM));
    }

    public void setEntries(List<Entry> targets) {
        String old = entries.isEmpty() ? null : entries.get(selected).key;
        ArrayList<Entry> copy = new ArrayList<>(targets);
        java.util.HashSet<String> keys = new java.util.HashSet<>();
        for (Entry entry : copy) if (entry == null || !keys.add(entry.key))
            throw new IllegalArgumentException("Null or duplicate target key");
        entries.clear(); entries.addAll(copy);
        selected = Math.max(0,indexOf(old));
        if (indexOf(armedKey) < 0) { armedCode=-1; armedKey=null; }
        adapter.notifyDataSetChanged();
        requestLayout();
        if (!entries.isEmpty()) move(selected);
    }

    public void selectCurrent() {
        if (!entries.isEmpty()) activateFromKey(entries.get(selected).key);
    }

    private int indexOf(String key) {
        if (key != null) for (int i=0;i<entries.size();i++) if (key.equals(entries.get(i).key)) return i;
        return -1;
    }

    private void activate(String key) {
        if (indexOf(key) >= 0 && selection != null) selection.select(key);
    }

    private void activateFromKey(String key) {
        if (indexOf(key)>=0) {
            list.playSoundEffect(SoundEffectConstants.CLICK);
            activate(key);
        }
    }

    private void move(int index) {
        selected = index;
        String key = entries.get(index).key;
        list.setSelection(index);
        list.post(() -> {
            if (!entries.isEmpty() && key.equals(entries.get(selected).key)) {
                View row = list.getSelectedView();
                if (row != null) row.requestFocus();
            }
        });
    }

    private boolean key(View view,int code,KeyEvent event) {
        if (code == KeyEvent.KEYCODE_DPAD_UP || code == KeyEvent.KEYCODE_DPAD_DOWN) {
            int direction=code==KeyEvent.KEYCODE_DPAD_UP ? 0 : 1;
            if (event.getAction() == KeyEvent.ACTION_DOWN && !entries.isEmpty()) {
                if ((direction==0 && selected==0) || (direction==1 && selected==entries.size()-1)) {
                    wrappedDirection[direction]=true;
                    move(direction==0 ? entries.size()-1 : 0);
                    list.playSoundEffect(SoundEffectConstants.CLICK);
                    return true;
                }
            } else if (event.getAction()==KeyEvent.ACTION_UP && wrappedDirection[direction]) {
                wrappedDirection[direction]=false;
                return true;
            }
            return false; // Retain native interior focus navigation and its sound effects.
        }
        boolean center = code==KeyEvent.KEYCODE_DPAD_CENTER || code==KeyEvent.KEYCODE_ENTER;
        int index = center ? selected : code-KeyEvent.KEYCODE_1;
        if (!center && (code<KeyEvent.KEYCODE_1 || code>KeyEvent.KEYCODE_9)) return false;
        if (event.getAction()==KeyEvent.ACTION_DOWN && event.getRepeatCount()==0) {
            armedCode=code;
            armedKey=index>=0 && index<entries.size() ? entries.get(index).key : null;
        } else if (event.getAction()==KeyEvent.ACTION_UP && armedCode==code) {
            String key=armedKey;armedKey=null;armedCode=-1;
            if (!event.isCanceled()) activateFromKey(key);
        }
        return true;
    }

    @Override protected void onMeasure(int widthSpec,int heightSpec) {
        int natural = entries.isEmpty() ? 0 : entries.size()*34+entries.size()-1;
        int available = MeasureSpec.getMode(heightSpec)==MeasureSpec.UNSPECIFIED
                ? natural+36 : MeasureSpec.getSize(heightSpec);
        ViewGroup.LayoutParams params=list.getLayoutParams();
        params.height=Math.max(0,Math.min(natural,available-36));
        super.onMeasure(widthSpec,heightSpec);
    }

    @Override protected void onDetachedFromWindow() {
        armedCode=-1;armedKey=null;
        wrappedDirection[0]=wrappedDirection[1]=false;
        super.onDetachedFromWindow();
    }
}
