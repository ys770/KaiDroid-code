"""Prepare an isolated native ChooserActivity presentation overlay; never launch builds."""
import argparse
import hashlib
import json
from pathlib import Path

SOURCE_SHA='8ce601b48e97871d2d68326bebce1c44673ed27a3512adad756e6c162daecc10'


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def once(text,old,new):
    if text.count(old)!=1:raise ValueError('Unexpected chooser anchor: '+old[:80])
    return text.replace(old,new)


def method_body(text,signature):
    """Extract a pinned Java8 body, skipping comment/string/character braces."""
    if text.count(signature)!=1:raise ValueError('Ambiguous method: '+signature)
    start=text.index('{',text.index(signature));depth=0;state='code';i=start
    while i<len(text):
        ch=text[i];pair=text[i:i+2]
        if state=='line':
            if ch=='\n':state='code'
        elif state=='block':
            if pair=='*/':state='code';i+=1
        elif state in ('string','char'):
            if ch=='\\':i+=1
            elif ch==('"' if state=='string' else "'"):state='code'
        elif pair=='//':state='line';i+=1
        elif pair=='/*':state='block';i+=1
        elif ch=='"':state='string'
        elif ch=="'":state='char'
        elif ch=='{':depth+=1
        elif ch=='}':
            depth-=1
            if depth==0:return text[start:i+1]
        i+=1
    raise ValueError('Unclosed Java method')


def prepare(source,output):
    if sha(source)!=SOURCE_SHA:raise ValueError('Wrong native ChooserActivity source')
    root=Path(__file__).resolve().parents[1]
    fragment=root/'framework/patches/tcl-chooser-host.java.fragment'
    helper=root/'framework/core/java/com/android/internal/app/TclResolverPresentation.java'
    original=text=source.read_text(encoding='utf-8')
    anchor='''        super.onCreate(savedInstanceState, target, title, defaultTitleRes, initialIntents,
                null, false);'''
    predicate='''        String tclSelector=target != null ? target.getStringExtra("ext_selector") : null;
        mTclResolverRequested=target != null && Intent.ACTION_SEND.equals(target.getAction())
                && target.getType() != null && target.getType().startsWith("image/")
                && tclSelector != null && tclSelector.matches("#[0-9a-fA-F]{6}")
                && getResources().getConfiguration().screenWidthDp<=240
                && !isVoiceInteraction()
                && (initialIntents == null || initialIntents.length==0)
                && mCallerChooserTargets == null
                && !intent.hasExtra(Intent.EXTRA_ALTERNATE_INTENTS);
'''
    text=once(text,anchor,predicate+anchor)
    anchor='''        mDirectShareShortcutInfoCache = new HashMap<>();
        mChooserTargetComponentNameCache = new HashMap<>();
    }'''
    text=once(text,anchor,anchor[:-5]+'''        if (mTclResolverRequested) setupTclResolver(title,tclSelector);
    }''')
    anchor='''    public void onListRebuilt(ResolverListAdapter listAdapter) {
'''
    text=once(text,anchor,anchor+'        postTclResolverRefresh();\n')
    anchor='''    protected void onDestroy() {
        super.onDestroy();'''
    text=once(text,anchor,'''    protected void onDestroy() {
        clearTclResolverObserver();
        mTclResolverPresentation=null;mTclHiddenContent.clear();
        super.onDestroy();''')
    if not text.endswith('}\n'):raise ValueError('Unexpected chooser class ending')
    text=text[:-2]+'\n'+fragment.read_text(encoding='utf-8')+'\n}\n'
    unchanged={}
    for signature in ['protected boolean onTargetSelected(', 'public void startSelected(',
                      'public void onActivityStarted(', 'public Intent getReplacementIntent(',
                      'public boolean shouldAutoLaunchSingleChoice(']:
        before=method_body(original,signature);after=method_body(text,signature)
        if before!=after:raise ValueError('Native routing method changed: '+signature)
        unchanged[signature]=hashlib.sha256(before.encode()).hexdigest()
    output.mkdir(parents=True,exist_ok=False)
    path=output/'overlay/core/java/com/android/internal/app';path.mkdir(parents=True)
    (path/'ChooserActivity.java').write_text(text,encoding='utf-8',newline='\n')
    (path/'TclResolverPresentation.java').write_bytes(helper.read_bytes())
    report=dict(native_source_sha256=SOURCE_SHA,helper_sha256=sha(helper),host_fragment_sha256=sha(fragment),
        files={str(p.relative_to(output)):sha(p) for p in path.iterdir()},
        scope='Opt-in marked image share on240dp single-profile; native TargetInfo/startSelected/URI/caller policy retained',
        resources_changed=False,manifest_changed=False,built=False,installed=False,
        unchanged_native_routing_bodies=unchanged,
        limitations=['Host overlay not platform compiled or runtime tested','No URI-grant or caller-identity test yet',
            'Native fallback for unsupported targets/profiles/empty state; not full framework chooser parity',
            'Presentation pixel match on actual donor/Nokia not established'])
    (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();print(json.dumps(prepare(a.source,a.output)))
