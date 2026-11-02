"""Index completed private reference captures into a local screenshot gallery."""
import argparse
import html
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def observed_hierarchy(path):
    """Retain observed labels separately from potentially mistaken folder names."""
    if not path.exists():
        return dict(hierarchy_available=False, hierarchy_text=None, text_nodes=None, focused_nodes=None)
    nodes = list(ET.parse(path).iter('node'))
    return dict(hierarchy_available=True,
                hierarchy_text=[n.attrib['text'] for n in nodes if n.attrib.get('text')],
                text_nodes=[{k:n.attrib.get(k) for k in ('text','resource-id','bounds','checked','selected')}
                            for n in nodes if n.attrib.get('text')],
                focused_nodes=[{k: n.attrib.get(k) for k in
                                ('text', 'resource-id', 'class', 'bounds', 'selected', 'checked')}
                               for n in nodes if n.attrib.get('focused') == 'true'])


def build(root):
    entries=[]
    for manifest in sorted(root.rglob('capture.json')):
        path=manifest.parent
        report=json.loads(manifest.read_text())
        if not report['complete']:continue
        entries.append(dict(id=path.relative_to(root).as_posix(), key=report['key'], component=report.get('component'),
                            selected_ime_before=report.get('selected_ime_before'),
                            selected_ime_after=report.get('selected_ime_after'),
                            ime_changed_during_capture=report.get('ime_changed_during_capture'),
                            screenshot_sha256=report['screenshot_sha256'],
                            dimensions=report['dimensions'],
                            **observed_hierarchy(path/'hierarchy.xml')))
    (root/'index.json').write_text(json.dumps(entries,indent=2)+'\n')
    page='''<!doctype html><meta charset="utf-8"><title>TCL live reference</title>
<style>body{font:16px system-ui;background:#ddd}main{display:flex;flex-wrap:wrap;gap:20px}figure{margin:0;background:white;padding:12px;width:240px}img{width:240px;height:320px}figcaption{font-size:13px;overflow-wrap:anywhere}</style>
<h1>TCL 4058L1/PJEP live reference</h1><p>Private 240×320 reference captures. ADB navigation; physical-input verification remains separate. Uncaptured scenarios are unfinished.</p><main>'''
    for entry in entries:
        name=html.escape(entry['id'],quote=True)
        ime=html.escape(entry['selected_ime_after'] or 'not recorded',quote=True)
        observed=html.escape(' | '.join(entry['hierarchy_text'] or []),quote=True)
        page+=f'<figure><a href="{name}/screen.png"><img src="{name}/screen.png"></a><figcaption>{name}<br>Key: {entry["key"]}<br>Selected IME: {ime}<br>Hierarchy text (may be clipped): {observed}</figcaption></figure>'
    (root/'index.html').write_text(page+'</main>',encoding='utf-8')
    return len(entries)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('root',type=Path)
    print(str(build(p.parse_args().root))+' completed captures indexed')
