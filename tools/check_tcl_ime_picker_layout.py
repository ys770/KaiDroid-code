"""Validate measured six-mode Notes picker geometry; never operate a device."""
import argparse
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

MODES = ['Kt9','abc','Abc','ABC','123','Symbols']


def bounds(value):
    if isinstance(value,list) and len(value)==4 and all(type(n) is int for n in value):
        return value
    match = re.fullmatch(r'\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]',str(value))
    if not match: raise ValueError('Invalid node bounds')
    return list(map(int,match.groups()))


def probe_nodes(tree):
    yield tree
    for child in tree.get('children',[]): yield from probe_nodes(child)


def xml_nodes(text):
    return [dict(node.attrib) for node in ET.fromstring(text).iter('node')]


def validate(nodes):
    nodes=[n for n in nodes if n.get('shown',True) and n.get('visibility',0)==0]
    errors=[]
    texts=[n.get('text','') for n in nodes]
    if 'Input mode' in texts: errors.append('Unexpected title; donor is titleless')
    rows=[n for n in nodes if re.match(r'^\d+\. ',n.get('text',''))]
    labels=[n['text'] for n in rows]
    expected=[str(i+1)+'. '+mode for i,mode in enumerate(MODES)]
    if labels != expected: errors.append('Visible mode rows differ from matched original Notes six-mode reference')
    positions=[]
    for i,row in enumerate(rows):
        box=bounds(row['bounds']);positions.append(box)
        # Original RecyclerView text excludes horizontal padding; replacement
        # ListView text includes it. Both must retain the same34px text row.
        if box[1]!=81+35*i or box[3]!=115+35*i or not 0<=box[0]<box[2]<=240:
            errors.append('Row '+str(i+1)+' is displaced or clipped')
    lists=[n for n in nodes if n.get('class','') in
           ('android.widget.ListView','com.android.internal.widget.RecyclerView')]
    if len(lists)!=1 or bounds(lists[0]['bounds']) != [0,81,240,290]:
        errors.append('Picker list must occupy [0,81,240,290]')
    footer=[n for n in nodes if n.get('text') and bounds(n['bounds'])[3]>290
            and bounds(n['bounds'])[1]<320]
    if [n['text'] for n in footer] != ['Select']:
        errors.append('Picker must own a single Select footer, without app editor actions')
    elif not (bounds(footer[0]['bounds'])[1:4:2]==[290,320]
              and bounds(footer[0]['bounds'])[0] < 120 < bounds(footer[0]['bounds'])[2]):
        errors.append('Select footer is clipped or displaced')
    return dict(passed=not errors,errors=errors,observed_rows=labels,row_text_bounds=positions,
        measured_list_bounds=[bounds(n['bounds']) for n in lists],
        scope='Six-mode matched Notes layout only; not pixels, advertised-mode provenance, callback or physical-key proof')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    source=p.add_mutually_exclusive_group(required=True)
    source.add_argument('--xml',type=Path)
    source.add_argument('--probe-report',type=Path)
    p.add_argument('--case',default='picker-initial')
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    if args.output.exists(): raise FileExistsError(args.output)
    if args.xml: nodes=xml_nodes(args.xml.read_text(encoding='utf-8'))
    else:
        report=json.loads(args.probe_report.read_text(encoding='utf-8'))
        cases=[case for case in report['cases'] if case['case']==args.case]
        if len(cases)!=1:raise ValueError('Missing or ambiguous probe case')
        nodes=list(probe_nodes(cases[0]['tree']))
    result=validate(nodes)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result))
    if not result['passed']:raise ValueError('Picker layout does not match the measured donor')


if __name__=='__main__':main()
