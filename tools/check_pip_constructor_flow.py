"""Trace the narrow reviewed PiP DEX constructor with modeled framework calls.

Unknown instructions/calls, exception handlers and loops are rejected. This checks
decoded control/data flow, not Android framework implementations or live objects.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

OWNER = 'Lcom/android/systemui/pip/PipUI;'


def trace(body, supports):
    if body['frame']['ins'] != 4 or body['catches'] != ['catches       : (none)']:
        raise ValueError('Unexpected constructor frame/handlers')
    first = body['frame']['registers'] - 4
    registers = {'v' + str(first + i): value for i, value in enumerate(['this', 'context', 'queue', 'lazy'])}
    code = body['instructions']; pc = 0; visited = set(); writes = {}; calls = []; result = None
    while True:
        if pc in visited or not 0 <= pc < len(code): raise ValueError('Loop or invalid target')
        visited.add(pc); line = code[pc]; next_pc = pc + 1
        if not isinstance(line, str): raise ValueError('Unexpected payload')
        if line.startswith('invoke-'):
            match = re.fullmatch(r'invoke-[\w/]+ \{([^}]+)\}, (.*)', line)
            if not match: raise ValueError('Unknown invocation encoding')
            args = [registers[v] for v in match[1].split(', ')]
            target = match[2]; calls.append(target)
            if target == 'Lcom/android/systemui/SystemUI;.<init>:(Landroid/content/Context;)V' and args == ['this', 'context']: result = None
            elif target == 'Landroid/content/Context;.getPackageManager:()Landroid/content/pm/PackageManager;' and args == ['context']: result = 'pm'
            elif target == 'Landroid/content/pm/PackageManager;.hasSystemFeature:(Ljava/lang/String;)Z' and args == ['pm', 'android.software.picture_in_picture']: result = bool(supports)
            elif target == 'Ldagger/Lazy;.get:()Ljava/lang/Object;' and args == ['lazy']: result = 'manager'
            else: raise ValueError('Unreviewed call or receiver/arguments')
        elif (match := re.fullmatch(r'move-result(?:-object)? (v\d+)', line)):
            registers[match[1]] = result
        elif (match := re.fullmatch(r'move-object(?:/from16|/16)? (v\d+), (v\d+)', line)):
            registers[match[1]] = registers[match[2]]
        elif (match := re.fullmatch(r'const-string(?:/jumbo)? (v\d+), "([^"]*)"', line)):
            registers[match[1]] = match[2]
        elif (match := re.fullmatch(r'const(?:/4|/16)? (v\d+), #int 0', line)):
            registers[match[1]] = None
        elif (match := re.fullmatch(r'check-cast (v\d+), Lcom/android/systemui/pip/BasePipManager;', line)):
            if registers[match[1]] not in ['manager', None]: raise ValueError('Wrong cast value')
        elif (match := re.fullmatch(r'if-(eqz|nez) (v\d+), @(\d+)', line)):
            value = registers[match[2]]
            if type(value) is not bool: raise ValueError('Branch is not the modeled feature result')
            if value == (match[1] == 'nez'): next_pc = int(match[3])
        elif (match := re.fullmatch(r'goto(?:/16|/32)? @(\d+)', line)):
            next_pc = int(match[1])
        elif (match := re.fullmatch(r'iput-object (v\d+), (v\d+), ' + re.escape(OWNER) + r'\.(mCommandQueue|mPipManager):[^ ]+', line)):
            if registers[match[2]] != 'this' or match[3] in writes: raise ValueError('Wrong or repeated field write')
            writes[match[3]] = registers[match[1]]
        elif line == 'return-void':
            break
        else: raise ValueError('Unknown instruction: ' + line)
        pc = next_pc
    expected = {'mCommandQueue': 'queue', 'mPipManager': 'manager' if supports else None}
    getter = 'Ldagger/Lazy;.get:()Ljava/lang/Object;'
    feature = 'Landroid/content/pm/PackageManager;.hasSystemFeature:(Ljava/lang/String;)Z'
    parent = 'Lcom/android/systemui/SystemUI;.<init>:(Landroid/content/Context;)V'
    pm = 'Landroid/content/Context;.getPackageManager:()Landroid/content/pm/PackageManager;'
    if writes != expected or calls.count(getter) != int(supports) or calls.count(feature) != 1 or calls.count(parent) != 1 or calls.count(pm) != 1 or len(calls) != 3 + int(supports):
        raise ValueError('Feature branch/provider/field contract failed')
    return dict(supports_pip=bool(supports), visited_instructions=sorted(visited), lazy_get_calls=calls.count(getter), field_writes=writes)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('constructor', type=Path)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args(); raw = a.constructor.read_bytes(); body = json.loads(raw)
    report = dict(constructor_json_sha256=hashlib.sha256(raw).hexdigest(), paths=[trace(body, supports) for supports in [False, True]],
                  limits=['Framework and Lazy calls are modeled return values. No Android process, Dagger factory, R8 output or allocation is executed.'])
    with a.output.open('x') as file: file.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
