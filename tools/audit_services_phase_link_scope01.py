"""Offline final-function census. Report unresolved changes; never infer full equivalence."""
import sys
sys.dont_write_bytecode = True
import argparse
import bisect
from collections import Counter, defaultdict
import hashlib
from io import BytesIO
import json
from pathlib import Path
import struct
import capstone as cs
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC
from elftools.elf.elffile import ELFFile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def known(token):
    if isinstance(token, (list, tuple)):
        return (not token or token[0] != 'unresolved') and all(known(value) for value in token)
    return True


def name_key(name):
    # The three helpers were already source/IR matched in matrix02. No general lambda rewrite.
    if 'UnlinkLeastRecentlyUsedVdexIfNeeded' in name and name.startswith(('_ZNSt3__16__sortI', '_ZNSt3__17__sort4I', '_ZNSt3__127__insertion_sort_incompleteI')):
        return name.replace('E4$_34', 'E4$_32')
    return name


def packed_rel(raw):
    """ARM REL only; APS2 grouping follows bionic/linker/linker_reloc_iterators.h."""
    # https://android.googlesource.com/platform/bionic/+/master/linker/linker_reloc_iterators.h
    if raw[:4] != b'APS2':
        raise ValueError('Expected APS2')
    position = 4
    def sleb():
        nonlocal position
        value, shift = 0, 0
        while True:
            if position >= len(raw) or shift > 35:
                raise ValueError('Invalid packed SLEB')
            byte = raw[position]
            position += 1
            value |= (byte & 127) << shift
            shift += 7
            if not byte & 128:
                return value - (1 << shift) if byte & 64 else value
    count, offset = sleb(), sleb()
    if not 0 <= count <= 1000000:
        raise ValueError('Invalid packed count')
    result = []
    while len(result) < count:
        size, flags = sleb(), sleb()
        if not 0 < size <= count - len(result) or flags & ~3:
            raise ValueError('Unexpected REL group/addend flags')
        delta = sleb() if flags & 2 else None
        info = sleb() if flags & 1 else None
        for _ in range(size):
            offset += delta if delta is not None else sleb()
            entry = info if info is not None else sleb()
            if offset < 0 or offset % 4 or not 0 <= entry <= 0xffffffff:
                raise ValueError('Invalid packed relocation')
            result.append((offset, entry >> 8, entry & 255))
    if position != len(raw):
        raise ValueError('Packed relocation trailing bytes')
    return result


def relr_offsets(raw):
    if len(raw) % 4:
        raise ValueError('Unaligned RELR')
    where, result = None, set()
    for (entry,) in struct.iter_unpack('<I', raw):
        if entry & 1:
            if where is None:
                raise ValueError('RELR bitmap lacks address')
            for bit in range(31):
                if entry & (1 << (bit + 1)):
                    if where + bit * 4 in result:
                        raise ValueError('Duplicate RELR slot')
                    result.add(where + bit * 4)
            where += 31 * 4
        else:
            if entry % 4 or entry in result:
                raise ValueError('Invalid RELR address')
            result.add(entry)
            where = entry + 4
    return result


class Image:
    def __init__(self, path):
        self.path = Path(path)
        self.raw = self.path.read_bytes()
        self.elf = ELFFile(BytesIO(self.raw))
        if self.elf.elfclass != 32 or self.elf['e_machine'] != 'EM_ARM' or not self.elf.little_endian:
            raise ValueError('ARM32 little endian required')
        self.sections = [s for s in self.elf.iter_sections() if s['sh_flags'] & 2 and s['sh_size']]
        self.functions, self.objects, self.mapping = {}, {}, {}
        for symbol in self.elf.get_section_by_name('.symtab').iter_symbols():
            address, size = symbol['st_value'], symbol['st_size']
            if not isinstance(symbol['st_shndx'], int):
                continue
            if symbol['st_info']['type'] == 'STT_FUNC' and size:
                self.functions[name_key(symbol.name)] = dict(name=symbol.name, address=address & ~1, size=size, thumb=bool(address & 1))
            elif symbol['st_info']['type'] == 'STT_OBJECT' and size:
                self.objects.setdefault(address, []).append((name_key(symbol.name), size))
            elif symbol.name in ('$a', '$t', '$d') or symbol.name.startswith(('$a.', '$t.', '$d.')):
                self.mapping[address] = symbol.name[1]
        self.maps = sorted(self.mapping)
        self.aliases = defaultdict(list)
        for name, row in self.functions.items():
            self.aliases[row['address']].append((name, row['size']))
        self.starts, self.object_starts = sorted(self.aliases), sorted(self.objects)
        self.got = {}
        self.target_cache = {}
        self.relative = relr_offsets(self.elf.get_section_by_name('.relr.dyn').data())
        rel = self.elf.get_section_by_name('.rel.dyn')
        symbols = self.elf.get_section_by_name('.dynsym')
        for offset, index, kind in packed_rel(rel.data()):
            if kind in (21, 22) and index:
                self.got[offset] = ('GOT_symbol', kind, symbols.get_symbol(index).name)
        self.plt = {}
        rel = self.elf.get_section_by_name('.rel.plt')
        if rel:
            symbols = self.elf.get_section(rel['sh_link'])
            got = {r['r_offset']: symbols.get_symbol(r['r_info_sym']).name for r in rel.iter_relocations()}
            section = self.elf.get_section_by_name('.plt')
            raw, base = section.data(), section['sh_addr']
            for offset in range(0, len(raw) - 11, 4):
                a, b, d = struct.unpack_from('<III', raw, offset)
                if a & 0xfffff000 != 0xe28fc000 or b & 0xfffff000 != 0xe28cc000 or d & 0xfffff000 != 0xe5bcf000:
                    continue
                def imm(word):
                    value, rotate = word & 255, ((word >> 8) & 15) * 2
                    return ((value >> rotate) | (value << (32 - rotate))) & 0xffffffff if rotate else value
                entry = base + offset
                target = entry + 8 + imm(a) + imm(b) + (d & 4095)
                if target in got:
                    self.plt[entry] = got[target]

    def read(self, address, size):
        for section in self.sections:
            if section['sh_type'] != 'SHT_NOBITS' and section['sh_addr'] <= address and address + size <= section['sh_addr'] + section['sh_size']:
                offset = section['sh_offset'] + address - section['sh_addr']
                return self.raw[offset:offset + size]
        return None

    def target(self, address, function=None, depth=0):
        address &= 0xffffffff
        if depth > 4:
            return ('unresolved', hex(address))
        if address in self.got:
            return self.got[address]
        section = next((s for s in self.sections if s['sh_addr'] <= address < s['sh_addr'] + s['sh_size']), None)
        if section is not None and section.name == '.plt' and address == section['sh_addr']:
            return ('PLT_resolver_exact_stub', digest(self.read(address, 32)))
        if section is not None and section.name in ('.got', '.got.plt') and address in self.relative:
            value = struct.unpack('<I', self.read(address, 4))[0]
            return ('GOT_relative', self.target(value, depth=depth + 1))
        code = address & ~1
        if function and function['address'] <= code < function['address'] + function['size']:
            return ('self', code - function['address'])
        if code in self.plt:
            return ('PLT', self.plt[code])
        index = bisect.bisect_right(self.starts, code) - 1
        if index >= 0:
            start = self.starts[index]
            names = tuple(sorted(name for name, size in self.aliases[start] if code < start + size))
            if names:
                return ('function', names, code - start)
        # String merging can add aliases to an existing unchanged string.
        if section is not None and section.name == '.rodata':
            offset = section['sh_offset'] + address - section['sh_addr']
            value = self.raw[offset:offset + min(4096, section['sh_addr'] + section['sh_size'] - address)].split(b'\0', 1)[0]
            if len(value) >= 1 and all(byte in (9, 10, 13) or 32 <= byte < 127 for byte in value) and self.raw[offset + len(value):offset + len(value) + 1] == b'\0':
                return ('string', value.decode('ascii'))
        index = bisect.bisect_right(self.object_starts, address) - 1
        if index >= 0:
            start = self.object_starts[index]
            names = tuple(sorted(name for name, size in self.objects[start] if address < start + size))
            if names:
                return ('object', names, address - start)
        # Compare complete remaining read-only tails, never a sampled prefix.
        if section is not None and section.name == '.rodata':
            size = section['sh_addr'] + section['sh_size'] - address
            return ('read_only_tail', size, digest(self.read(address, size)))
        if section is not None and section.name == '.data.rel.ro' and address % 4 == 0:
            key = (address, depth)
            if key not in self.target_cache:
                words = []
                for slot in range(address, section['sh_addr'] + section['sh_size'], 4):
                    value = struct.unpack('<I', self.read(slot, 4))[0]
                    if slot in self.got:
                        words.append(self.got[slot])
                    elif slot in self.relative:
                        words.append(self.target(value, depth=depth + 1))
                    else:
                        words.append(('raw', value))
                self.target_cache[key] = ('relocated_read_only_tail', len(words), digest(json.dumps(words).encode()))
            return self.target_cache[key]
        return ('unresolved', hex(address))

    def decode(self, function):
        start, end = function['address'], function['address'] + function['size']
        marks = [start] + [p for p in self.maps if start < p < end] + [end]
        rows, instructions, mode = [], [], 't' if function['thumb'] else 'a'
        index = bisect.bisect_right(self.maps, start) - 1
        if index >= 0:
            mode = self.mapping[self.maps[index]]
        for low, high in zip(marks, marks[1:]):
            mode = self.mapping.get(low, mode)
            raw = self.read(low, high - low)
            if raw is None:
                raise ValueError('Function outside file-backed allocated sections')
            if mode == 'd':
                rows.append(dict(address=low, kind='data_span', raw=raw))
                continue
            decoder = cs.Cs(cs.CS_ARCH_ARM, (cs.CS_MODE_THUMB if mode == 't' else cs.CS_MODE_ARM) | cs.CS_MODE_LITTLE_ENDIAN)
            decoder.detail = True
            consumed = 0
            for ins in decoder.disasm(raw, low):
                rows.append(dict(address=ins.address, kind='instruction', raw=bytes(ins.bytes), instruction=ins))
                instructions.append(ins)
                consumed += ins.size
            if consumed != len(raw):
                rows.append(dict(address=low + consumed, kind='undecoded', raw=raw[consumed:]))
        # Assembly can use unaligned words; C++ pools can start with padding.
        # Partition using actual word-load addresses, never assumed alignment.
        slots = set()
        for ins in instructions:
            ops = ins.operands
            if ins.mnemonic.split('.')[0] == 'ldr' and len(ops) == 2 and ops[1].type == ARM_OP_MEM and ops[1].mem.base == ARM_REG_PC and not ops[1].mem.index:
                pc = ins.address + (4 if function['thumb'] else 8)
                slots.add((pc & ~3 if function['thumb'] else pc) + ops[1].mem.disp)
        partitioned = []
        for row in rows:
            if row['kind'] != 'data_span':
                partitioned.append(row)
                continue
            low, high = row['address'], row['address'] + len(row['raw'])
            cuts = sorted({low, high} | {p for slot in slots if low <= slot and slot + 4 <= high for p in (slot, slot + 4)})
            for begin, stop in zip(cuts, cuts[1:]):
                for address in range(begin, stop, 4):
                    size = min(4, stop - address)
                    partitioned.append(dict(address=address, kind='data', raw=row['raw'][address-low:address-low+size]))
        rows = partitioned
        # Bind changed literal words to the actual PC addition that consumes them.
        registers, literals = {}, defaultdict(list)
        instruction_addresses = [ins.address for ins in instructions]
        for index, ins in enumerate(instructions):
            operands = ins.operands
            old = registers.copy()
            for reg in ins.regs_access()[1]:
                registers.pop(reg, None)
            pc = ins.address + (4 if function['thumb'] else 8)
            if ins.mnemonic.split('.')[0] == 'ldr' and len(operands) == 2 and operands[0].type == ARM_OP_REG and operands[1].type == ARM_OP_MEM and operands[1].mem.base == ARM_REG_PC and not operands[1].mem.index:
                location = (pc & ~3 if function['thumb'] else pc) + operands[1].mem.disp
                raw = self.read(location, 4)
                if raw is not None and start <= location < end:
                    registers[operands[0].reg] = (location, struct.unpack('<I', raw)[0])
            elif ins.mnemonic.split('.')[0] == 'mov' and len(operands) == 2 and all(o.type == ARM_OP_REG for o in operands) and operands[1].reg in old:
                registers[operands[0].reg] = old[operands[1].reg]
            elif ins.mnemonic.split('.')[0] == 'add' and all(o.type == ARM_OP_REG for o in operands) and any(o.reg == ARM_REG_PC for o in operands[1:]):
                source = operands[0].reg if len(operands) == 2 else next(o.reg for o in operands[1:] if o.reg != ARM_REG_PC)
                if source in old:
                    location, value = old[source]
                    literals[location].append(self.target(value + pc, function))
            if ins.group(cs.CS_GRP_JUMP) or ins.group(cs.CS_GRP_CALL):
                skips_only_pool = False
                if ins.mnemonic in ('b', 'b.w') and len(operands) == 1 and operands[0].type == ARM_OP_IMM:
                    destination = bisect.bisect_left(instruction_addresses, operands[0].imm)
                    skips_only_pool = (index < destination < len(instructions) and instructions[destination].address == operands[0].imm
                                       and all(item.mnemonic == 'nop' for item in instructions[index+1:destination]))
                if not skips_only_pool:
                    registers.clear()
        return rows, literals


def compare_function(a, b, left, right):
    old, new = a.read(left['address'], left['size']), b.read(right['address'], right['size'])
    if old == new:
        return dict(classification='identical_bytes')
    if left['size'] != right['size'] or left['thumb'] != right['thumb']:
        return dict(classification='changed_shape', before_size=left['size'], after_size=right['size'])
    aa, al = a.decode(left)
    bb, bl = b.decode(right)
    if left['name'].startswith('__ThumbV7PILongThunk_'):
        def thunk(image, rows, function):
            if len(rows) != 4 or any(row['kind'] != 'instruction' for row in rows):
                return None
            ins = [row['instruction'] for row in rows]
            if [i.mnemonic for i in ins] != ['movw', 'movt', 'add', 'bx']:
                return None
            register = ins[0].operands[0].reg
            if (ins[1].operands[0].reg != register or [o.reg for o in ins[2].operands] != [register, ARM_REG_PC]
                    or len(ins[3].operands) != 1 or ins[3].operands[0].reg != register):
                return None
            address = ins[0].operands[1].imm + (ins[1].operands[1].imm << 16) + ins[2].address + 4
            target = image.target(address)
            expected = function['name'][len('__ThumbV7PILongThunk_'):]
            return target if target[0] == 'function' and expected in target[1] and target[2] == 0 else None
        ta, tb = thunk(a, aa, left), thunk(b, bb, right)
        if ta and ta == tb:
            return dict(classification='reference_changes_only', explained={'verified_PC_relative_long_thunk': 1}, unresolved=[])
    unresolved, explained = [], Counter()
    if len(aa) != len(bb):
        return dict(classification='changed_decode_layout', before_rows=len(aa), after_rows=len(bb))
    for x, y in zip(aa, bb):
        offset = x['address'] - left['address']
        if offset != y['address'] - right['address'] or x['kind'] != y['kind'] or len(x['raw']) != len(y['raw']):
            unresolved.append(dict(offset=offset, reason='decode row layout differs'))
            continue
        if x['raw'] == y['raw']:
            continue
        reason = None
        if x['kind'] == 'data' and len(x['raw']) == 4:
            lx, ly = al.get(x['address']), bl.get(y['address'])
            if lx and ly and lx == ly and known(lx):
                reason = 'PC_relative_literal_to_same_named_target'
            else:
                tx = a.target(struct.unpack('<I', x['raw'])[0], left)
                ty = b.target(struct.unpack('<I', y['raw'])[0], right)
                if tx == ty and known(tx):
                    reason = 'absolute_literal_to_same_named_target'
        elif x['kind'] == 'instruction':
            ix, iy = x['instruction'], y['instruction']
            if ix.mnemonic == iy.mnemonic and (ix.group(cs.CS_GRP_JUMP) or ix.group(cs.CS_GRP_CALL)) and len(ix.operands) == len(iy.operands) == 1 and ix.operands[0].type == iy.operands[0].type == ARM_OP_IMM:
                tx, ty = a.target(ix.operands[0].imm, left), b.target(iy.operands[0].imm, right)
                if tx == ty and known(tx):
                    reason = 'direct_branch_to_same_named_target'
        if reason:
            explained[reason] += 1
        elif len(unresolved) < 12:
            unresolved.append(dict(offset=offset, kind=x['kind'], before=x['raw'].hex(), after=y['raw'].hex(),
                                   before_asm=x['instruction'].mnemonic + ' ' + x['instruction'].op_str if x['kind'] == 'instruction' else None,
                                   after_asm=y['instruction'].mnemonic + ' ' + y['instruction'].op_str if y['kind'] == 'instruction' else None,
                                   before_literal_targets=al.get(x['address']), after_literal_targets=bl.get(y['address'])))
    return dict(classification='unresolved_changes' if unresolved else 'reference_changes_only', explained=dict(explained), unresolved=unresolved)


def audit(off, on):
    a, b = Image(off), Image(on)
    rows, cache = {}, {}
    for name in sorted(a.functions.keys() | b.functions.keys()):
        if name not in a.functions or name not in b.functions:
            rows[name] = dict(classification='missing_function')
            continue
        left, right = a.functions[name], b.functions[name]
        key = (left['address'], left['size'], right['address'], right['size'])
        if key not in cache:
            cache[key] = compare_function(a, b, left, right)
        rows[name] = cache[key]
    return dict(classification='bounded_final_function_change_census', off_sha256=digest(a.raw), on_sha256=digest(b.raw),
                counts=dict(Counter(row['classification'] for row in rows.values())), functions=rows,
                full_code_equivalence_proven=False, allocated_data_review_complete=False, installed=False, savings_proven=False,
                decoder=dict(capstone_version=cs.__version__, analyzer_sha256=digest(Path(__file__).read_bytes())))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--off', type=Path, required=True)
    parser.add_argument('--on', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.off, args.on)
    with args.output.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps(result['counts']))
