"""Extract actual FindEntryByName into a standalone C++ regression harness.

String pools/container setup and checked entry access are small stand-ins;
this does not replace Android libandroidfw/idmap integration testing.
"""
import argparse
from pathlib import Path


def extract(source):
    start = source.index('uint32_t LoadedPackage::FindEntryByName(')
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


PREFIX = r'''
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
static uint32_t dtohl(uint32_t v) { return v; }
static uint16_t dtohs(uint16_t v) { return v; }
static uint32_t make_resid(uint32_t p, uint32_t t, uint32_t e) { return p<<24 | t<<16 | e; }
struct Header { uint16_t type, headerSize; uint32_t size; };
struct ResTable_type {
  Header header; uint8_t id, flags; uint16_t reserved;
  uint32_t entryCount, entriesStart;
  static constexpr uint32_t NO_ENTRY=0xffffffffu;
  static constexpr uint8_t FLAG_SPARSE=1;
};
struct ResTable_sparseTypeEntry { uint16_t idx, offset; };
struct ResTable_entry { uint16_t size, flags; struct { uint32_t index; } key; };
struct Pool {
  std::vector<std::u16string> values;
  long indexOfString(const char16_t* p, size_t n) const {
    for (size_t i=0;i<values.size();++i) if(values[i]==std::u16string(p,n)) return i;
    return -1;
  }
};
struct TypeSpec { const ResTable_type** types; size_t type_count; };
struct LoadedPackage {
  Pool type_string_pool_, key_string_pool_;
  std::vector<std::unique_ptr<TypeSpec>> type_specs_{256};
  uint32_t type_id_offset_=0;
  static const ResTable_entry* GetEntryFromOffset(const ResTable_type* type, uint32_t offset) {
    if (offset%4 || type->entriesStart>type->header.size ||
        offset>type->header.size-type->entriesStart ||
        type->header.size-type->entriesStart-offset<sizeof(ResTable_entry)) return nullptr;
    auto* entry=reinterpret_cast<const ResTable_entry*>(reinterpret_cast<const uint8_t*>(type)+type->entriesStart+offset);
    return entry->size>=sizeof(ResTable_entry) ? entry : nullptr;
  }
  uint32_t FindEntryByName(const std::u16string&, const std::u16string&) const;
};
'''
SUFFIX = r'''
struct Fixture {
  LoadedPackage pkg;
  std::vector<uint32_t> words=std::vector<uint32_t>(32);
  const ResTable_type* configs[1];
  ResTable_type* type() { return reinterpret_cast<ResTable_type*>(words.data()); }
  Fixture(bool sparse) {
    pkg.type_string_pool_.values={u"drawable"};
    pkg.key_string_pool_.values={u"first",u"second"};
    auto* t=type(); t->header={0x201,20,128}; t->id=1; t->flags=sparse?1:0;
    t->entryCount=2; t->entriesStart=28;
    if(sparse) {
      auto* slots=reinterpret_cast<ResTable_sparseTypeEntry*>(reinterpret_cast<uint8_t*>(t)+20);
      slots[0]={1,4}; slots[1]={4095,6};
    } else { words[5]=16; words[6]=24; }
    auto* first=reinterpret_cast<ResTable_entry*>(reinterpret_cast<uint8_t*>(t)+44);
    first->size=8; first->key.index=0;
    auto* second=reinterpret_cast<ResTable_entry*>(reinterpret_cast<uint8_t*>(t)+52);
    second->size=8; second->key.index=1;
    configs[0]=t; pkg.type_specs_[0]=std::unique_ptr<TypeSpec>(new TypeSpec{configs,1});
  }
};
int main(int argc,char**) {
  if(argc>1) { Fixture f(true); return f.pkg.FindEntryByName(u"drawable",u"first")==0x10001 ? 0:2; }
  int checks=0;
  auto expect=[&](uint32_t actual,uint32_t expected) { if(actual!=expected) {
    std::cerr<<"check "<<checks<<" actual="<<actual<<" expected="<<expected<<"\n"; std::abort(); } ++checks; };
  Fixture sparse(true), dense(false);
  expect(sparse.pkg.FindEntryByName(u"drawable",u"first"),0x10001);
  expect(sparse.pkg.FindEntryByName(u"drawable",u"second"),0x10fff);
  expect(dense.pkg.FindEntryByName(u"drawable",u"first"),0x10000);
  expect(dense.pkg.FindEntryByName(u"drawable",u"second"),0x10001);
  dense.words[5]=0xffffffffu;
  expect(dense.pkg.FindEntryByName(u"drawable",u"first"),0);
  expect(dense.pkg.FindEntryByName(u"drawable",u"second"),0x10001);
  sparse.pkg.type_id_offset_=3;
  expect(sparse.pkg.FindEntryByName(u"drawable",u"second"),0x40fff);
  expect(sparse.pkg.FindEntryByName(u"unknown",u"first"),0);
  expect(sparse.pkg.FindEntryByName(u"drawable",u"unknown"),0);
  sparse.words[5]=0xffff0001;
  expect(sparse.pkg.FindEntryByName(u"drawable",u"first"),0);
  expect(sparse.pkg.FindEntryByName(u"drawable",u"second"),0x40fff);
  sparse.type()->entriesStart=24;
  expect(sparse.pkg.FindEntryByName(u"drawable",u"second"),0);
  sparse.type()->entriesStart=129;
  expect(sparse.pkg.FindEntryByName(u"drawable",u"second"),0);
  dense.pkg.type_specs_[0].reset();
  expect(dense.pkg.FindEntryByName(u"drawable",u"second"),0);
  std::cout<<checks<<" actual-function assertions passed; Android integration untested\n";
}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    with a.output.open('x', encoding='utf-8') as output:
        output.write(PREFIX + extract(a.source.read_text()) + SUFFIX)


if __name__ == '__main__':
    main()
