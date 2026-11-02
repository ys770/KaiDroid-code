"""Replace equal-width top-level AXML/ARSC strings; preserve indexes and offsets."""
import struct
from remap_tcl_app_resources import chunks


def rewrite_pool(data,mapping,container_kind):
    kind,head,size=struct.unpack_from('<HHI',data)
    if kind!=container_kind or size!=len(data):raise ValueError('Unexpected container kind or extent')
    result=bytearray(data);changes=[];pools=0
    for off,typ,hs,length in chunks(data,head,size):
        if typ!=1:continue
        pools+=1
        if hs!=28:raise ValueError('Unsupported string pool header')
        count,styles,flags,start,style_start=struct.unpack_from('<IIIII',data,off+8)
        if start<hs+4*(count+styles) or start>=length:raise ValueError('Invalid string data offset')
        limit=off+(style_start or length)
        def read_length(pos,utf8):
            width=1 if utf8 else 2;mark=0x80 if utf8 else 0x8000
            if pos+width>limit:raise ValueError('Truncated length')
            value=int.from_bytes(data[pos:pos+width],'little');pos+=width
            if value&mark:
                if pos+width>limit:raise ValueError('Truncated long length')
                value=((value&(mark-1))<<(8 if utf8 else 16))|int.from_bytes(data[pos:pos+width],'little');pos+=width
            return value,pos
        for i in range(count):
            pos=off+start+struct.unpack_from('<I',data,off+hs+4*i)[0]
            units,pos=read_length(pos,bool(flags&0x100))
            if flags&0x100:
                size_bytes,pos=read_length(pos,True);encoding='utf-8';null=1
            else:size_bytes=units*2;encoding='utf-16-le';null=2
            if pos+size_bytes+null>limit or any(data[pos+size_bytes:pos+size_bytes+null]):raise ValueError('Invalid string extent')
            text=data[pos:pos+size_bytes].decode(encoding)
            if len(text.encode('utf-16-le'))//2!=units:raise ValueError('String length mismatch')
            if text not in mapping:continue
            new=mapping[text];encoded=new.encode(encoding)
            if len(encoded)!=size_bytes or len(new.encode('utf-16-le'))//2!=units:raise ValueError('Replacement must retain encoded width')
            result[pos:pos+size_bytes]=encoded
            changes.append(dict(index=i,before=text,after=new,offset=pos,bytes=size_bytes))
        if changes and flags&1:struct.pack_into('<I',result,off+16,flags&~1)
    if pools!=1:raise ValueError('Expected one top-level string pool')
    return bytes(result),changes


def rewrite_manifest(data,mapping):
    return rewrite_pool(data,mapping,3)


def rewrite_resource_strings(data,mapping):
    return rewrite_pool(data,mapping,2)
