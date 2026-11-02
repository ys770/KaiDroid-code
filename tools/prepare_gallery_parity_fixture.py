"""Generate a deterministic, nonprivate Gallery test image; no device operations."""
import argparse
import binascii
import hashlib
import json
from pathlib import Path
import struct
import zlib


def image():
    width, height = 640, 480
    colors = [(224,48,48),(48,192,72),(48,104,224),(240,208,48)]
    rows = bytearray()
    for y in range(height):
        rows.append(0)
        for x in range(width):
            rgb = (224,224,224) if ((x//32 + y//32) % 2) else (64,64,64)
            # Distinct corners and an unequal cross make rotation/cropping visible.
            if x < 80 and y < 80: rgb = colors[0]
            elif x >= width-80 and y < 80: rgb = colors[1]
            elif x < 80 and y >= height-80: rgb = colors[2]
            elif x >= width-80 and y >= height-80: rgb = colors[3]
            elif abs(x-240) < 4 or abs(y-200) < 4: rgb = (255,255,255)
            elif abs((x-320)**2+(y-240)**2-120**2) < 700: rgb = (0,0,0)
            rows.extend(rgb)
    def chunk(kind, data):
        return struct.pack('>I',len(data))+kind+data+struct.pack('>I',binascii.crc32(kind+data)&0xffffffff)
    png = b'\x89PNG\r\n\x1a\n'
    png += chunk(b'IHDR',struct.pack('>IIBBBBB',width,height,8,2,0,0,0))
    png += chunk(b'IDAT',zlib.compress(rows,9)) + chunk(b'IEND',b'')
    return png, bytes(rows), width, height


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();data,rows,width,height=image()
    a.output.mkdir(parents=True,exist_ok=False)
    path=a.output/'KaiDroid-Gallery-Parity01.png';path.write_bytes(data)
    report=dict(file=path.name,width=width,height=height,mime_type='image/png',
        sha256=hashlib.sha256(data).hexdigest(),filtered_rgb_rows_sha256=hashlib.sha256(rows).hexdigest(),
        private_content=False,device_operations=False,
        orientation='Landscape; red/green top corners, blue/yellow bottom corners',
        scope='Controlled Gallery viewer/thumbnail/menu reference; no photo quality or camera claim')
    (a.output/'fixture.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__=='__main__':main()
