"""Offline research helper; see tools/README.md for limitations."""
import os
from pathlib import Path
import collections, struct, json, zlib, hashlib, urllib.request, sys, re
import zipfile, gzip

ROOT = Path(os.environ.get('SBERBOOM_WORKDIR', str(Path(__file__).resolve().parent.parent / 'work'))).resolve()
OUT = ROOT / 'unpacked'
OUT.mkdir(exist_ok=True)
b = (ROOT / 'boom_original.bin').read_bytes()
be32 = lambda x, o: struct.unpack_from('>I', x, o)[0]
be64 = lambda x, o: struct.unpack_from('>Q', x, o)[0]
rows = []
volumes = collections.defaultdict(dict)
names = {}
for p in range(0, len(b), 0x20000):
    if b[p:p+4] != b'UBI#':
        continue
    ec = b[p:p+64]
    vo, do = be32(ec, 16), be32(ec, 20)
    if vo + 64 > 0x20000 or not 64 <= do < 0x20000:
        continue
    v = b[p+vo:p+vo+64]
    if v[:4] != b'UBI!':
        continue
    vid, lnum, seq = be32(v,8), be32(v,12), be64(v,40)
    size, pad = be32(v,20), be32(v,28)
    ec_ok = (zlib.crc32(ec[:60]) ^ 0xffffffff) == be32(ec,60)
    vid_ok = (zlib.crc32(v[:60]) ^ 0xffffffff) == be32(v,60)
    payload = b[p+do:p+0x20000-pad]
    if v[5] == 2:
        payload = payload[:size]
    row = dict(physical=hex(p), volume_id=vid, lnum=lnum, seq=seq,
               volume_type=v[5], data_size=size, data_offset=do,
               ec_crc_ok=ec_ok, vid_crc_ok=vid_ok)
    rows.append(row)
    if not ec_ok or not vid_ok:
        continue
    old = volumes[vid].get(lnum)
    if old is None or seq > old[0]:
        volumes[vid][lnum] = (seq,payload)
    if vid == 0x7fffefff:
        for i in range(min(128, len(payload)//172)):
            rec = payload[i*172:(i+1)*172]
            n = struct.unpack_from('>H', rec,14)[0]
            if 0 < n <= 127:
                names[i] = dict(name=rec[16:16+n].decode('ascii','replace'),
                                reserved_pebs=be32(rec,0), alignment=be32(rec,4),
                                type=rec[12], crc_ok=(zlib.crc32(rec[:168]) ^ 0xffffffff) == be32(rec,168))
(OUT/'ubi-headers.json').write_text(json.dumps(rows,indent=2))
(OUT/'ubi-volume-table.json').write_text(json.dumps(names,indent=2))
print('UBI headers:',len(rows),'invalid CRC:',sum(not r['ec_crc_ok'] or not r['vid_crc_ok'] for r in rows))
print('Volume table:',names)
for vid, blocks in volumes.items():
    missing = sorted(set(range(max(blocks)+1))-blocks.keys())
    name = names.get(vid,{}).get('name',str(vid))
    safe = re.sub(r'[^A-Za-z0-9_.-]','_',name)
    if missing:
        print('Skipping non-contiguous volume',name,'unmapped LEBs',missing[:20], '(may be normal for UBIFS; not evidence of corruption)')
        continue
    data = b''.join(blocks[i][1] for i in range(max(blocks)+1))
    path = OUT / f'volume-{vid}-{safe}.bin'
    path.write_bytes(data)
    print('Volume',vid,name,'blocks',len(blocks),'bytes',len(data),'magic',data[:8].hex())

def fdt_parse(data):
    assert be32(data,0)==0xd00dfeed
    total, ps, ss = be32(data,4), be32(data,8), be32(data,12)
    strings = data[ss:ss+be32(data,32)]
    stack=[]
    result={}
    while ps < total:
        token = be32(data,ps); ps+=4
        if token==1:
            end=data.index(0,ps)
            stack.append(data[ps:end].decode('ascii','replace'))
            ps=(end+4)&~3
        elif token==2:
            stack.pop()
        elif token==3:
            size,no=be32(data,ps),be32(data,ps+4);ps+=8
            end=strings.index(0,no)
            key=strings[no:end].decode('ascii','replace')
            value=data[ps:ps+size];ps=(ps+size+3)&~3
            result['/'.join(stack)+'/'+key]=value
        elif token==4: pass
        elif token==9: break
        else: raise ValueError(('FDT token',token,ps))
    return result

for path in OUT.glob('volume-*.bin'):
    data=path.read_bytes()
    if data[:4]==b'\xd0\x0d\xfe\xed':
        props=fdt_parse(data)
        lines=[]
        for key,value in props.items():
            if key.endswith('/data'):
                name=re.sub(r'[^A-Za-z0-9_.-]','_',key)
                target=OUT/(name+'.bin')
                target.write_bytes(value)
                lines.append(f'{key}: {len(value)} bytes -> {target.name}')
            else:
                rendered=value.rstrip(b'\0').decode('ascii','backslashreplace').replace('\0','\\0') if all(c in (0,9,10,13) or 32<=c<127 for c in value) else value.hex()
                lines.append(f'{key}: {rendered}')
        (OUT/'fit-properties.txt').write_text('\n'.join(lines))
        print('Extracted FIT image properties/data')

ramdisk=OUT/'_images_ramdisk_data.bin'
if ramdisk.exists():
    cpio=gzip.decompress(ramdisk.read_bytes())
    (OUT/'initramfs.cpio').write_bytes(cpio)
    target=OUT/'initramfs-files'
    target.mkdir(exist_ok=True)
    pos=0; listing=[]
    while cpio[pos:pos+6] in (b'070701',b'070702'):
        fields=[int(cpio[pos+6+i*8:pos+14+i*8],16) for i in range(13)]
        mode,size,namesz=fields[1],fields[6],fields[11]
        name=cpio[pos+110:pos+110+namesz-1].decode('utf-8','replace')
        pos=(pos+110+namesz+3)&~3
        content=cpio[pos:pos+size]
        pos=(pos+size+3)&~3
        if name=='TRAILER!!!': break
        listing.append(f'{mode:o}\t{size}\t{name}')
        parts=name.strip('/').split('/')
        if mode & 0xf000 != 0x8000:continue
        if any(p in ('.','..') or ':' in p or '\\' in p for p in parts):raise ValueError(name)
        dest=target.joinpath(*parts)
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_bytes(content)
    (OUT/'initramfs-file-list.txt').write_text('\n'.join(listing))
    print('Initramfs entries',len(listing))

from PySquashfsImage import SquashFsImage
for path in OUT.glob('volume-*.bin'):
    data=path.read_bytes()
    if data[:4] != b'hsqs':continue
    print('SquashFS compression',struct.unpack_from('<H',data,20)[0], 'bytes_used',struct.unpack_from('<Q',data,40)[0])
    target=OUT/'rootfs-files'
    target.mkdir(exist_ok=True)
    listing=[]
    with SquashFsImage.from_bytes(data) as image:
        for item in image:
            listing.append(item.path)
            if not item.is_file:continue
            # No links, device nodes or firmware programs are executed/created.
            parts=item.path.strip('/').split('/')
            if any(p in ('.','..') or ':' in p or '\\' in p for p in parts):
                raise ValueError('Unsafe path: '+item.path)
            dest=target.joinpath(*parts)
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes(item.read_bytes())
    (OUT/'rootfs-file-list.txt').write_text('\n'.join(listing))
    print('Rootfs entries',len(listing))
