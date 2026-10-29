"""Offline research helper; see tools/README.md for limitations."""
import os
from pathlib import Path
import re, hashlib, struct, json, gzip, datetime, math, collections
ROOT = Path(os.environ.get('SBERBOOM_WORKDIR', str(Path(__file__).resolve().parent.parent / 'work'))).resolve()
OUT=ROOT/'unpacked'
report=[]
pattern=re.compile(rb'[\x20-\x7e]{6,}')
terms=re.compile(r'rabbith|rabbit.?hole|linux_console|adb_root|firmware.?version|1\.[0-9]{2,3}\.[0-9]{1,4}|Linux version|jenkins|buildroot|jwt|uboot|debug.?console',re.I)
hits=[]
for base in ('rootfs-files','initramfs-files'):
    for p in (OUT/base).rglob('*'):
        if not p.is_file():continue
        data=p.read_bytes()
        found=[]
        for match in pattern.finditer(data):
            s=match.group().decode('ascii')
            if terms.search(s):
                # Limit output; retain offsets for further static inspection.
                found.append(f'0x{match.start():x}\t{s[:1600]}')
        if found:
            hits.append(str(p.relative_to(OUT))+'\n'+'\n'.join(found[:100]))
(OUT/'interesting-strings.txt').write_text('\n\n'.join(hits),encoding='utf-8')

# Validate extracted FIT payload hashes, not the RSA signatures.
boot=(OUT/'volume-0-boot.bin').read_bytes()
ss=struct.unpack_from('>I',boot,12)[0]
ps=struct.unpack_from('>I',boot,8)[0]
strings=boot[ss:ss+struct.unpack_from('>I',boot,32)[0]]
stack=[];props={}
while True:
    token=struct.unpack_from('>I',boot,ps)[0];ps+=4
    if token==1:
        end=boot.index(0,ps);stack.append(boot[ps:end].decode());ps=(end+4)&~3
    elif token==2:stack.pop()
    elif token==3:
        size,no=struct.unpack_from('>II',boot,ps);ps+=8
        end=strings.index(0,no);name=strings[no:end].decode()
        props['/'.join(stack)+'/'+name]=boot[ps:ps+size];ps=(ps+size+3)&~3
    elif token==4:pass
    elif token==9:break
    else:raise ValueError(token)
for k,v in props.items():
    if k.endswith('/data'):
        expected=props.get(k[:-5]+'/hash-1/value')
        report.append(f'FIT {k}: SHA256 matches: {hashlib.sha256(v).digest()==expected}')
report.append('FIT timestamp: '+datetime.datetime.fromtimestamp(struct.unpack('>I',props['/timestamp'])[0],datetime.timezone.utc).isoformat())

# Decode device tree strings relevant to UART and flash layout.
dtb=(OUT/'_images_radio1_a_mp_data.bin').read_bytes()
dt_strings=[m.group().decode('ascii') for m in pattern.finditer(dtb)]
(OUT/'dtb-strings.txt').write_text('\n'.join(dt_strings))

b=(ROOT/'boom_original.bin').read_bytes()
for off,n in [(0,0x100000),(0x100000,0x100000),(0x800000,0x200000),(0xa00000,0x200000),(0xc00000,0x200000),(0xe00000,0x200000)]:
    report.append(f'Boot area 0x{off:x} len 0x{n:x}: sha256 {hashlib.sha256(b[off:off+n]).hexdigest()}')
for off in (0,0x10000,0x800000,0x808000,0x840000):
    data=b[off:off+65536]; counts=collections.Counter(data)
    e=-sum((v/len(data))*math.log2(v/len(data)) for v in counts.values())
    report.append(f'Entropy 64 KiB at 0x{off:x}: {e:.5f}')
for marker in (b'AML', b'IFPG',b'RABBIT',b'RABBITH',b'U-Boot',b'FIP'):
    offsets=[];i=0
    while (i:=b.find(marker,i))>=0:
        offsets.append(hex(i));i+=len(marker)
    report.append(f'Marker {marker!r}: {offsets[:30]} count={len(offsets)}')

kernel=(OUT/'_images_kernel_data.bin').read_bytes()
# Linux ARM zImage normally embeds the compressed kernel; find valid gzip streams.
for m in re.finditer(b'\x1f\x8b\x08',kernel):
    try:
        import zlib
        d=zlib.decompress(kernel[m.start():],31)
    except zlib.error:continue
    (OUT/'kernel-decompressed.bin').write_bytes(d)
    versions=[x.group().decode('ascii') for x in pattern.finditer(d) if b'Linux version' in x.group()]
    report.append(f'Kernel gzip at {m.start():#x}, decompressed {len(d)} bytes, versions={versions}')
    break
(OUT/'validation.txt').write_text('\n'.join(report))
print('\n'.join(report))
print('Interesting string index:', OUT/'interesting-strings.txt')
