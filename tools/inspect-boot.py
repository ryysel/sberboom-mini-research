"""Offline research helper; see tools/README.md for limitations."""
import os
from pathlib import Path
import struct,hashlib,json,collections,math,re
ROOT = Path(os.environ.get('SBERBOOM_WORKDIR', str(Path(__file__).resolve().parent.parent / 'work'))).resolve()
OUT=ROOT/'boot-analysis'
OUT.mkdir(exist_ok=True)
b=(ROOT/'boom_original.bin').read_bytes()
report={}
markers=(b'@AML',b'AMLC',b'LZ4C',b'AMLIFPG',b'RABBIT',b'RABBITH',b'U-Boot',b'\x01\x00\x64\xaa')
report['boot_area_markers']={repr(m):[hex(x.start()) for x in re.finditer(re.escape(m),b[:0x1100000])] for m in markers}
for start,length,name in ((0,0x100000,'bl2-area-copy0'),(0x800000,0x200000,'tpl-area-copy0')):
    data=b[start:start+length]
    (OUT/(name+'.bin')).write_bytes(data)
    report[name]={'offset':hex(start),'size':length,'sha256':hashlib.sha256(data).hexdigest()}
    pages=[]
    for offset in range(0,length,0x1000):
        page=data[offset:offset+0x1000]
        count=collections.Counter(page)
        entropy=-sum((n/len(page))*math.log2(n/len(page)) for n in count.values())
        pages.append({'offset':hex(start+offset),'entropy':round(entropy,5),'ff':count[255],'zero':count[0]})
    (OUT/(name+'-pages.json')).write_text(json.dumps(pages,indent=2))
for offset in (0x10000,0x50000,0x90000,0xd0000):
    data=b[offset:offset+512]
    report[f'IFPG_{offset:x}']={'hex':data.hex(),'u32_le':[hex(x[0]) for x in struct.iter_unpack('<I',data[:128])]}
report['bl2_64KiB_copies_identical']=len({b[x:x+0x10000] for x in (0,0x40000,0x80000,0xc0000,0x100000,0x140000,0x180000,0x1c0000)})==1

# Decode DTB nodes without running device code.
dt=(ROOT/'unpacked/_images_radio1_a_mp_data.bin').read_bytes()
u32=lambda o:struct.unpack_from('>I',dt,o)[0]
ps,ss=u32(8),u32(12)
strings=dt[ss:ss+u32(32)]
stack=[];parts=[]
while True:
    tok=u32(ps);ps+=4
    if tok==1:
        end=dt.index(0,ps);stack.append(dt[ps:end].decode());ps=(end+4)&~3
    elif tok==2:stack.pop()
    elif tok==3:
        size,no=u32(ps),u32(ps+4);ps+=8
        key=strings[no:strings.index(0,no)].decode()
        val=dt[ps:ps+size];ps=(ps+size+3)&~3
        path='/'.join(stack)+'/'+key
        if 'partition' in path or key in ('bootargs','stdout-path'):
            if key in ('offset','size') and len(val) in (4,8):
                value=hex(int.from_bytes(val,'big'))
            else:
                value=val.rstrip(b'\0').decode('ascii').replace('\0','\\0') if val and any(val) and all(x==0 or 32<=x<127 for x in val) else val.hex()
            parts.append(f'{path}: {value}')
    elif tok==4:pass
    elif tok==9:break
    else:raise ValueError(tok)
(OUT/'dtb-partitions.txt').write_text('\n'.join(parts))
(OUT/'container-report.json').write_text(json.dumps(report,indent=2))
print('Markers:',report['boot_area_markers'])
print('Eight 64KiB BL2 copies identical:',report['bl2_64KiB_copies_identical'])
print('\n'.join(parts))
print('IFPG first 128 bytes:',b[0x10000:0x10080].hex())
