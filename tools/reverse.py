"""Offline research helper; see tools/README.md for limitations."""
import os
from pathlib import Path
import sys, json, urllib.request, hashlib, zipfile, re
import struct, bisect
ROOT = Path(os.environ.get('SBERBOOM_WORKDIR', str(Path(__file__).resolve().parent.parent / 'work'))).resolve()
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

p=ROOT/'unpacked/rootfs-files/vendor/staros/box'
f=p.open('rb');elf=ELFFile(f)
out=ROOT/'reverse';out.mkdir(exist_ok=True)
print('ELF',elf.header)
sections=[];symbols=[]
for section in elf.iter_sections():
    sections.append(f'{section.name}\t{section["sh_addr"]:#x}\t{section["sh_offset"]:#x}\t{section["sh_size"]:#x}')
    if section['sh_type'] in ('SHT_SYMTAB','SHT_DYNSYM'):
        for s in section.iter_symbols():
            symbols.append((s['st_value'],s['st_size'],s.name,s['st_info']['type']))
(out/'sections.txt').write_text('\n'.join(sections))
(out/'symbols.tsv').write_text('\n'.join(f'{a:#x}\t{n}\t{t}\t{name}' for a,n,name,t in symbols))
interesting=[s for s in symbols if re.search('Rabbit|AdbService|adb|RS256',s[2],re.I)]
print('Symbols',len(symbols),'interesting',len(interesting))
print('\n'.join(f'{a:#x}\t{n}\t{t}\t{name}' for a,n,name,t in interesting[:100]))
for seg in elf.iter_segments():
    if seg['p_type']=='PT_LOAD':print('LOAD',hex(seg['p_vaddr']),hex(seg['p_offset']),hex(seg['p_filesz']),seg['p_flags'])

raw=p.read_bytes()
def addr_to_offset(addr):
    for seg in elf.iter_segments():
        if seg['p_type']=='PT_LOAD' and seg['p_vaddr']<=addr<seg['p_vaddr']+seg['p_filesz']:
            return addr-seg['p_vaddr']+seg['p_offset']
    return None
def string_at(addr):
    offset=addr_to_offset(addr)
    if offset is None:return None
    end=raw.find(b'\0',offset,offset+500)
    if end<0:return None
    s=raw[offset:end]
    return s.decode('ascii') if len(s)>=3 and all(32<=c<127 for c in s) else None
exidx=elf.get_section_by_name('.ARM.exidx')
starts=[]
for i in range(0,exidx['sh_size'],8):
    val=struct.unpack_from('<I',exidx.data(),i)[0]&0x7fffffff
    if val&0x40000000:val-=0x80000000
    starts.append(exidx['sh_addr']+i+val)
print('Unwind function boundaries',len(starts))
targets={}
textsec=elf.get_section_by_name('.text')
code=textsec.data()
constants=[]
for i in range(0,len(code)-4,4):
    w=struct.unpack_from('<I',code,i)[0]
    if w&0x0ff00000 != 0x03000000:continue
    reg=(w>>12)&15
    low=((w>>4)&0xf000)|(w&0xfff)
    for j in range(i+4,min(i+36,len(code)-3),4):
        high=struct.unpack_from('<I',code,j)[0]
        if high&0x0ff00000==0x03400000 and (high>>12)&15==reg:
            value=low|((((high>>4)&0xf000)|(high&0xfff))<<16)
            constants.append((textsec['sh_addr']+i,value))
            break
print('MOVW/MOVT constants',len(constants))
scan=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
scan.skipdata=True
pc_refs=[];loaded={};calls=[]
for a,size,mnem,ops in scan.disasm_lite(code,textsec['sh_addr']):
    if mnem in ('bl','b') and ops.startswith('#'):
        try:
            destination=int(ops[1:],0)
            if destination in (0x12d0c8,0x12d670,0x12c070,0x127d54):calls.append((a,destination))
        except ValueError:pass
    if mnem=='ldr':
        match=re.fullmatch(r'(r\d+), \[pc(?:, #(-?0x[0-9a-f]+|-?\d+))?\]',ops)
        if match:
            loc=a+8+(int(match[2],0) if match[2] else 0)
            off=addr_to_offset(loc)
            if off is not None and off+4<=len(raw):
                loaded[match[1]]=(a,struct.unpack_from('<I',raw,off)[0])
    elif mnem=='add':
        match=re.fullmatch(r'(r\d+), pc, (r\d+)',ops)
        if not match:match=re.fullmatch(r'(r\d+), (r\d+), pc',ops)
        if match and match[2] in loaded:
            at,value=loaded[match[2]]
            if a-at<=80:
                pc_refs.append((a,(a+8+value)&0xffffffff))
print('PC-relative references',len(pc_refs))
pc_ref_map=dict(pc_refs)
for a,destination in calls:
    idx=bisect.bisect_right(starts,a)-1
    targets[starts[idx]]=starts[idx+1]
    print('Caller',hex(a),'->',hex(destination),'function',hex(starts[idx]))
for address in (0x12c070,0x4d46b0,0x4d5c04,0x127d54,0x12b310,0x12b2f4,0x12c174,0x4d413c,0x4d593c,0x127ae0,0x12b660,0x12bf84,0x12b460,0x4d58b8,0x4d6870,0x12b7a4):
    idx=bisect.bisect_right(starts,address)-1
    targets[starts[idx]]=starts[idx+1]
for needle in (b'staros::RabbitHole::parseJwtToken',b'RS256\0',b'serialNumber\0',b'sessionUUID\0',b'adb_root\0',b'rabbitHole\0',b'uuidLifetimeMs\0',b'TRY ENABLE ADB VIA COMMAND',b'UnauthorizedAdbAccessAttempt'):
    occurrences=[m.start() for m in re.finditer(re.escape(needle),raw)]
    if not occurrences:continue
    addresses=[]
    for offset in occurrences:
        if b'parseJwtToken' in needle:offset=raw.rfind(b'\0',0,offset)+1
        addresses.append(offset+0x10000)
    refs=[]
    reference_addresses=[]
    for addr in addresses:
        reference_addresses.extend(m.start()+0x10000 for m in re.finditer(re.escape(struct.pack('<I',addr)),raw))
        reference_addresses.extend(a for a,v in constants if v==addr)
        reference_addresses.extend(a for a,v in pc_refs if v==addr)
    for va in reference_addresses:
        idx=bisect.bisect_right(starts,va)-1
        if idx>=0 and starts[idx]<=va<starts[idx+1] and va<0x5bd6b4:
            refs.append((va,starts[idx],starts[idx+1]))
            targets[starts[idx]]=starts[idx+1]
    print('String',needle,'addresses',[hex(a) for a in addresses],'references',[(hex(a),hex(s),hex(e)) for a,s,e in refs])

rel=elf.get_section_by_name('.rel.plt'); dynsym=elf.get_section(rel['sh_link'])
plt=elf.get_section_by_name('.plt')
plt_names={plt['sh_addr']+20+i*12:dynsym.get_symbol(r['r_info_sym']).name for i,r in enumerate(rel.iter_relocations())}
md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
md.detail=True
for start,end in targets.items():
    lines=[]
    off=addr_to_offset(start)
    for ins in md.disasm(raw[off:off+end-start],start):
        note=''
        if ins.mnemonic in ('bl','b','blx'):
            try:
                dest=int(ins.op_str.lstrip('#'),0)
                note=plt_names.get(dest,'')
            except ValueError:pass
        # Resolve PC-relative literal pool loads and show string values.
        if ins.mnemonic.startswith('ldr'):
            match=re.search(r'\[pc(?:, #(-?0x[0-9a-f]+|-?\d+))?\]',ins.op_str)
            if match:
                a=ins.address+8+(int(match[1],0) if match[1] else 0)
                o=addr_to_offset(a)
                if o is not None and o+4<=len(raw):
                    value=struct.unpack_from('<I',raw,o)[0]
                    note+=f' literal {value:#x}'
                    text=string_at(value)
                    if text:note+=' '+repr(text)
        if ins.address in pc_ref_map:
            text=string_at(pc_ref_map[ins.address])
            if text:note+=' PC-relative '+repr(text)
        lines.append(f'{ins.address:08x}: {ins.mnemonic:8} {ins.op_str:40} ; {note}')
    (out/f'function-{start:08x}.asm').write_text('\n'.join(lines))
print('Disassembled candidate functions',len(targets))
