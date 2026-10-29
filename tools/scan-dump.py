"""Read-only initial scan. Generated strings can contain secrets: keep work/ private."""
from pathlib import Path
import os,re,json,hashlib
root=Path(os.environ.get('SBERBOOM_WORKDIR',str(Path(__file__).resolve().parent.parent/'work'))).resolve()
b=(root/'boom_original.bin').read_bytes()
out=root/'scan'
out.mkdir(parents=True,exist_ok=True)
with (out/'strings-ascii.txt').open('w',encoding='utf-8') as f:
    for m in re.finditer(rb'[\x20-\x7e]{6,}',b):
        f.write(f'0x{m.start():08x}\t{m.group().decode("ascii")}\n')
signatures={'TF-A FIP':'010064aa','uImage':'27051956','FDT/FIT':'d00dfeed',
            'SquashFS':'68737173','UBI EC':'55424923','UBI VID':'55424921',
            'UBIFS':'31181006','gzip':'1f8b08','xz':'fd377a585a00',
            'LZ4 frame':'04224d18','ELF':'7f454c46','@AML':'40414d4c',
            'AMLC':'414d4c43','LZ4C':'4c5a3443','AMLIFPG':'414d4c49465047'}
result={name:[hex(m.start()) for m in re.finditer(re.escape(bytes.fromhex(h)),b)] for name,h in signatures.items()}
(out/'signatures.json').write_text(json.dumps(result,indent=2))
print('Input bytes:',len(b),'SHA256:',hashlib.sha256(b).hexdigest())
print({name:len(positions) for name,positions in result.items()})
