"""Offline research helper; see tools/README.md for limitations."""
import os
from pathlib import Path
import hashlib,struct,json
ROOT = Path(os.environ.get('SBERBOOM_WORKDIR', str(Path(__file__).resolve().parent.parent / 'work'))).resolve()
root=ROOT/'unpacked'
b=(root/'volume-1-system.bin').read_bytes()
o=22212608
assert b[o:o+8]==b'verity\0\0'
sb=b[o:o+512]
hash_type=struct.unpack_from('<I',sb,12)[0]
algorithm=sb[32:64].split(b'\0')[0].decode()
db,hb,blocks,saltlen=struct.unpack_from('<IIQH',sb,64)
salt=sb[88:88+saltlen]
digest=lambda data:hashlib.new(algorithm,salt+data if hash_type==1 else data+salt).digest()
digest_size=hashlib.new(algorithm).digest_size
per_block=hb//digest_size
leaf_count=(blocks+per_block-1)//per_block
top=b[o+hb:o+2*hb]
leaves=b[o+2*hb:o+(2+leaf_count)*hb]
expected=(root/'initramfs-files'/'sd_verity_table').read_text().split()[-1]
result=dict(hash_type=hash_type,algorithm=algorithm,data_blocks=blocks,data_block_size=db,
            hash_block_size=hb,salt_length=saltlen,leaf_count=leaf_count,
            root_hash_matches=digest(top).hex()==expected,
            data_blocks_mismatched=sum(digest(b[i*db:(i+1)*db])!=leaves[i*digest_size:(i+1)*digest_size] for i in range(blocks)),
            tree_blocks_mismatched=sum(digest(leaves[i*hb:(i+1)*hb])!=top[i*digest_size:(i+1)*digest_size] for i in range(leaf_count)))
(root/'dm-verity-validation.json').write_text(json.dumps(result,indent=2))
print(json.dumps(result,indent=2))
