#!/usr/bin/env python3
"""Dump the .codesign segment layout of an ELF (payload + trailing merkle bytes)."""
import hashlib, struct, sys

def find_codesign(b):
    e_shoff = struct.unpack_from('<Q', b, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', b, 0x3a)[0]
    e_shnum = struct.unpack_from('<H', b, 0x3c)[0]
    e_shstrndx = struct.unpack_from('<H', b, 0x3e)[0]
    assert e_shentsize == 64, f'e_shentsize={e_shentsize}'
    shstr = struct.unpack_from('<QQ', b, e_shoff + e_shstrndx*64 + 24)
    names = b[shstr[0]:shstr[0]+shstr[1]]
    for i in range(e_shnum):
        e = e_shoff + i*64
        nm = struct.unpack_from('<I', b, e)[0]
        if names[nm:nm+9] == b'.codesign':
            off, sz = struct.unpack_from('<QQ', b, e + 24)
            return b[off:off+sz]
    return None

for path in sys.argv[1:]:
    b = open(path, 'rb').read()
    cs = find_codesign(b)
    print(f'== {path} ({len(b)} bytes)')
    if cs is None:
        print('   no .codesign'); continue
    t, length = struct.unpack_from('<II', cs, 0)
    d = cs[8:8+256]
    ss = struct.unpack_from('<I', d, 4)[0]
    fs = struct.unpack_from('<Q', d, 8)[0]
    end = 8 + 256 + ss
    tail = cs[end:]
    nz = [i for i, v in enumerate(tail) if v]
    print(f'   .codesign type={t} length={length} signSize={ss} fileSize={fs} (actual {len(b)})')
    print(f'   payload: cs[0:{end}]  md5={hashlib.md5(cs[:end]).hexdigest()}')
    print(f'   tail after payload: {len(tail)}B, nonzero {len(nz)}B, range {min(nz) if nz else None}..{max(nz) if nz else None}')
    if nz:
        tn = tail[:max(nz)+1]
        print(f'   tail md5={hashlib.md5(tn).hexdigest()}  sha256={hashlib.sha256(tn).hexdigest()[:16]}')
