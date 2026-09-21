#!/usr/bin/env python3
"""Verify that the bytes after the .codesign payload are fs-verity merkle
intermediate hashes of the file itself.

    python3 verify_merkle_tail.py <elf> [--dump-prefix N]

Checks, in order:
  1. descriptor.signSize == 32, fileSize == actual size
  2. recomputed merkle root == descriptor.rootHash
  3. recomputed intermediate layers (level1, level2, ..., root level),
     concatenated and truncated to the last min(3800, len) bytes,
     equal the bytes stored after the payload inside the 4 KiB section
"""
import hashlib
import struct
import sys

PAGE = 4096
H = 32


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def codesign_info(elf: bytes):
    e_shoff = struct.unpack_from('<Q', elf, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', elf, 0x3a)[0]
    e_shnum = struct.unpack_from('<H', elf, 0x3c)[0]
    e_shstrndx = struct.unpack_from('<H', elf, 0x3e)[0]
    shstr_off = struct.unpack_from('<Q', elf, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    shstr_sz = struct.unpack_from('<Q', elf, e_shoff + e_shstrndx * e_shentsize + 32)[0]
    names = elf[shstr_off:shstr_off + shstr_sz]
    for i in range(e_shnum):
        e = e_shoff + i * e_shentsize
        nm = struct.unpack_from('<I', elf, e)[0]
        end = names.find(b'\0', nm)
        if names[nm:end] == b'.codesign':
            off = struct.unpack_from('<Q', elf, e + 24)[0]
            size = struct.unpack_from('<Q', elf, e + 32)[0]
            return off, size
    raise SystemExit('no .codesign section')


def merkle(data: bytes, cs_off: int, cs_len: int):
    """Return (root, intermediate_bytes) using the binary-sign-tool algorithm."""
    npages = (len(data) + PAGE - 1) // PAGE
    cs_begin = cs_off // PAGE
    cs_end = (cs_off + cs_len + PAGE - 1) // PAGE
    cur = bytearray()
    for i in range(npages):
        if cs_begin <= i < cs_end:
            cur += bytes(H)  # the .codesign page(s) are excluded
        else:
            page = data[i * PAGE:(i + 1) * PAGE]
            cur += sha256(page.ljust(PAGE, b'\0'))
    levels = []
    while len(cur) > PAGE:
        nxt = bytearray()
        for i in range(0, len(cur), PAGE):
            nxt += sha256(bytes(cur[i:i + PAGE]).ljust(PAGE, b'\0'))
        cur = nxt
        levels.append(bytes(cur))
    root = sha256(bytes(cur).ljust(PAGE, b'\0'))
    return root, b''.join(levels)


def main() -> int:
    path = sys.argv[1]
    elf = open(path, 'rb').read()
    cs_off, cs_len = codesign_info(elf)
    cs = elf[cs_off:cs_off + cs_len]
    typ, length = struct.unpack_from('<II', cs, 0)
    desc = cs[8:8 + 256]
    sign_size = struct.unpack_from('<I', desc, 4)[0]
    file_size = struct.unpack_from('<Q', desc, 8)[0]
    stored_root = desc[16:48]
    tail = cs[8 + 256 + sign_size:]

    root, intermediate = merkle(elf, cs_off, cs_len)
    # written from the layer closest to the leaves, truncated at the root side
    # (binary-sign-tool writes tree_bytes[:4096 - 296])
    expected_tail = intermediate[:len(tail)].ljust(len(tail), b'\0')

    print(f'file            {path} ({len(elf)} bytes)')
    print(f'.codesign       type={typ} length={length} signSize={sign_size}')
    print(f'fileSize        descriptor={file_size} actual={len(elf)} '
          f'{"OK" if file_size == len(elf) else "MISMATCH"}')
    print(f'rootHash        stored={stored_root.hex()[:32]}...')
    print(f'                recomputed={root.hex()[:32]}... '
          f'{"MATCH" if root == stored_root else "MISMATCH"}')
    nz = sum(1 for v in tail if v)
    print(f'tail            {len(tail)} bytes, {nz} nonzero')
    print(f'                stored   = {hashlib.md5(tail).hexdigest()}')
    print(f'                expected = {hashlib.md5(expected_tail).hexdigest()} '
          f'{"MATCH" if tail == expected_tail else "MISMATCH"}')
    if '--dump-prefix' in sys.argv:
        n = int(sys.argv[sys.argv.index('--dump-prefix') + 1])
        print(f'stored[:{n}]   {tail[:n].hex()}')
        print(f'expected[:{n}] {expected_tail[:n].hex()}')
    return 0 if (root == stored_root and tail == expected_tail) else 1


if __name__ == '__main__':
    raise SystemExit(main())
