#!/usr/bin/env python3
"""Generate the selfsign reproduction fixtures from any ELF64 input.

    python3 mkfixtures.py <base.elf> <outdir>

Creates:
  trail.elf       base.elf + 20 KiB of data appended after the ELF (Bun
                  standalone module-graph style layout)
  entsize128.elf  base.elf whose section-header entries are expanded from
                  64 to 128 bytes (e_shentsize = 128, a legal ELF variant)
"""
import struct
import sys

TRAILER = bytes((i * 7 + 13) & 0xFF for i in range(20 * 1024))


def expand_sht(elf: bytes) -> bytes:
    e_shoff = struct.unpack_from('<Q', elf, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', elf, 0x3a)[0]
    e_shnum = struct.unpack_from('<H', elf, 0x3c)[0]
    e_shstrndx = struct.unpack_from('<H', elf, 0x3e)[0]
    assert e_shentsize == 64, f'input e_shentsize={e_shentsize}, only 64 supported here'
    sht_end = e_shoff + e_shnum * e_shentsize
    assert sht_end <= len(elf), 'section header table out of bounds'

    # keep everything outside the SHT, move the SHT to the end as 128-byte entries
    body = elf[:e_shoff] + elf[sht_end:]
    new_sht = bytearray()
    for i in range(e_shnum):
        entry = elf[e_shoff + i * 64: e_shoff + (i + 1) * 64]
        new_sht += entry + bytes(64)  # x86_64/arm64 reserve 64B for extensions
    new_shoff = len(body)
    out = bytearray(body + new_sht)
    struct.pack_into('<Q', out, 0x28, new_shoff)
    struct.pack_into('<H', out, 0x3a, 128)
    assert struct.unpack_from('<H', out, 0x3c)[0] == e_shnum
    assert struct.unpack_from('<H', out, 0x3e)[0] == e_shstrndx
    return bytes(out)


def main() -> int:
    base_path, outdir = sys.argv[1], sys.argv[2]
    base = open(base_path, 'rb').read()
    assert base[:4] == b'\x7fELF' and base[4] == 2, f'{base_path} is not ELF64'

    with open(f'{outdir}/trail.elf', 'wb') as f:
        f.write(base + TRAILER)

    with open(f'{outdir}/entsize128.elf', 'wb') as f:
        f.write(expand_sht(base))

    print(f'trail.elf      = {len(base)} + 20480 = {len(base) + len(TRAILER)} bytes')
    print(f'entsize128.elf = {len(expand_sht(base))} bytes, e_shentsize=128')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
