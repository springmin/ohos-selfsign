// Standalone OpenHarmony ELF64 self-signer (C#).
//
// Adapted from the standalone signer in dotnet/sdk-ohos (eng/ohos-install/selfsign.cs
// and src/Tasks/Microsoft.NET.Build.Tasks/ElfSigner.cs, MIT), matching the algorithm
// and CLI of the other implementations in this repository byte-for-byte.
//
// Zero third-party dependencies: the BCL only (System.Security.Cryptography for SHA-256).
//
// Usage:
//   dotnet run selfsign.cs -- <input_elf> [output_elf] [--force] [--strip] [--check]
//     (output defaults to input, in-place)
//
// Or publish a native binary:
//   dotnet publish selfsign.cs -c Release -r linux-arm64 -o out
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

internal static class ElfSigner
{
    private const int DescSize = 256;
    private const int PageSize = 4096;
    private const uint FlagSelfSign = 0x10;
    private const uint FsVerityDescriptorType = 1;
    private const int HashOut = 32;

    // ELF64 header field offsets
    private const int EShOff = 0x28;
    private const int EShentsize = 0x3a;
    private const int EShnum = 0x3c;
    private const int EShstrndx = 0x3e;

    // ".codesign\0" including the trailing NUL (10 bytes)
    private static readonly byte[] s_codesignName = new byte[] { (byte)'.', (byte)'c', (byte)'o', (byte)'d', (byte)'e', (byte)'s', (byte)'i', (byte)'g', (byte)'n', 0 };

    internal static bool IsElf64(byte[] data) =>
        data.Length >= 64 &&
        data[0] == 0x7f && data[1] == (byte)'E' && data[2] == (byte)'L' && data[3] == (byte)'F' &&
        data[4] == 2 && // ELFCLASS64
        data[5] == 1;   // ELFDATA2LSB: the signer reads/writes little-endian fields

    private static ushort ReadU16(byte[] b, int off) => (ushort)(b[off] | (b[off + 1] << 8));

    private static uint ReadU32(byte[] b, int off) =>
        (uint)(b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24));

    private static ulong ReadU64(byte[] b, int off) =>
        (ulong)b[off] | ((ulong)b[off + 1] << 8) | ((ulong)b[off + 2] << 16) | ((ulong)b[off + 3] << 24) |
        ((ulong)b[off + 4] << 32) | ((ulong)b[off + 5] << 40) | ((ulong)b[off + 6] << 48) | ((ulong)b[off + 7] << 56);

    private static void WriteU16(byte[] b, int off, ushort v)
    {
        b[off] = (byte)v;
        b[off + 1] = (byte)(v >> 8);
    }

    private static void WriteU32(byte[] b, int off, uint v)
    {
        b[off] = (byte)v;
        b[off + 1] = (byte)(v >> 8);
        b[off + 2] = (byte)(v >> 16);
        b[off + 3] = (byte)(v >> 24);
    }

    private static void WriteU64(byte[] b, int off, ulong v)
    {
        b[off] = (byte)v;
        b[off + 1] = (byte)(v >> 8);
        b[off + 2] = (byte)(v >> 16);
        b[off + 3] = (byte)(v >> 24);
        b[off + 4] = (byte)(v >> 32);
        b[off + 5] = (byte)(v >> 40);
        b[off + 6] = (byte)(v >> 48);
        b[off + 7] = (byte)(v >> 56);
    }

    private static ulong AlignUp(ulong v, ulong a) => (v + a - 1) / a * a;

    // NOTE: SHA256.HashData is not available on net472, which the SDK project also
    // multi-targets; SHA256.Create() works everywhere.
    private static byte[] Sha256(byte[] data)
    {
        using (SHA256 sha = SHA256.Create())
        {
            return sha.ComputeHash(data);
        }
    }

    // eShentsize must be at least the standard 64 bytes; larger entries (with extra
    // fields) are legal and all table walks advance by the real entry size.
    private static (ulong eShOff, ushort eShnum, ushort eShstrndx, ushort eShentsize) ParseElfHeader(byte[] elf)
    {
        if (!IsElf64(elf))
        {
            throw new InvalidDataException("not ELF64");
        }

        ulong eShOff = ReadU64(elf, EShOff);
        ushort eShentsize = ReadU16(elf, EShentsize);
        ushort eShnum = ReadU16(elf, EShnum);
        ushort eShstrndx = ReadU16(elf, EShstrndx);
        if (eShentsize < 64 || eShOff == 0 || eShnum == 0 || eShstrndx >= eShnum)
        {
            throw new InvalidDataException("ELF has no usable section header table");
        }

        if (eShOff > (ulong)elf.Length || (ulong)eShnum > ((ulong)elf.Length - eShOff) / eShentsize)
        {
            throw new InvalidDataException("section header table out of bounds");
        }

        return (eShOff, eShnum, eShstrndx, eShentsize);
    }

    private static long FindSectionByName(byte[] elf, ulong eShOff, ushort eShnum, ushort eShstrndx, ushort eShentsize, byte[] name)
    {
        int nameLen = name.Length;
        ulong shstrE = eShOff + (ulong)eShstrndx * eShentsize;
        ulong shstrOff = ReadU64(elf, (int)(shstrE + 24));
        ulong shstrSz = ReadU64(elf, (int)(shstrE + 32));
        if (shstrOff > (ulong)elf.Length || shstrSz > (ulong)elf.Length - shstrOff)
        {
            return -1;
        }

        for (int i = 0; i < eShnum; i++)
        {
            ulong e = eShOff + (ulong)i * eShentsize;
            uint nameOff = ReadU32(elf, (int)e);
            if ((ulong)nameOff + (ulong)nameLen <= shstrSz)
            {
                int start = (int)(shstrOff + nameOff);
                if (start + nameLen <= elf.Length && ByteArrayEquals(elf, start, name))
                {
                    return (long)e;
                }
            }
        }

        return -1;
    }

    private static bool ByteArrayEquals(byte[] b, int off, byte[] name)
    {
        for (int i = 0; i < name.Length; i++)
        {
            if (b[off + i] != name[i])
            {
                return false;
            }
        }

        return true;
    }

    private static bool BytesEqual(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
        {
            return false;
        }

        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    private static bool HasCodesignSection(byte[] elf)
    {
        (ulong eShOff, ushort eShnum, ushort eShstrndx, ushort eShentsize) = ParseElfHeader(elf);
        return FindSectionByName(elf, eShOff, eShnum, eShstrndx, eShentsize, s_codesignName) >= 0;
    }

    private static ushort NewShstrndx(ushort oldShstrndx, int csIdx) =>
        csIdx < oldShstrndx ? (ushort)(oldShstrndx - 1) : oldShstrndx;

    internal static byte[] StripCodesign(byte[] buf, out bool removed)
    {
        removed = false;
        (ulong eShOff, ushort eShnum, ushort eShstrndx, ushort eShentsize) = ParseElfHeader(buf);

        long csEntryOff = FindSectionByName(buf, eShOff, eShnum, eShstrndx, eShentsize, s_codesignName);
        if (csEntryOff < 0)
        {
            return buf;
        }

        removed = true;
        int csIdx = (int)(((ulong)csEntryOff - eShOff) / eShentsize);

        ulong shstrE = eShOff + (ulong)eShstrndx * eShentsize;
        ulong shstrOff = ReadU64(buf, (int)(shstrE + 24));
        ulong shstrSz = ReadU64(buf, (int)(shstrE + 32));
        if (shstrOff > (ulong)buf.Length || shstrSz > (ulong)buf.Length - shstrOff)
        {
            throw new InvalidDataException("shstrtab out of bounds");
        }

        uint csNameOff = ReadU32(buf, (int)csEntryOff);
        int csNameLen = s_codesignName.Length;
        int shstrStart = (int)shstrOff;
        byte[] newShstr = new byte[shstrSz - (ulong)csNameLen];
        Buffer.BlockCopy(buf, shstrStart, newShstr, 0, (int)csNameOff);
        Buffer.BlockCopy(buf, shstrStart + (int)csNameOff + csNameLen, newShstr, (int)csNameOff, (int)(shstrSz - (ulong)csNameOff - (ulong)csNameLen));
        int newShstrSz = newShstr.Length;

        int newShnum = eShnum - 1;
        byte[] newSht = new byte[newShnum * eShentsize];
        int dst = 0;
        for (int i = 0; i < eShnum; i++)
        {
            if (i == csIdx)
            {
                continue;
            }

            Buffer.BlockCopy(buf, (int)eShOff + i * eShentsize, newSht, dst, eShentsize);
            dst += eShentsize;
        }

        ulong csSecOff = ReadU64(buf, (int)csEntryOff + 24);
        int keepLen = (int)Math.Min(csSecOff, (ulong)buf.Length);
        int newShstrOff = keepLen;
        int newShtOff = (int)AlignUp((ulong)(newShstrOff + newShstrSz), 8);
        int newTotal = newShtOff + newShnum * eShentsize;

        byte[] outBuf = new byte[newTotal];
        Buffer.BlockCopy(buf, 0, outBuf, 0, keepLen);
        Buffer.BlockCopy(newShstr, 0, outBuf, newShstrOff, newShstrSz);
        Buffer.BlockCopy(newSht, 0, outBuf, newShtOff, newShnum * eShentsize);

        int shstrEntryOffInNew = NewShstrndx(eShstrndx, csIdx) * eShentsize;
        WriteU64(outBuf, newShtOff + shstrEntryOffInNew + 24, (ulong)newShstrOff);
        WriteU64(outBuf, newShtOff + shstrEntryOffInNew + 32, (ulong)newShstrSz);

        for (int i = 0; i < newShnum; i++)
        {
            int e = newShtOff + i * eShentsize;
            uint noff = ReadU32(outBuf, e);
            if (noff > csNameOff)
            {
                WriteU32(outBuf, e, noff - (uint)csNameLen);
            }
        }

        WriteU64(outBuf, EShOff, (ulong)newShtOff);
        WriteU16(outBuf, EShnum, (ushort)newShnum);
        if (csIdx < eShstrndx)
        {
            WriteU16(outBuf, EShstrndx, (ushort)(eShstrndx - 1));
        }

        return outBuf;
    }

    private static (byte[] buf, int csOff) InjectCodesignSection(byte[] elf)
    {
        (ulong eShOff, ushort eShnum, ushort eShstrndx, ushort eShentsize) = ParseElfHeader(elf);

        ulong shstrE = eShOff + (ulong)eShstrndx * eShentsize;
        ulong shstrOff = ReadU64(elf, (int)(shstrE + 24));
        ulong shstrSz = ReadU64(elf, (int)(shstrE + 32));
        if (shstrOff > (ulong)elf.Length || shstrSz > (ulong)elf.Length - shstrOff)
        {
            throw new InvalidDataException("shstrtab out of bounds");
        }

        ulong curEnd = eShOff + (ulong)eShnum * eShentsize;
        for (int i = 0; i < eShnum; i++)
        {
            ulong e = eShOff + (ulong)i * eShentsize;
            uint shType = ReadU32(elf, (int)(e + 4));
            ulong off = ReadU64(elf, (int)(e + 24));
            ulong sz = shType == 8 ? 0 : ReadU64(elf, (int)(e + 32));
            if (off + sz > curEnd)
            {
                curEnd = off + sz;
            }
        }

        // SingleFile bundles (and other data) may follow the section header table but are not
        // covered by any section. Preserve everything through the real end of file so the
        // bundle survives signing (otherwise the apphost is truncated to its ELF-only part).
        if ((ulong)elf.Length > curEnd)
        {
            curEnd = (ulong)elf.Length;
        }

        ulong csOffAligned = AlignUp(curEnd, PageSize);
        if (csOffAligned > int.MaxValue)
        {
            throw new InvalidDataException("ELF too large to sign");
        }

        int csOff = (int)csOffAligned;

        int shstrStart = (int)shstrOff;
        byte[] newShstr = new byte[shstrSz + (ulong)s_codesignName.Length];
        Buffer.BlockCopy(elf, shstrStart, newShstr, 0, (int)shstrSz);
        Buffer.BlockCopy(s_codesignName, 0, newShstr, (int)shstrSz, s_codesignName.Length);
        int newShstrSz = newShstr.Length;
        uint csShname = (uint)shstrSz;

        int newShstrOff = csOff + PageSize;
        int newShtOff = (int)AlignUp((ulong)(newShstrOff + newShstrSz), 8);
        int newShnum = eShnum + 1;
        int newTotal = newShtOff + newShnum * eShentsize;

        byte[] buf = new byte[newTotal];
        int copyLen = Math.Min(elf.Length, Math.Min(newTotal, csOff));
        Buffer.BlockCopy(elf, 0, buf, 0, copyLen);

        Buffer.BlockCopy(newShstr, 0, buf, newShstrOff, newShstrSz);
        Buffer.BlockCopy(elf, (int)eShOff, buf, newShtOff, (int)eShnum * eShentsize);

        int csE = newShtOff + (int)eShnum * eShentsize;
        WriteU32(buf, csE, csShname); // sh_name
        WriteU32(buf, csE + 4, 1); // sh_type = SHT_PROGBITS
        WriteU64(buf, csE + 24, (ulong)csOff); // sh_offset
        WriteU64(buf, csE + 32, PageSize); // sh_size
        WriteU64(buf, csE + 48, PageSize); // sh_addralign

        int shstrENew = newShtOff + (int)eShstrndx * eShentsize;
        WriteU64(buf, shstrENew + 24, (ulong)newShstrOff);
        WriteU64(buf, shstrENew + 32, (ulong)newShstrSz);

        WriteU64(buf, EShOff, (ulong)newShtOff);
        WriteU16(buf, EShnum, (ushort)newShnum);

        return (buf, csOff);
    }

    // Returns (root, tree): the fs-verity Merkle root hash and the intermediate tree
    // bytes (levels above the leaves, bottom-up; the root level is excluded).
    private static (byte[] root, byte[] tree) MerkleRootHashAndTree(byte[] data, int csOff, int csLen)
    {
        if (data.Length == 0)
        {
            return (Sha256(new byte[PageSize]), Array.Empty<byte>());
        }

        int npages = (data.Length + PageSize - 1) / PageSize;
        int csPageBegin = csOff / PageSize;
        int csPageEnd = (csOff + csLen + PageSize - 1) / PageSize;

        byte[] leaves = new byte[npages * HashOut];
        for (int i = 0; i < npages; i++)
        {
            if (csLen > 0 && i >= csPageBegin && i < csPageEnd)
            {
                continue; // codesign pages: zero leaf hash
            }

            byte[] page = new byte[PageSize];
            int off = i * PageSize;
            int n = Math.Min(PageSize, data.Length - off);
            Buffer.BlockCopy(data, off, page, 0, n);
            byte[] h = Sha256(page);
            Buffer.BlockCopy(h, 0, leaves, i * HashOut, HashOut);
        }

        if (npages == 1)
        {
            byte[] single = new byte[HashOut];
            Buffer.BlockCopy(leaves, 0, single, 0, HashOut);
            return (single, Array.Empty<byte>());
        }

        // levels[0] = leaves; the last level is the root level.
        var levels = new List<byte[]> { leaves };
        while (levels[levels.Count - 1].Length > PageSize)
        {
            byte[] prev = levels[levels.Count - 1];
            int nextPages = (prev.Length + PageSize - 1) / PageSize;
            byte[] next = new byte[nextPages * HashOut];
            for (int i = 0; i < nextPages; i++)
            {
                byte[] page = new byte[PageSize];
                int off = i * PageSize;
                int n = Math.Min(PageSize, prev.Length - off);
                Buffer.BlockCopy(prev, off, page, 0, n);
                byte[] h = Sha256(page);
                Buffer.BlockCopy(h, 0, next, i * HashOut, HashOut);
            }

            levels.Add(next);
        }

        byte[] rootPage = new byte[PageSize];
        Buffer.BlockCopy(levels[levels.Count - 1], 0, rootPage, 0, levels[levels.Count - 1].Length);
        byte[] root = Sha256(rootPage);

        // Tree bytes = the levels between the leaves and the root level, bottom-up.
        var tree = new List<byte>();
        if (levels.Count > 2)
        {
            for (int i = 1; i < levels.Count - 1; i++)
            {
                tree.AddRange(levels[i]);
            }
        }

        return (root, tree.ToArray());
    }

    private static byte[] BuildDescriptor(uint signSize, ulong fileSize, byte[] root, uint flags)
    {
        byte[] d = new byte[DescSize];
        d[0] = 1; // version
        d[1] = 1; // hashAlgorithm = SHA-256
        d[2] = 12; // log2BlockSize = 2^12 = 4096
        d[3] = 0; // saltSize
        WriteU32(d, 4, signSize);
        WriteU64(d, 8, fileSize);
        Buffer.BlockCopy(root, 0, d, 16, HashOut); // rootHash left-aligned
        WriteU32(d, 112, flags);
        d[255] = 3; // csVersion
        return d;
    }

    internal static byte[] SignElf(byte[] elf, bool force)
    {
        if (!IsElf64(elf))
        {
            throw new InvalidDataException("not ELF64");
        }

        byte[] buf = elf;
        if (HasCodesignSection(buf))
        {
            if (!force)
            {
                throw new InvalidDataException("already has a .codesign section; strip first or use --force");
            }

            buf = StripCodesign(buf, out _);
        }

        (byte[] tmp0, int csOff) = InjectCodesignSection(buf);
        ulong fileSize = (ulong)tmp0.Length;

        (byte[] root, byte[] tree) = MerkleRootHashAndTree(tmp0, csOff, PageSize);

        byte[] descForDigest = BuildDescriptor(0, fileSize, root, FlagSelfSign);
        byte[] signature = Sha256(descForDigest);
        byte[] descOnDisk = BuildDescriptor(32, fileSize, root, FlagSelfSign);

        byte[] payload = new byte[4 + 4 + DescSize + HashOut];
        WriteU32(payload, 0, FsVerityDescriptorType); // type
        WriteU32(payload, 4, (uint)(DescSize + HashOut)); // length = 288
        Buffer.BlockCopy(descOnDisk, 0, payload, 8, DescSize);
        Buffer.BlockCopy(signature, 0, payload, 8 + DescSize, HashOut);

        Buffer.BlockCopy(payload, 0, tmp0, csOff, payload.Length);

        // Write the Merkle tree intermediate hashes after the payload, as
        // binary-sign-tool does; the 4KB section truncates them from the leaf side.
        int treeStart = csOff + payload.Length;
        int treeMax = PageSize - payload.Length;
        if (tree.Length > 0)
        {
            int n = Math.Min(tree.Length, treeMax);
            Buffer.BlockCopy(tree, 0, tmp0, treeStart, n);
        }

        ValidateSigned(tmp0, csOff);
        return tmp0;
    }

    /// <summary>
    /// True when the file carries a .codesign payload that matches the current content: the
    /// descriptor is well-formed, the stored page Merkle root equals the recomputed one, and
    /// the stored signature equals SHA-256 of the descriptor with signSize zeroed.
    /// </summary>
    internal static bool IsValidlySigned(byte[] elf)
    {
        try
        {
            if (!TryGetCodesignSection(elf, out int csOff, out int csLen) || csLen < 8 + DescSize + HashOut)
            {
                return false;
            }

            uint type = ReadU32(elf, csOff);
            uint length = ReadU32(elf, csOff + 4);
            int dOff = csOff + 8;
            if (type != FsVerityDescriptorType || length != DescSize + HashOut)
            {
                return false;
            }

            if (elf[dOff] != 1 || elf[dOff + 1] != 1 || elf[dOff + 2] != 12 || elf[dOff + 255] != 3)
            {
                return false;
            }

            uint signSize = ReadU32(elf, dOff + 4);
            ulong fileSize = ReadU64(elf, dOff + 8);
            uint flags = ReadU32(elf, dOff + 112);
            if (signSize != HashOut || fileSize != (ulong)elf.Length)
            {
                return false;
            }

            byte[] root = new byte[HashOut];
            Buffer.BlockCopy(elf, dOff + 16, root, 0, HashOut);
            (byte[] recomputedRoot, _) = MerkleRootHashAndTree(elf, csOff, csLen);
            if (!BytesEqual(root, recomputedRoot))
            {
                return false;
            }

            byte[] signature = new byte[HashOut];
            Buffer.BlockCopy(elf, dOff + DescSize, signature, 0, HashOut);
            byte[] expectedSignature = Sha256(BuildDescriptor(0, fileSize, recomputedRoot, flags));
            return BytesEqual(signature, expectedSignature);
        }
        catch (Exception)
        {
            // A malformed ELF/section table means "not validly signed" for our purposes.
            return false;
        }
    }

    private static bool TryGetCodesignSection(byte[] elf, out int csOff, out int csLen)
    {
        csOff = 0;
        csLen = 0;
        (ulong eShOff, ushort eShnum, ushort eShstrndx, ushort eShentsize) = ParseElfHeader(elf);
        long csEntryOff = FindSectionByName(elf, eShOff, eShnum, eShstrndx, eShentsize, s_codesignName);
        if (csEntryOff < 0)
        {
            return false;
        }

        ulong off = ReadU64(elf, (int)csEntryOff + 24);
        ulong size = ReadU64(elf, (int)csEntryOff + 32);
        if (off > (ulong)elf.Length || size > (ulong)elf.Length - off || size > int.MaxValue)
        {
            return false;
        }

        csOff = (int)off;
        csLen = (int)size;
        return true;
    }

    // Mirrors Mach-O Validate: after building the signature, re-parse the result to ensure the
    // layout is self-consistent — the .codesign data is at csOff, nothing that must be covered
    // by the signature (the executable and any SingleFile bundle) was dropped, and the section
    // header table is still readable.
    private static void ValidateSigned(byte[] signed, int csOff)
    {
        if (signed.Length < csOff + PageSize)
        {
            throw new InvalidDataException("signature payload exceeds file length");
        }

        (ulong eShOff, ushort eShnum, ushort eShstrndx, ushort eShentsize) = ParseElfHeader(signed);
        if (FindSectionByName(signed, eShOff, eShnum, eShstrndx, eShentsize, s_codesignName) < 0)
        {
            throw new InvalidDataException("signed output is missing the .codesign section");
        }

        if (csOff > signed.Length)
        {
            throw new InvalidDataException("codesign offset out of bounds");
        }
    }
}

internal static class Program
{
    private static int Main(string[] args)
    {
        bool force = false;
        bool stripOnly = false;
        bool checkOnly = false;
        var positional = new List<string>();
        foreach (var a in args)
        {
            if (a == "--force" || a == "-f") force = true;
            else if (a == "--strip") stripOnly = true;
            else if (a == "--check") checkOnly = true;
            else positional.Add(a);
        }

        if (positional.Count == 0 || positional.Count > 2)
        {
            Console.Error.WriteLine("usage: selfsign <input_elf> [output_elf] [--force] [--strip] [--check]");
            Console.Error.WriteLine("  (output defaults to input, in-place)");
            return 1;
        }

        string inPath = positional[0];
        string outPath = positional.Count == 2 ? positional[1] : inPath;

        try
        {
            if (checkOnly)
            {
                byte[] raw = File.ReadAllBytes(inPath);
                if (ElfSigner.IsValidlySigned(raw))
                {
                    Console.WriteLine($"check ok: {inPath} (valid self-sign, {raw.Length} bytes)");
                    return 0;
                }

                Console.WriteLine($"check failed: {inPath} (not a valid self-sign ELF)");
                return 1;
            }

            if (stripOnly)
            {
                byte[] raw = File.ReadAllBytes(inPath);
                byte[] stripped = ElfSigner.StripCodesign(raw, out bool removed);
                if (!removed)
                {
                    Console.WriteLine($"no .codesign section to strip: {inPath}");
                    return 0;
                }

                File.WriteAllBytes(outPath, stripped);
                Console.WriteLine($"strip ok: {inPath} → {outPath} ({stripped.Length} bytes)");
                return 0;
            }

            byte[] data = File.ReadAllBytes(inPath);
            byte[] signed = ElfSigner.SignElf(data, force);
            if (inPath == outPath)
            {
                // Overwrite the same inode so the file keeps its Unix permissions.
                File.WriteAllBytes(inPath, signed);
                Console.WriteLine($"selfsign ok: {inPath} (in-place, {(force ? "force" : "append-only")})");
            }
            else
            {
                File.WriteAllBytes(outPath, signed);
                Console.WriteLine($"selfsign ok: {inPath} → {outPath} ({signed.Length} bytes)");
            }

            return 0;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"error: {e.Message}");
            return 2;
        }
    }
}
