// Copyright (C) 2026 hqzing
// SPDX-License-Identifier: 0BSD
// Repository: https://github.com/hqzing/ohos-selfsign
//
// Licensed under the BSD Zero Clause License.

/*
 * selfsign.go — 轻量级 OpenHarmony 二进制自签名工具
 *
 * 用法:
 *     go build -o selfsign selfsign.go
 *     ./selfsign <input_elf> [output_elf] [--force] [--strip] [--check]
 *         缺省 output 时, inplace 改写 input.
 *         --force : 若已含 .codesign 段, 先剥离再重签
 *         --strip : 仅剥离 .codesign 段, 不做签名
 *         --check : 只读校验已有自签名的有效性, 不写任何文件
 */
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

const (
	descSize               = 256
	pageSize               = 4096
	flagSelfSign           = 0x10
	fsVerityDescriptorType = 1
	hashOut                = 32 // SHA-256 输出字节数
)

// ELF64 header 字段偏移
const (
	eShOff     = 0x28
	eShEntsize = 0x3a
	eShNum     = 0x3c
	eShStrndx  = 0x3e
)

var codesignName = []byte(".codesign\x00") // 含结尾 NUL, 共 10 字节

// ─────────────────────── 字节读写工具 ───────────────────────
func readU16(b []byte, off int) uint16 {
	return binary.LittleEndian.Uint16(b[off : off+2])
}
func readU32(b []byte, off int) uint32 {
	return binary.LittleEndian.Uint32(b[off : off+4])
}
func readU64(b []byte, off int) uint64 {
	return binary.LittleEndian.Uint64(b[off : off+8])
}
func writeU16(b []byte, off int, v uint16) {
	binary.LittleEndian.PutUint16(b[off:off+2], v)
}
func writeU32(b []byte, off int, v uint32) {
	binary.LittleEndian.PutUint32(b[off:off+4], v)
}
func writeU64(b []byte, off int, v uint64) {
	binary.LittleEndian.PutUint64(b[off:off+8], v)
}

func alignUp(v, a uint64) uint64 {
	return ((v + a - 1) / a) * a
}

func doSha256(b []byte) [32]byte {
	return sha256.Sum256(b)
}

// ─────────────────── ELF 预清洗/标准化 (非签名必需) ───────────────────
type elfHeader struct {
	eShOff     uint64
	eShEntsize uint16 // 实际段表条目大小 (>= 64)
	eShNum     uint16
	eShStrndx  uint16
}

func parseElfHeader(elf []byte) (*elfHeader, error) {
	if len(elf) < 64 || elf[0] != 0x7f || elf[1] != 0x45 ||
		elf[2] != 0x4c || elf[3] != 0x46 || elf[4] != 2 {
		return nil, errors.New("not ELF64")
	}
	eShOff := readU64(elf, eShOff)
	shentsize := readU16(elf, eShEntsize)
	eShNum := readU16(elf, eShNum)
	eShStrndx := readU16(elf, eShStrndx)
	// ELF64 允许段表条目大于 64 字节 (携带扩展字段), 故只拒绝小于 64 的
	if shentsize < 64 || eShOff == 0 || eShNum == 0 || eShStrndx >= eShNum {
		return nil, errors.New("ELF has no usable section header table")
	}
	if eShOff > uint64(len(elf)) || uint64(eShNum) > (uint64(len(elf))-eShOff)/uint64(shentsize) {
		return nil, errors.New("section header table out of bounds")
	}
	return &elfHeader{eShOff: eShOff, eShEntsize: shentsize, eShNum: eShNum, eShStrndx: eShStrndx}, nil
}

func findSectionByName(elf []byte, h *elfHeader, name []byte) int64 {
	nameLen := len(name)
	shstrE := h.eShOff + uint64(h.eShStrndx)*uint64(h.eShEntsize)
	shstrOff := readU64(elf, int(shstrE)+24)
	shstrSz := readU64(elf, int(shstrE)+32)
	if shstrOff > uint64(len(elf)) || shstrSz > uint64(len(elf))-shstrOff {
		return -1
	}
	for i := uint16(0); i < h.eShNum; i++ {
		e := h.eShOff + uint64(i)*uint64(h.eShEntsize)
		nameOff := readU32(elf, int(e))
		if uint64(nameOff)+uint64(nameLen) <= shstrSz {
			start := int(shstrOff + uint64(nameOff))
			if string(elf[start:start+nameLen]) == string(name) {
				return int64(e)
			}
		}
	}
	return -1
}

func hasCodesignSection(elf []byte) bool {
	h, err := parseElfHeader(elf)
	if err != nil {
		return false
	}
	return findSectionByName(elf, h, codesignName) >= 0
}

func newShstrndx(oldShstrndx uint16, csIdx int) uint16 {
	if uint16(csIdx) < oldShstrndx {
		return oldShstrndx - 1
	}
	return oldShstrndx
}

func stripCodesign(buf []byte) (bool, []byte, error) {
	elf := make([]byte, len(buf))
	copy(elf, buf)
	h, err := parseElfHeader(elf)
	if err != nil {
		return false, nil, err
	}

	csEntryOff := findSectionByName(elf, h, codesignName)
	if csEntryOff < 0 {
		return false, elf, nil
	}
	shentsize := int(h.eShEntsize)
	csIdx := int((uint64(csEntryOff) - h.eShOff) / uint64(shentsize))

	shstrE := h.eShOff + uint64(h.eShStrndx)*uint64(shentsize)
	shstrOff := readU64(elf, int(shstrE)+24)
	shstrSz := readU64(elf, int(shstrE)+32)
	if shstrOff > uint64(len(elf)) || shstrSz > uint64(len(elf))-shstrOff {
		return false, nil, errors.New("shstrtab out of bounds")
	}

	// 2. 新 shstrtab = 旧 shstrtab 删掉 ".codesign\0"
	csNameOff := readU32(elf, int(csEntryOff))
	csNameLen := len(codesignName) // 10, 含 NUL
	shstrStart := int(shstrOff)
	newShstr := make([]byte, shstrSz)
	copy(newShstr, elf[shstrStart:shstrStart+int(shstrSz)])
	newShstrSz := int(shstrSz)
	if int(csNameOff)+csNameLen <= len(newShstr) {
		newShstr = append(newShstr[:csNameOff], newShstr[int(csNameOff)+csNameLen:]...)
		newShstrSz = len(newShstr)
	}

	// 3. 新 SHT = 旧 SHT 去掉 csIdx 条目 (条目不压缩, 按原 e_shentsize 保留)
	newShNum := h.eShNum - 1
	newSht := make([]byte, 0, int(newShNum)*shentsize)
	for i := uint16(0); i < h.eShNum; i++ {
		if int(i) == csIdx {
			continue
		}
		e := int(h.eShOff) + int(i)*shentsize
		newSht = append(newSht, elf[e:e+shentsize]...)
	}

	// 4. 新表落位: 若 .codesign 段数据之后恰好只有旧 shstrtab 与旧 SHT
	//    (即本工具自己签出的布局), 照旧截断到段偏移并在原位重建, 文件不膨胀;
	//    否则 (如签名后又被 patchelf 等工具重排过, 段数据之后仍有活跃内容,
	//    例如被挪到文件尾部新增段的 .interp) 不截断, 新表追加到文件末尾,
	//    原段数据成为无引用的死字节.
	csSecOff := readU64(elf, int(csEntryOff)+24)
	compact := csSecOff <= uint64(len(elf)) &&
		csSecOff+pageSize == shstrOff &&
		h.eShOff == alignUp(shstrOff+shstrSz, 8) &&
		uint64(len(elf)) == h.eShOff+uint64(h.eShNum)*uint64(shentsize)
	keepLen := len(elf)
	if compact {
		keepLen = int(csSecOff)
	}
	newShstrOff := keepLen
	newShtOff := int(alignUp(uint64(newShstrOff+newShstrSz), 8))
	newTotal := newShtOff + int(newShNum)*shentsize

	out := make([]byte, newTotal)
	copy(out, elf[:keepLen])
	copy(out[newShstrOff:], newShstr)
	copy(out[newShtOff:], newSht)

	// 5. 重写 shstrtab 条目
	shstrEntryOffInNew := int(newShstrndx(h.eShStrndx, csIdx)) * shentsize
	writeU64(out, newShtOff+shstrEntryOffInNew+24, uint64(newShstrOff))
	writeU64(out, newShtOff+shstrEntryOffInNew+32, uint64(newShstrSz))

	// 6. 所有 sh_name > cs_name_off 的段名偏移整体前移 cs_name_len
	for i := 0; i < int(newShNum); i++ {
		e := newShtOff + i*shentsize
		noff := readU32(out, e)
		if noff > csNameOff {
			writeU32(out, e, noff-uint32(csNameLen))
		}
	}

	// 7. 更新 header
	writeU64(out, eShOff, uint64(newShtOff))
	writeU16(out, eShNum, newShNum)
	if uint16(csIdx) < h.eShStrndx {
		writeU16(out, eShStrndx, h.eShStrndx-1)
	}

	return true, out, nil
}

// ─────────────────── 签名必需的算法核心 ───────────────────
func injectCodesignSection(elf []byte) ([]byte, int, error) {
	h, err := parseElfHeader(elf)
	if err != nil {
		return nil, 0, err
	}

	shstrE := h.eShOff + uint64(h.eShStrndx)*uint64(h.eShEntsize)
	shstrOff := readU64(elf, int(shstrE)+24)
	shstrSz := readU64(elf, int(shstrE)+32)
	if shstrOff > uint64(len(elf)) || shstrSz > uint64(len(elf))-shstrOff {
		return nil, 0, errors.New("shstrtab out of bounds")
	}
	shentsize := int(h.eShEntsize)

	// 1. cur_end: SHT 末尾与各段 off+sz 的最大值 (SHT_NOBITS=8 不占文件),
	// 且不小于文件实际长度 (段表之后可能拖着附加数据)
	curEnd := h.eShOff + uint64(h.eShNum)*uint64(shentsize)
	for i := uint16(0); i < h.eShNum; i++ {
		e := h.eShOff + uint64(i)*uint64(shentsize)
		shType := readU32(elf, int(e)+4)
		off := readU64(elf, int(e)+24)
		var sz uint64
		if shType != 8 {
			sz = readU64(elf, int(e)+32)
		}
		if off+sz > curEnd {
			curEnd = off + sz
		}
	}
	if uint64(len(elf)) > curEnd {
		curEnd = uint64(len(elf))
	}
	csOff := int(alignUp(curEnd, pageSize))

	// 2. 新 shstrtab = 旧 + ".codesign\0"
	shstrStart := int(shstrOff)
	newShstr := make([]byte, 0, shstrSz+uint64(len(codesignName)))
	newShstr = append(newShstr, elf[shstrStart:shstrStart+int(shstrSz)]...)
	newShstr = append(newShstr, codesignName...)
	newShstrSz := len(newShstr)
	csShname := uint32(shstrSz) // .codesign 在新 shstrtab 内的偏移

	// 3. 新布局
	newShstrOff := csOff + pageSize
	newShtOff := int(alignUp(uint64(newShstrOff+newShstrSz), 8))
	newShNum := h.eShNum + 1
	newTotal := newShtOff + int(newShNum)*shentsize

	buf := make([]byte, newTotal)
	// 4. 拷贝原内容: 只拷到 cs_off
	copyLen := len(elf)
	if copyLen > newTotal {
		copyLen = newTotal
	}
	if copyLen > csOff {
		copyLen = csOff
	}
	copy(buf, elf[:copyLen])

	copy(buf[newShstrOff:], newShstr)
	shtStart := int(h.eShOff)
	copy(buf[newShtOff:newShtOff+int(h.eShNum)*shentsize], elf[shtStart:shtStart+int(h.eShNum)*shentsize])

	// .codesign 段条目 (前 64B 为标准字段, 超出 64B 的扩展部分保持 0)
	csE := newShtOff + int(h.eShNum)*shentsize
	writeU32(buf, csE, csShname)         // sh_name
	writeU32(buf, csE+4, 1)              // sh_type = SHT_PROGBITS
	writeU64(buf, csE+24, uint64(csOff)) // sh_offset
	writeU64(buf, csE+32, pageSize)      // sh_size
	writeU64(buf, csE+48, pageSize)      // sh_addralign

	// 更新 shstrtab 条目偏移/大小
	shstrENew := newShtOff + int(h.eShStrndx)*shentsize
	writeU64(buf, shstrENew+24, uint64(newShstrOff))
	writeU64(buf, shstrENew+32, uint64(newShstrSz))

	// 更新 header: e_shoff / e_shnum; e_shstrndx 不变
	writeU64(buf, eShOff, uint64(newShtOff))
	writeU16(buf, eShNum, newShNum)

	return buf, csOff, nil
}

// merkleRootHash 计算 fs-verity Merkle 树根哈希, 并顺带暂存中间层哈希.
// 中间层 = 叶层与根所在层之间的所有层, 从低往高逐层把 32B 哈希按顺序
// 拼接 (叶层 <= 4096B 时不存在中间层), 签名时写入 .codesign 段内
// payload 之后.
func merkleRootHash(data []byte, csOff, csLen int) ([32]byte, []byte) {
	if len(data) == 0 {
		return doSha256(make([]byte, pageSize)), nil
	}

	npages := (len(data) + pageSize - 1) / pageSize
	csPageBegin := csOff / pageSize
	csPageEnd := (csOff + csLen + pageSize - 1) / pageSize

	hashes := make([]byte, 0, npages*hashOut)
	for i := 0; i < npages; i++ {
		if csLen > 0 && i >= csPageBegin && i < csPageEnd {
			hashes = append(hashes, make([]byte, hashOut)...) // 段所在页: 叶哈希置 0
			continue
		}
		page := make([]byte, pageSize)
		off := i * pageSize
		n := pageSize
		if off+pageSize > len(data) {
			n = len(data) - off
		}
		copy(page, data[off:off+n])
		sum := doSha256(page)
		hashes = append(hashes, sum[:]...)
	}

	if npages == 1 {
		var root [32]byte
		copy(root[:], hashes[:hashOut])
		return root, nil
	}

	cur := hashes
	var mid []byte // 中间层暂存: 低于根所在层的各层, 从低往高拼接
	for len(cur) > pageSize {
		packed := len(cur)
		nextPages := (packed + pageSize - 1) / pageSize
		next := make([]byte, 0, nextPages*hashOut)
		for i := 0; i < nextPages; i++ {
			page := make([]byte, pageSize)
			off := i * pageSize
			n := pageSize
			if off+pageSize > packed {
				n = packed - off
			}
			copy(page, cur[off:off+n])
			sum := doSha256(page)
			next = append(next, sum[:]...)
		}
		if len(next) > pageSize {
			mid = append(mid, next...) // 根所在层 (packed <= 4096) 不属于中间层
		}
		cur = next
	}
	page := make([]byte, pageSize)
	copy(page, cur)
	return doSha256(page), mid
}

func buildDescriptor(signSize uint32, fileSize uint64, root [32]byte, flags uint32) [descSize]byte {
	var d [descSize]byte
	d[0] = 1  // version
	d[1] = 1  // hashAlgorithm = SHA-256
	d[2] = 12 // log2BlockSize = 2^12 = 4096
	d[3] = 0  // saltSize
	binary.LittleEndian.PutUint32(d[4:8], signSize)
	binary.LittleEndian.PutUint64(d[8:16], fileSize)
	copy(d[16:48], root[:]) // rootHash 左对齐
	binary.LittleEndian.PutUint32(d[112:116], flags)
	d[255] = 3 // csVersion
	return d
}

func signElf(elf []byte, force bool) ([]byte, error) {
	if len(elf) < 64 || elf[0] != 0x7f || elf[1] != 0x45 ||
		elf[2] != 0x4c || elf[3] != 0x46 || elf[4] != 2 {
		return nil, errors.New("not ELF64")
	}

	buf := make([]byte, len(elf))
	copy(buf, elf)
	if hasCodesignSection(buf) {
		if !force {
			return nil, errors.New("already has a .codesign section; strip first or use --force")
		}
		_, stripped, err := stripCodesign(buf)
		if err != nil {
			return nil, err
		}
		buf = stripped
	}

	// 1. 注入 4KB 占位 .codesign 段
	tmp0, csOff, err := injectCodesignSection(buf)
	if err != nil {
		return nil, err
	}
	fileSize := uint64(len(tmp0))

	// 2. merkle 根哈希; mid 为中间层哈希
	root, mid := merkleRootHash(tmp0, csOff, pageSize)

	// 3/4. descriptor(signSize=0) 用于摘要
	descForDigest := buildDescriptor(0, fileSize, root, flagSelfSign)
	// 5. signature = SHA256(descriptor)
	signature := doSha256(descForDigest[:])
	// 6. descriptor(signSize=32) 用于落盘
	descOnDisk := buildDescriptor(32, fileSize, root, flagSelfSign)

	// 7. ElfSignInfo: 8B 头 + descriptor 256B + signature 32B = 296B
	payload := make([]byte, 4+4+descSize+hashOut)
	writeU32(payload, 0, fsVerityDescriptorType)   // type
	writeU32(payload, 4, uint32(descSize+hashOut)) // length = 288
	copy(payload[8:], descOnDisk[:])
	copy(payload[8+descSize:], signature[:])

	// 8. 原地写入段内: payload 之后紧跟中间层哈希, 可用容量
	// 4096-296=3800B, 中间层更长时保留靠叶层一侧的前 3800B
	tmp := tmp0
	copy(tmp[csOff:], payload)
	tail := mid
	if len(tail) > pageSize-len(payload) {
		tail = tail[:pageSize-len(payload)]
	}
	copy(tmp[csOff+len(payload):], tail)
	return tmp, nil
}

// ─────────────────── 只读校验 (--check) ───────────────────

// checkSelfsign 只读校验已有自签名的有效性 (--check 的实现).
//
// 校验项 (全部通过才算有效; 多项不符时按序报告第一个):
//  1. 可解析的 ELF64 (走 parseElfHeader 的全部检查), 存在 .codesign 段,
//     且段内 ElfSignInfo 头 type=1 / length=288
//  2. descriptor 固定字段: version=1, hashAlgorithm=1, log2BlockSize=12,
//     csVersion=3
//  3. signSize=32 且 fileSize=文件实际大小
//  4. 存储的 merkle 根哈希 == 对整个文件重算的根
//  5. 存储的 signature == SHA256(signSize 置 0 后的 descriptor)
//
// 明确不校验 merkle 中间层 (payload 296B 之后的区域): .codesign 段覆盖
// 的页在 merkle 叶层本来就置 0, 篡改中间层不影响根, 此类篡改下本校验
// 仍通过 (预期行为).
//
// 返回 (ok, reason); ok 为 false 时 reason 为原因串 (文案五个实现统一).
func checkSelfsign(elf []byte) (bool, string) {
	// 1a. ELF64 预检 (parse 失败含段表不可用)
	h, err := parseElfHeader(elf)
	if err != nil {
		return false, "not ELF64"
	}

	// 1b. 定位 .codesign 段, 段内至少要容得下 296B payload
	csEntryOff := findSectionByName(elf, h, codesignName)
	if csEntryOff < 0 {
		return false, "no .codesign section"
	}
	csOff := readU64(elf, int(csEntryOff)+24)
	csSize := readU64(elf, int(csEntryOff)+32)
	const payloadLen = 8 + descSize + hashOut
	if csSize < payloadLen || csOff > uint64(len(elf)) || payloadLen > uint64(len(elf))-csOff {
		return false, "bad ElfSignInfo header"
	}

	// 1c. ElfSignInfo 头: type=1, length=288
	if readU32(elf, int(csOff)) != fsVerityDescriptorType ||
		readU32(elf, int(csOff)+4) != uint32(descSize+hashOut) {
		return false, "bad ElfSignInfo header"
	}

	desc := elf[int(csOff)+8 : int(csOff)+8+descSize]
	sig := elf[int(csOff)+8+descSize : int(csOff)+payloadLen]

	// 2. descriptor 固定字段: version/hashAlgorithm/log2BlockSize/csVersion
	if desc[0] != 1 || desc[1] != 1 || desc[2] != 12 || desc[255] != 3 {
		return false, "unsupported descriptor fields"
	}

	// 3. signSize=32 且 fileSize=文件实际大小
	if readU32(desc, 4) != hashOut {
		return false, "signSize mismatch"
	}
	if readU64(desc, 8) != uint64(len(elf)) {
		return false, "fileSize mismatch"
	}

	// 4. merkle 根哈希: 重算整个文件的根 (中间层忽略)
	root, _ := merkleRootHash(elf, int(csOff), pageSize)
	if !bytes.Equal(desc[16:16+hashOut], root[:]) {
		return false, "merkle root mismatch"
	}

	// 5. signature == SHA256(signSize 置 0 后的 descriptor)
	desc0 := make([]byte, descSize)
	copy(desc0, desc)
	for i := 4; i < 8; i++ {
		desc0[i] = 0
	}
	expect := doSha256(desc0)
	if !bytes.Equal(sig, expect[:]) {
		return false, "signature mismatch"
	}

	return true, ""
}

// ─────────────────── 文件 I/O 层 ───────────────────
func signFileAtomic(path string, force bool) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	signed, err := signElf(raw, force)
	if err != nil {
		return err
	}

	var mode os.FileMode = 0
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}

	tmpPath := fmt.Sprintf("%s.ohos-signing.%d.tmp", path, os.Getpid())
	os.Remove(tmpPath)
	if err := os.WriteFile(tmpPath, signed, 0o600); err != nil {
		return err
	}
	if mode != 0 {
		os.Chmod(tmpPath, mode)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

func main() {
	args := os.Args[1:]
	force := false
	stripOnly := false
	checkOnly := false
	var positional []string
	for _, a := range args {
		if a == "--force" || a == "-f" {
			force = true
		} else if a == "--strip" {
			stripOnly = true
		} else if a == "--check" {
			checkOnly = true
		} else {
			positional = append(positional, a)
		}
	}
	// --check 与输出路径/--force/--strip 组合属用法错误
	if len(positional) < 1 || len(positional) > 2 ||
		(checkOnly && (force || stripOnly || len(positional) == 2)) {
		fmt.Fprintf(os.Stderr, "usage: %s <input_elf> [output_elf] [--force] [--strip] [--check]\n  (output defaults to input, in-place)\n", os.Args[0])
		os.Exit(1)
	}
	inPath := positional[0]
	outPath := inPath
	if len(positional) == 2 {
		outPath = positional[1]
	}

	if checkOnly {
		// --check: 只读校验, 不写任何文件
		raw, err := os.ReadFile(inPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		ok, reason := checkSelfsign(raw)
		if ok {
			fmt.Printf("check ok: %s\n", inPath)
			return
		}
		fmt.Fprintf(os.Stderr, "check failed: %s (%s)\n", inPath, reason)
		os.Exit(1)
	}

	if stripOnly {
		raw, err := os.ReadFile(inPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		removed, out, err := stripCodesign(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		if !removed {
			fmt.Printf("no .codesign section to strip: %s\n", inPath)
			return
		}
		if err := os.WriteFile(outPath, out, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("strip ok: %s → %s (%d bytes)\n", inPath, outPath, len(out))
		return
	}

	if inPath == outPath {
		if err := signFileAtomic(inPath, force); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		mode := "append-only"
		if force {
			mode = "force"
		}
		fmt.Printf("selfsign ok: %s (in-place, %s)\n", inPath, mode)
	} else {
		raw, err := os.ReadFile(inPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		signed, err := signElf(raw, force)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		if err := os.WriteFile(outPath, signed, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("selfsign ok: %s → %s (%d bytes)\n", inPath, outPath, len(signed))
	}
}
