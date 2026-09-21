# 我们的实现 vs 上游 v3.1.0 — 代码差异对比（2026-09-21）

> **状态（2026-09-21）：上游 v3.1.0 已覆盖全部四项修复**
> （`2751f8d` 尾部数据 / `e0b75d0` e_shentsize / `b526139` merkle 中间层 /
> `eee7eaf` --check）。本报告作为对比记录**保留，以后不再修改**；相关分支
> （`fix/ports-…`、`fix/rust-…`、`feat/merkle-tree-bytes`、`feat/validity-check`）
> 随之归档，不再继续开发。
>
> 归档前的两个小问题已修复：
> - `feat/merkle-tree-bytes` JS 模块导出（`require()` 抛 ReferenceError）→
>   `a4683e0`：导出改为 `merkleRootHashAndTree`，`require()`/CLI 均正常；
> - `fix/ports-…` 的 `selfsign.py`/`selfsign.js` 可执行位回退（100755→100644）→
>   `058ed03`：已恢复 100755（内容不变）。
>
> 另外的差异（`--check` 原因串/参数组合校验、README 同步等）**不跟进**，
> 因为上游实现已包含这些改进。

**前提**：4 项修复的功能验证全部通过，且 5 个语言、3 类输入（普通/尾部数据/
e_shentsize=128）、101MB merkle 用例的输出与我们的参考实现**逐字节一致**。
因此以下差异均为实现风格、API 形态与诊断质量层面，不影响产物。

对比对象：
- 我们：`fix/ports-trailing-data-and-entsize`、`fix/rust-trailing-data-and-entsize`、
  `feat/merkle-tree-bytes`、`feat/validity-check`
- 上游：`2751f8d`（尾部）、`e0b75d0`（e_shentsize）、`b526139`（merkle）、
  `eee7eaf`（--check），即 v3.1.0

原始补丁（可复现）：`/data/storage/el2/base/tmp/opencode/code-compare/*.diff`

## 1. 尾部数据 + e_shentsize（上游 `2751f8d`+`e0b75d0`）

核心相同：`e_shentsize >= 64` 合法、所有 SHT 遍历/越界校验/strip 重建按实际
条目大小步进；`cur_end` 纳入文件真实长度；strip 按原条目大小保留。

| 维度 | 我们 | 上游 |
|------|------|------|
| 解析返回值顺序 | `(e_shoff, e_shnum, e_shstrndx, e_shentsize)`（追加在末尾） | `(e_shoff, e_shentsize, e_shnum, e_shstrndx)`（紧跟 e_shoff） |
| Go 段查找 | `findSectionByName(elf, eShOff, eShNum, eShStrndx, eShEntsize, name)` 逐参传 | `findSectionByName(elf, h, name)` 传 `elfHeader` 结构体（更整洁） |
| 尾部修正写法 | py/rs/js 用 `max` / `.max()` / `Math.max` | 全部 `if (len > cur_end)` 比较（C/Go 双方本就一致） |
| 注释/文档 | 较简 | 更详尽：ELF64 扩展字段说明、strip "条目不压缩"、cs 条目超 64B 部分保持 0 |
| **文件权限位** | `fix/ports` 把 `selfsign.py`、`selfsign.js` 由 `100755` 改成 `100644`（丢可执行位） | 保持 `100755` |

其余（C/Go/JS/Rust 的注入、剥离、对齐逻辑）结构基本一一对应。

## 2. merkle 中间层（上游 `b526139`）

核心相同：中间层 = 叶层与根所在层之间的各层，低→高拼接；写入 payload 之后，
容量 `4096-296=3800B`，超出时保留靠叶层一侧的前缀。

| 维度 | 我们 | 上游 |
|------|------|------|
| 函数命名 | 改名 `merkle_root_hash_and_tree` / `merkleRootHashAndTree` | 保留原名 `merkle_root_hash` / `merkleRootHash`，仅扩展返回值 |
| 返回形态 | py/rs tuple、go tuple、js `{root, tree}`、C 出参 `tree_out/tree_len` | py/go tuple、js `{root, mid}`、rs tuple、C 出参 `mid/mid_len` |
| 聚合方式 | 收集 `levels` 列表，取 `levels[1:-1]` | 运行缓冲：`if len(nxt) > PAGE_SIZE: mid += nxt` |
| JS 模块导出 | **缺陷**：改名后 `module.exports` 仍引用 `merkleRootHash` → `require()` 抛 `ReferenceError`（CLI 不受影响，`process.exit(main())` 在 exports 之前）；未导出新名 | `merkleRootHash` 保持导出，新增 `checkSelfsign` 导出，`require()` 正常 |
| 注释 | 说明中间层定义 | 额外说明"根所在层不属于中间层" |

## 3. --check（上游 `eee7eaf`）

检查项集合与顺序等价（ElfSignInfo 头 → descriptor 固定字段 → signSize/fileSize
→ merkle 根 → signature）。

| 维度 | 我们 | 上游 |
|------|------|------|
| 函数/API | `is_validly_signed` / `isValidlySigned`，返回 bool | `check_selfsign` / `checkSelfsign`：py/go `(bool, reason)`、js `{ok, reason}`、C `int + const char **reason`、Rust `Result<(), &'static str>` |
| CLI 参数组合 | 未校验：`--check` 可与输出路径/`--force`/`--strip` 同用（忽略之） | `--check` + 输出路径/`--force`/`--strip` 判为用法错误（usage + exit 1），5 个实现一致 |
| 输出 | 成功 stdout：`check ok: <path> (valid self-sign, N bytes)`；失败 stdout：`check failed: ... (not a valid self-sign ELF)` | 成功 `check ok: <path>`；失败 **stderr** 并带**原因串**（not ELF64 / no .codesign section / bad ElfSignInfo header / unsupported descriptor fields / signSize mismatch / fileSize mismatch / merkle root mismatch / signature mismatch，五实现统一） |
| 文档 | 列出校验项 | 额外显式声明"不校验 merkle 中间层（内核只验根哈希）" |
| JS 导出 | 未导出 `isValidlySigned` | 导出 `checkSelfsign`（`(elf) => {ok, reason}`） |

## 4. 组织/合并形态

- 我们：4 个独立分支、各自基于 `main`，未合并；`feat/validity-check` 调用的是
  旧签名的 `merkle_root_hash`（与 `feat/merkle-tree-bytes` 有耦合，合并需适配）。
- 上游：4 个线性提交，`--check` 与 merkle 的调用已就地协调（`PAGE_SIZE` 入参）；
- 上游同时更新了 `README.md`（用法表 + `--check` 示例）与文件头说明；我们的分支
  未更新 README。

## 5. 结论与可改进点

- **行为等价**：所有产物逐字节一致，未发现语义差异（除下面两个实现缺陷）。
- 归档前已修复：
  1. `feat/merkle-tree-bytes` 的 **JS 导出缺陷** → `a4683e0`
     （`module.exports` 改为 `merkleRootHashAndTree`，`require()` 正常）；
  2. `fix/ports` 的 **100755 → 100644** 权限位回退 → `058ed03`（已恢复）。
- 明确不跟进（上游 v3.1.0 已覆盖）：`--check` 原因串与参数组合校验、
  "不校验中间层"文档说明、README 同步；本 fork 的这些分支就此归档。
- 上游比我们更好的点：诊断信息（原因串）、CLI 防御（组合校验）、Go 结构体传参、
  JS 模块 API 导出。
