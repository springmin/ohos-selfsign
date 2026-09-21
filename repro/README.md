# ohos-selfsign 复现集

用于复现三个问题（对应本 fork 的改动）：

1. **尾部数据被丢弃** —— 段表之后的数据（Bun standalone 的 module graph、
   .NET SingleFile bundle 等布局）被静默截断。
2. **e_shentsize 硬编码 64** —— `e_shentsize=128` 的合法 ELF 被拒绝，
   而官方 `binary-sign-tool` 接受并签名。
3. **.codesign 段缺少 merkle 树中间层哈希** —— payload 之后本应写入
   树中间层字节的区域全为 0，与官方工具产物不一致。

## 文件

| 文件 | 说明 |
|------|------|
| `fixtures/base.elf` | 23944 B 的普通 ELF64，段表在文件末尾（e_shentsize=64） |
| `fixtures/trail.elf` | `base.elf` + 20480 B 尾部序列 = 44424 B |
| `fixtures/entsize128.elf` | `base.elf` 的段表条目 64 B → 128 B = 26376 B |
| `mkfixtures.py` | 从任意 ELF64 生成上述两个 fixture：`python3 mkfixtures.py <base.elf> <outdir>` |
| `run_repro.sh` | 用指定实现跑三个 fixture：`sh run_repro.sh "python3 selfsign.py"` |
| `codesign_dump.py` | 打印 `.codesign` 段布局（type/length/signSize/fileSize/payload md5/尾部非零字节） |
| `verify_merkle_tail.py` | 复算 merkle 根与中间层哈希，校验 `.codesign` 尾部字节 |
| `node/node-codesign.bin` | 官方产物实例（Harmonybrew node 26.8.1）的 4 KiB `.codesign` 段 |
| `node/node-codesign.tail.bin` | 上述产物 payload 之后的 3800 B（3791 B 非零） |
| `node/node-info.txt` | 该产物的大小/哈希/descriptor 字段 |

## 用法

```sh
# 实现：把 "python3 selfsign.py" 换成任一实现
sh run_repro.sh "python3 /path/to/main/selfsign.py"

# 单个复现
python3 /path/to/selfsign.py fixtures/trail.elf /tmp/trail.out   # 观察输出大小/尾部
python3 /path/to/selfsign.py fixtures/entsize128.elf /tmp/e.out  # 观察退出码与 stderr
python3 codesign_dump.py /tmp/e.out

# merkle 尾字节：对任意大 ELF（段覆盖大部分文件，例如 > 50MB 的可执行文件）
python3 /path/to/selfsign.py big.elf big.signed
python3 verify_merkle_tail.py big.signed     # main：stored 全 0、expected 非 0 → MISMATCH
```

## 实测基准（2026-09-21，aarch64 OpenHarmony）

`fixtures/base.elf = 23944 B`，`md5 1b8b8d873442833c4722ce0f5ef52860`

| 输入 | main（5 实现一致） | 修复后（5 实现一致） |
|------|--------------------|----------------------|
| `base.elf` | 31560 B `9cb2d9a33cbd38c545456b72aa57b1c0` | 31560 B `9cb2d9a33cbd38c545456b72aa57b1c0` |
| `trail.elf` | 31560 B `fba78c120762da500c18d200b1d20866`（尾部只剩前 632 B） | 52040 B `56af266153c62abf6370c59635fdb2d7`（完整 20480 B） |
| `entsize128.elf` | 退出码 2，`error: ELF has no usable section header table` | 38152 B `30db78f637fdc100665c46cb375fd285`（e_shentsize=128 保留） |

官方 `binary-sign-tool`（SDK 26.0.0.18）对照：

- `trail.elf` → 31168 B（尾部同样被丢弃；本项请求是“不要静默截断”，不追求与官方逐字节一致）
- `entsize128.elf` → 33600 B，`add codesign section success`，输出保持 `e_shentsize=128`；
  `display-sign` 可识别为 `self-sign`。

## 复现结果判读

- `trail`：输出应保留完整 20480 B 尾部（`trailer: PRESENT`）；main 会丢失
  （输出尺寸与签 `base.elf` 相同，仅保留尾部前 632 B）。
- `entsize128`：应签名成功且保留 `e_shentsize=128`；main 退出码 2、无输出。
- `base`：main 与修复后的输出必须逐字节相同（无回归）。
- merkle：`verify_merkle_tail.py` 对官方 node 产物应输出 root/tail 双 `MATCH`；
  对 main 签出的大文件 tail 全 0 → `MISMATCH`；修复后应 `MATCH`。
