# GPU 密码破解 — 技术问题与修复记录

## 问题总览

| # | 问题 | 影响 | 修复 |
|---|------|------|------|
| 1 | NVML 风扇速度警告被误报为错误 | hashcat 正常运行时显示误导错误信息 | 添加 NVML/ADL 行前缀过滤 |
| 2 | Bandizip ZIP 与 hashcat 不兼容 | GPU 模式无法破解 Bandizip 创建的 ZipCrypto ZIP | 检测 + GPU 前后警告，引导用户改用 CPU |
| 3 | CS 字段使用 raw byte 而非 CRC 值 | 无实际影响（hashcat 自身校验逻辑独立） | 记录说明，无需修改 |
| 4 | threading 受 GIL 限制 | ZIP CPU 破解多线程无加速 | 改为 multiprocessing |
| 5 | zip2john 是否必需 | 不需要（纯 Python 实现已覆盖） | 记录说明 |

### 系统环境

- hashcat v6.2.6
- GPU: NVIDIA GeForce RTX 3060 Laptop (OpenCL API)
- 速度: ~109 MH/s (mode 17200, mask attack)
- NVML: 不支持风扇速度查询（笔记本 GPU 限制）
- CUDA SDK: 未安装（hashcat 回退 OpenCL，不影响性能）

### 涉及文件

| 文件 | 修改内容 |
|------|---------|
| `core/hashcat.py` | NVML/ADL 警告过滤；改进 `_check_error()` |
| `core/hash_extractor.py` | 新增 Bandizip 兼容性检测函数 |
| `ui/crack_dialog.py` | GPU 前后 Bandizip 检测与警告 UI |
| `core/cracker.py` | ZIP 暴力破解改用 multiprocessing |

---

## 问题 1 — NVML 风扇速度警告误报

### 现象

```
stderr: nvmlDeviceGetFanSpeed(): Not Supported
```

hashcat 尝试通过 NVML 读取 GPU 风扇速度，部分硬件（笔记本、WSL、新版驱动）不支持此功能。

### 根因

`core/hashcat.py` 的 `_check_error()` 包含 `("not supported", "不支持的哈希类型")` 匹配项，将 NVML 的 "Not Supported" 误判为哈希类型错误。

### 修复

1. 移除 `"not supported"` 通用匹配（它匹配 NVML 警告而非哈希错误）
2. 添加 `_NVML_ADL_PREFIXES = ("nvml", "ADL", "NVML")` 前缀过滤
3. `_check_error()` 跳过所有以 NVML/ADL 开头的行（硬件监控警告，不影响计算）

NVML 风扇速度读取失败**不影响** hashcat 的破解能力 — OpenCL/CUDA 计算路径独立于 NVML 监控。

---

## 问题 2 — Bandizip ZIP 与 hashcat 不兼容

### 现象

hashcat mode 17200 (PKZIP Compressed) 无法破解 Bandizip 创建的 ZipCrypto 加密 ZIP，即使提供正确密码也报告 `Status: Exhausted`。

### 根因

标准 PKZIP ZipCrypto 解密后 byte 11 应等于 CRC32 MSB：

```
decrypted_header[11] == CRC32 >> 24
```

hashcat 以此作为 early-reject 校验依据。但 **Bandizip 使用时间戳校验和代替 CRC**：

```
decrypted_header[11] == (timestamp_checksum >> 24) & 0xFF
```

验证机制不同导致 hashcat 即使解密正确也无法匹配。

### 验证过程

测试 `passwords.zip` (Bandizip 创建，密码 `123asd`)：

| 工具 | 结果 |
|------|------|
| Python zipfile | 成功解密 |
| hashcat mode 17200 | Exhausted（全部候选密码尝试完毕，均不匹配） |

```
enc_header:  ab90757c380554bf088076f0
decrypted:   c02fe1890bd4167333d1bc7b
check_byte:  0x7b
CRC32 MSB:   0xa9  ← 不匹配
timestamp upper 16: 0x7bbc ← 匹配 byte 10-11
```

### 影响范围

- 所有 Bandizip ZipCrypto 加密 ZIP（hashcat mode 17200/17210/17220/17225/17230 均受影响）
- Bandizip AES-256 (WinZip AES) **不受**影响（不同 hashcat mode）
- 7-Zip / WinRAR 创建的 ZipCrypto ZIP **不受**影响

### 修复方案

三层防御：

1. **检测** — `hash_extractor.py` 新增 `is_zip_bandizip_incompatible()` 通过 local header flag bit 1 判断
2. **GPU 启动前** — `crack_dialog.py` 弹出警告对话框，不阻止继续但告知风险
3. **GPU 失败后** — 再次检测并提示用户改用 CPU 模式

### 替代方案

| 方案 | 速度 | 说明 |
|------|------|------|
| CPU 模式 (7z t) | ~10-100/s | 正确验证所有 ZIP 变体 |
| CPU 模式 (Python zipfile) | ~1,000/s | 纯 Python，更快但仅限 ZIP |
| 用 7-Zip 重新打包 | — | 创建标准 ZipCrypto ZIP 后可用 GPU |

---

## 问题 3 — CS 字段使用 raw encrypted byte

### 根因

`hash_extractor.py` 的 `_extract_zipcrypto_hash()` 使用原始加密字节的重复值作为 CS 字段：

```python
check_byte = enc_data[11]
cs = f"{check_byte:02x}{check_byte:02x}"
```

标准做法应使用 CRC 相关值，但 hashcat 解密后与 CRC MSB 比较，与 CS 原始值无关，故此问题**不影响**标准 ZIP 破解。Bandizip 兼容性问题的根因是 hashcat 验证逻辑本身，非 CS 字段。

---

## 问题 4 — threading 受 GIL 限制导致多线程无效

### 根因

Python GIL 阻止多线程同时执行 Python 字节码。ZipCrypto 解密是纯 Python 实现，zlib 解压虽释放 GIL 但解密占主要耗时，导致 `threading.Thread` 无法利用多核：

| 线程数 | 速度 |
|--------|------|
| 1 | 32,000/s |
| 4 | 32,000/s（无提升） |

### 修复

ZIP 暴力破解改用 `multiprocessing`：

- 新增模块级函数 `_zip_mp_worker()` — 每进程独立 ZipFile + BruteForceGenerator
- `CrackSession` 新增 `_run_zip_bruteforce_mp()` — 多进程协调、进度报告、取消控制
- 每进程通过 `offset` / `stride` 分片 keyspace，无需进程间通信

### 性能对比

| 方案 | 速度 | 36^6 字符集预估 |
|------|------|-----------------|
| threading（旧） | 32,000/s | ~19 小时 |
| multiprocessing 4 进程 | 64,000/s | ~9.4 小时 |
| multiprocessing 6-8 进程 | ~70,000/s | **~8.7 小时** |

> 进程数超过 10 后性能下降（笔记本 CPU 功耗/散热限制）。

### 影响范围

- ZIP 暴力破解：multiprocessing
- ZIP 字典/掩码：保持 threading（字典规模小，GIL 影响不明显）
- RAR/7z：保持 threading（7z 子进程释放 GIL）

---

## 问题 5 — zip2john 是否需要安装

**不需要。** 本项目 ZIP 哈希提取为纯 Python 实现（`hash_extractor.py`），不依赖 zip2john。zip2john 提取的哈希格式与 hashcat 验证逻辑同样基于 CRC-MSB 校验，对 Bandizip ZIP 同样无效。
