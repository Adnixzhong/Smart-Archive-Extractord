# 智能解压工具 (Smart Archive Extractor)

基于 Python + Tkinter 的 GUI 压缩包解压工具，使用 **7-Zip** 作为解压引擎，通过**文件头魔数 (magic bytes)** 智能识别压缩包格式，支持后缀名自动修正、分卷解压、密码字典爆破、GPU 加速密码破解、嵌套压缩包全自动处理。

## 核心功能

- **魔数格式检测** — 读取文件头二进制签名识别真实格式（ZIP/RAR/7z/TAR/GZ/BZ2/XZ/ZST/CAB/ISO/ARJ/LZH/LZ4），不依赖文件后缀名
- **后缀名自动修正** — 检测到错误后缀名时自动重命名为正确后缀，分卷文件（.001/.r00/.part1.rar）不会被误改名
- **分卷解压** — 自动识别并合并 .part1.rar / .r00 / .zip.001 / .7z.001 等分卷压缩包
- **密码字典** — 多行批量粘贴密码，自动去重持久化，按文件类型自动选择存储路径
- **密码破解** — CPU 多进程暴力破解 + GPU 加速 (hashcat)，支持暴力/字典/掩码/规则叠加
- **智能嵌套解压** — 解压后自动检测嵌套结构，单个包裹自动解压、复杂结构自动扫描
- **双面板文件列表** — 左侧「待解压」+ 右侧「已解压」，右键设置密码、还原已解压文件
- **解压后处理** — 保留 / 回收站 / 删除 三种模式，解压完成自动打开文件夹
- **回收站还原** — 扫描 Windows `$Recycle.Bin` 精准找回，支持批量还原
- **Windows 原生拖放** — 支持从资源管理器直接拖入文件/文件夹
- **2 套暗色主题** — slate / midnight，一键切换
- **零控制台闪烁** — 所有 subprocess 调用在后台静默执行，`main.pyw` 无控制台启动

## 支持的格式

| 格式 | 后缀名 | 魔数 |
|------|--------|------|
| ZIP | .zip | `PK\x03\x04` |
| RAR (v4/v5) | .rar | `Rar!\x1a\x07` |
| 7-Zip | .7z | `7z\xbc\xaf\x27\x1c` |
| GZIP | .gz / .gzip | `\x1f\x8b\x08` |
| BZIP2 | .bz2 / .bzip2 | `BZh` |
| XZ | .xz | `\xfd7zXZ\x00` |
| Zstandard | .zst / .zstd | `\x28\xb5\x2f\xfd` |
| LZ4 | .lz4 | `\x04\x22\x4d\x18` |
| TAR | .tar | `ustar` @ offset 257 |
| tar.gz / tgz | .tar.gz / .tgz | GZIP + 内层 TAR |
| tar.bz2 / tbz2 | .tar.bz2 / .tbz2 | BZIP2 + 内层 TAR |
| tar.xz / txz | .tar.xz / .txz | XZ + 内层 TAR |
| tar.zst | .tar.zst | ZST + 内层 TAR |
| CAB | .cab | `MSCF` |
| ISO 9660 | .iso | `CD001` @ offset 32769/34817/36865 |
| ARJ | .arj | `\x60\xea` |
| LZH/LHA | .lzh / .lha | `\x1f\xa0` / `\x1f\x9d` |

### 分卷格式

| 模式 | 示例 |
|------|------|
| `.partN.rar` | archive.part1.rar, archive.part2.rar |
| `.rNN` | archive.r00, archive.r01, archive.rar |
| `.ext.NNN` | archive.zip.001, archive.7z.001, archive.tgz.001 |
| `.NNN` | archive.001, archive.002 |

## 安装与运行

### 源码运行

**依赖**
- **Python 3.9+**（3.8 不支持 `list[str]` 语法）
- **7-Zip** — 需安装并确保 `7z.exe` 在 PATH 中，或安装到 `C:\Program Files\7-Zip\`
- **windnd** — Windows 原生拖放支持

```bash
git clone https://github.com/Adnixzhong/Smart-Archive-Extractord.git
cd Smart-Archive-Extractord
pip install windnd
python main.py       # 控制台启动（调试用）
# 或双击 main.pyw    # 无控制台启动（推荐）
```

### 预打包版本（GitHub Releases）

从 [Releases](https://github.com/Adnixzhong/Smart-Archive-Extractord/releases) 下载：

| 版本 | 大小 | 说明 |
|------|------|------|
| `Smart Archive Extractor (PyInstaller).exe` | ~10 MB | PyInstaller 单文件，分发最方便 |
| `Smart Archive Extractor (Nuitka).exe` | ~22 MB | Nuitka 单文件，C 编译，启动较快 |
| `Smart Archive Extractor (Nuitka 便携版).zip` | ~8 MB | Nuitka 文件夹版，解压即用，启动最快 |

### 自行打包

```bash
# PyInstaller
pip install PyInstaller
pyinstaller --onefile --windowed --name "Smart Archive Extractor" main.py

# Nuitka 单文件
pip install nuitka
python -m nuitka --onefile --windows-console-mode=disable --enable-plugin=tk-inter main.py

# Nuitka 便携版
python -m nuitka --standalone --windows-console-mode=disable --enable-plugin=tk-inter main.py
```

> 打包后的 EXE 仍需目标机器安装 7-Zip。

### 密码文件存储路径

| 版本类型 | 路径 |
|---------|------|
| 单文件版 (PyInstaller / Nuitka onefile) | `%APPDATA%\Smart Archive Extractor\passwords.txt` |
| Nuitka 便携版 (standalone) | exe 同目录 `passwords.txt` |
| 源码版 | 项目根目录 `passwords.txt` |

## 使用说明

1. **添加文件** — 点击「添加文件」/「添加文件夹」，或从资源管理器直接拖入
2. **设置输出目录** — 默认为第一个文件所在目录，可选自定义路径
3. **配置密码** — 点击「编辑」打开密码库，支持多行批量粘贴；或右键文件列表单独设置密码
4. **解压** — 选中待解压文件，点击「开始解压」

### 密码优先级

对于每个文件，按以下顺序尝试密码：

1. 文件级别「指定密码」（右键 → 设置密码）
2. 无密码尝试
3. 密码字典（跳过已尝试和上级密码）

嵌套压缩包会优先继承上级密码（通常同一套密码）。

### 解压流程

```
检测格式 → 识别分卷 → 修正后缀名 → 解压 → 智能嵌套检测 → 展平空壳目录 → 清理
```

## 密码破解

密码破解模块提供 CPU 和 GPU 两种攻击方式，适用于忘记密码的加密压缩包。

### 攻击方式

| 方式 | 说明 |
|------|------|
| 暴力破解 | 按字符集和长度范围穷举所有组合 |
| 字典攻击 | 加载外部密码字典文件，可叠加规则变形 |
| 掩码攻击 | 按模式生成（`?` 替换为字符集字符，如 `???2024`） |
| 规则叠加 | 对字典词进行大小写、leet、数字/符号、反转、重复等变换 |

### GPU 环境配置

1. 安装 [hashcat](https://hashcat.net/hashcat/) — 或点击破解对话框中的「下载工具...」自动安装
2. 安装 John the Ripper 工具 (rar2john / 7z2john) — 同上，一键下载到 `%APPDATA%\Smart Archive Extractor\tools\`

首次使用 GPU 模式时程序会自动提示下载缺失的工具。

### 技术原理

```
加密压缩包 → extract_hash() → 哈希字符串 → hashcat → 密码
              │                              │
              ├─ ZIP: 纯 Python 读取          ├─ 模式 11600 (7z)
              │   ZipCrypto 加密头             ├─ 模式 13000 (RAR5)
              ├─ RAR: rar2john 提取            ├─ 模式 17200 (ZipCrypto)
              └─ 7z:  7z2john 提取             └─ 模式 17210 (ZipCrypto Store)
```

> 详细技术问题与修复记录见 [docs/GPU-CRACK-TECHNICAL-NOTES.md](docs/GPU-CRACK-TECHNICAL-NOTES.md)

## 项目结构

```
smart-archive-extractor/
├── main.py                  # 入口（控制台）
├── main.pyw                 # 入口（无控制台）
├── passwords.txt            # 密码字典（源码版）
├── core/
│   ├── signatures.py        # 魔数签名数据库
│   ├── detector.py          # 格式检测（含 tar.gz 组合检测）
│   ├── split_detector.py    # 分卷压缩包识别与卷查找
│   ├── renamer.py           # 后缀名自动修正
│   ├── extractor.py         # 7-Zip 解压封装 + 密码验证
│   ├── password.py          # 密码管理与持久化
│   ├── cracker.py           # CPU 密码破解引擎（多进程）
│   ├── hash_extractor.py    # 哈希提取 (ZIP纯Python / RAR+7z via John)
│   ├── hashcat.py           # hashcat GPU 子进程封装
│   └── tool_manager.py      # 外部工具检测与一键下载
└── ui/
    ├── app.py               # Tkinter GUI 主程序
    └── crack_dialog.py      # 密码破解配置与进度 UI
```

### 模块职责

| 模块 | 职责 |
|------|------|
| `signatures.py` | `FormatInfo` 数据类和 `SIGNATURES` 魔数列表（ISO/TAR 含特殊偏移量） |
| `detector.py` | `detect()` 读取文件头 512 字节匹配魔数；`detect_with_tar_combo()` 识别 GZ/BZ2/XZ/ZST 内 TAR 组合 |
| `split_detector.py` | 正则匹配分卷模式，`find_volumes()` 返回完整卷列表 |
| `renamer.py` | `needs_rename()` / `get_correct_path()` — 分卷文件跳过，普通文件修正后缀 |
| `extractor.py` | `find_7z()` 搜索 7z.exe；`extract()` subprocess 调用 7z 并解析进度；`scan_for_archives()` 递归扫描 |
| `password.py` | `PasswordManager` 管理密码库，支持去重、增删、导入导出、路径感知持久化 |
| `cracker.py` | CPU 破解引擎：暴力/字典/掩码/规则生成器，ZIP 多进程并行，RAR/7z 子进程验证 |
| `hash_extractor.py` | 从加密压缩包提取哈希：ZIP ZipCrypto (纯 Python)、RAR5 (rar2john)、7z (7z2john) |
| `hashcat.py` | hashcat GPU 子进程封装：命令行构建、--status 输出解析 (速度/温度/进度/ETA)、取消控制 |
| `tool_manager.py` | 外部工具 (hashcat/rar2john/7z2john) 检测与一键下载 |
| `ui/app.py` | 完整 GUI：双面板文件列表、选项面板、日志、进度条、拖放、智能嵌套检测 |
| `ui/crack_dialog.py` | 密码破解对话框：攻击类型选择、字符集/字典/掩码配置、GPU 开关、实时进度 |

## 技术要点

### 魔数检测

读取文件前 512 字节，从 SIGNATURES 列表按顺序匹配。TAR 检测在 offset 257 处查找 `ustar`。ISO 9660 在 offset 32769/34817/36865 处查找 `CD001`。

### 分卷处理

不解压单个分卷 — 识别所有卷后将第一个卷路径传给 7-Zip，7-Zip 自动读取其余卷。

### 后缀名修正

取文件名，移除所有已知压缩包后缀（`.tar.gz`、`.zip`、`.rar` 等），移除 `.partN` 后缀，附加检测到的正确后缀。分卷文件（`.001`、`.r00`、`.part1.rar`）跳过不处理。

### 嵌套解压

解压完成后检查输出目录结构：
- 仅含 1 个文件夹且该文件夹内仅 1 个文件 → 若该文件是压缩包则自动解压（继承上级密码）
- 含多个文件/文件夹 → 自动扫描并递归解压所有内部压缩包
- 自动展平单层包装目录，清理残留

## License

MIT

### 第三方工具

本项目的 GPU 加速功能通过子进程调用以下第三方工具（不分发二进制文件）：

- **[hashcat](https://hashcat.net/hashcat/)** — [MIT License](https://github.com/hashcat/hashcat/blob/master/docs/license.txt)
- **[John the Ripper](https://www.openwall.com/john/)** (rar2john, 7z2john) — [GPLv2+](https://github.com/openwall/john/blob/main/doc/LICENSE)

子进程调用属于 "mere aggregation"，不构成衍生作品，不触发 GPL copyleft 条款。
