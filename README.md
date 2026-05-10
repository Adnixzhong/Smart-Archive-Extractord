# Smart Archive Extractor v2.0.1

基于 Python 3.13 + Tkinter 的 GUI 压缩包解压工具。以 **7-Zip** 为解压引擎，通过**文件头魔数 (magic bytes)** 智能识别格式，支持后缀名自动修正、分卷解压、密码字典管理、CPU 多线程密码破解、嵌套压缩包全自动处理。

## 核心功能

- **魔数格式检测** — 读取文件头二进制签名识别真实格式（ZIP/RAR/7z/TAR/GZ/BZ2/XZ/ZST/CAB/ISO/ARJ/LZH/LZ4），不依赖文件后缀名
- **后缀名自动修正** — 检测到错误后缀名时自动重命名为正确后缀，分卷文件不会被误改名
- **分卷解压** — 自动识别并合并 .part1.rar / .r00 / .zip.001 / .7z.001 等分卷
- **密码字典** — 多行批量粘贴密码，自动去重持久化，支持自定义路径
- **密码破解** — CPU 多线程破解引擎，支持暴力/字典/掩码/规则叠加，ZIP 多进程分片
- **智能嵌套解压** — 解压后自动检测嵌套结构，单个包裹自动解压、复杂结构自动扫描
- **解压后处理** — 保留 / 回收站 / 删除三种模式，解压完成自动打开文件夹

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
| `.ext.NNN` | archive.zip.001, archive.7z.001 |
| `.NNN` | archive.001, archive.002 |

## 安装与运行

### 依赖

- **Python 3.9+**（推荐 3.13）
- **7-Zip** — 安装到 `C:\Program Files\7-Zip\` 或确保 `7z.exe` 在 PATH 中
- **windnd** — Windows 拖放支持

```bash
git clone https://github.com/Adnixzhong/Smart-Archive-Extractord.git
cd Smart-Archive-Extractord
pip install windnd
python main.py       # 控制台启动
# 或双击 main.pyw    # 无控制台启动
```

### 预打包版本（GitHub Releases）

从 [Releases](https://github.com/Adnixzhong/Smart-Archive-Extractord/releases) 下载：

| 版本 | 文件 | 大小 | 说明 |
|------|------|------|------|
| 单文件版 | `SmartArchiveExtractor-Nuitka.exe` | ~37 MB | Nuitka C 编译单文件，启动快，密码库和配置在 `%APPDATA%` |
| 便携版 | `SmartArchiveExtractor-Nuitka-Portable.zip` | ~15 MB | Nuitka C 编译，解压即用，密码库和配置在 EXE 同目录 |

> 打包版本仍需目标机器安装 7-Zip。

### 自行打包

```bash
pip install nuitka

# 单文件版
python -m nuitka --onefile --windows-console-mode=disable --enable-plugin=tk-inter main.py

# 便携版
python -m nuitka --standalone --windows-console-mode=disable --enable-plugin=tk-inter main.py
# 将 main.dist/ 整个文件夹打包即可
```

## 密码破解

### 攻击方式

| 方式 | 说明 |
|------|------|
| 暴力破解 | 按字符集和长度范围穷举所有组合 |
| 字典攻击 | 加载外部密码字典文件，可叠加规则变形和掩码组合 |
| 掩码攻击 | 按模式生成（`?` 替换为字符集字符，如 `???2024`） |

### 规则叠加（字典模式）

对字典词进行额外变换：大小写转换、首字母大写、Leet 替换 (a→4, e→3...)、末尾/开头追加数字或符号、反转、重复。

### 字符集预设

| 预设 | 字符 |
|------|------|
| 数字 (0-9) | 0123456789 |
| 小写字母 | abcdefghijklmnopqrstuvwxyz |
| 大写字母 | ABCDEFGHIJKLMNOPQRSTUVWXYZ |
| 数字+小写 | 0-9 + a-z |
| 数字+大小写 | 0-9 + a-z + A-Z |
| 所有可打印 | ASCII 32-126 |

## 密码优先级

解压时按以下顺序尝试密码：

1. 文件级别「指定密码」（右键 → 设置密码）
2. 无密码尝试
3. 密码字典（跳过已尝试和上级密码）

嵌套压缩包优先继承上级密码。

## 项目结构

```
SmartArchiveExtractor-Crack/
├── main.py                    # 入口（控制台）
├── main.pyw                   # 入口（无控制台）
├── passwords.txt              # 密码字典
├── core/
│   ├── __init__.py            # subprocess_kwargs() 工具函数
│   ├── signatures.py          # 魔数签名数据库
│   ├── detector.py            # 格式检测（含 tar.gz 组合检测）
│   ├── split_detector.py      # 分卷压缩包识别
│   ├── renamer.py             # 后缀名自动修正
│   ├── extractor.py           # 7-Zip 解压封装 + 密码验证
│   ├── password.py            # 密码管理与持久化
│   └── cracker.py             # CPU 密码破解引擎
└── ui/
    ├── __init__.py
    ├── app.py                 # GUI 主程序
    └── crack_dialog.py        # 密码破解配置与进度对话框
```

### 模块职责

| 模块 | 职责 |
|------|------|
| `signatures.py` | `FormatInfo` 数据类和 `SIGNATURES` 魔数列表 |
| `detector.py` | `detect()` 读取前 512 字节匹配魔数；`detect_with_tar_combo()` 识别 tar.gz 等组合 |
| `split_detector.py` | 正则匹配分卷模式，`find_volumes()` 返回完整卷列表 |
| `renamer.py` | `needs_rename()` / `get_correct_path()` 后缀修正 |
| `extractor.py` | `find_7z()` 搜索 7z.exe；`extract()` 调用 7z 解析进度；`verify_password()` 用 7z test 验证 |
| `password.py` | `PasswordManager` 管理密码库：去重、增删、持久化 |
| `cracker.py` | CPU 破解引擎：5 种密码生成器 + producer-consumer 多线程 + ZIP 多进程分片 |
| `ui/app.py` | 完整 GUI：双面板文件列表、选项面板、日志、进度条、拖放、嵌套检测 |
| `ui/crack_dialog.py` | 密码破解对话框：攻击类型选择、字符集/字典/掩码配置、实时进度 |

## 技术要点

### 破解引擎架构（cracker.py）

```
CrackSession.run()
  ├─ ZIP 暴力破解 → multiprocessing.Process × N
  │   └─ Worker: offset/stride 分片 → zipfile 快检 → 7z t 确认
  └─ 其他模式 → producer-consumer 线程
      ├─ Producer: PasswordGenerator.next_batch() → queue.Queue
      └─ Consumers × N: queue.get() → verify_password() / _try_zip_read()
```

密码生成器（均实现 `PasswordGenerator` ABC）：
- `BruteForceGenerator` — 笛卡尔积穷举，支持 offset/stride 分片
- `DictionaryGenerator` — 流式读取密码字典文件
- `MaskGenerator` — 模式生成（? 替换为字符集字符，最多 12 个通配符）
- `RuleBasedGenerator` — 对基础词应用大小写/leet/数字符号/反转/重复等规则
- `HybridGenerator` — 字典词 × 掩码组合

### 密码验证

ZIP 文件采用两层验证避免 CRC 误判：先用 `zipfile.read()` 在进程内快速检查，再通过 `7z t`（测试模式，不写磁盘）确认。其他格式直接用 7z test。

### 魔数检测

读取文件前 512 字节，按 SIGNATURES 列表顺序匹配。TAR 检测在 offset 257 处查找 `ustar`。ISO 9660 在 offset 32769/34817/36865 处查找 `CD001`。

### 分卷处理

不解压单个分卷 — 识别所有卷后将第一个卷路径传给 7-Zip，7-Zip 自动读取其余卷。

### 嵌套解压

解压完成后检查输出目录：
- 仅含 1 个文件夹且该文件夹内仅 1 个文件 → 若是压缩包则自动解压（继承上级密码）
- 含多个文件/文件夹 → 自动扫描并递归解压所有内部压缩包
- 自动展平单层包装目录

## 密码文件与配置

| 版本类型 | 密码库默认位置 | 配置文件位置 |
|---------|-------------|------------|
| 单文件 EXE | `%APPDATA%\Smart Archive Extractor\passwords.txt` | `%APPDATA%\Smart Archive Extractor\config.json` |
| 便携版 | exe 同目录 `passwords.txt` | exe 同目录 `config.json` |
| 源码 | 项目根目录 `passwords.txt` | 项目根目录 `config.json` |

密码库窗口（工具栏 → 密码库）可以自由切换密码文件位置。切换后自动写入配置文件，下次启动恢复上次路径。
单文件版配置文件**仅限于 AppData 目录**，便携版和源码版配置文件**固定于 exe/项目根目录**，不可更改配置文件的存储位置。

## License

MIT
