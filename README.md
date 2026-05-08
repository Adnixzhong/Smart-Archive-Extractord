# 智能解压工具 (Smart Archive Extractor)

基于 Python + Tkinter 的 GUI 压缩包解压工具，使用 **7-Zip** 作为解压引擎，通过**文件头魔数 (magic bytes)** 智能识别压缩包格式，支持后缀名自动修正、分卷解压、密码字典爆破、嵌套压缩包全自动处理。

## 核心功能

- **魔数格式检测** — 读取文件头二进制签名识别真实格式（ZIP/RAR/7z/TAR/GZ/BZ2/XZ/ZST/CAB/ISO/ARJ/LZH/LZ4），不依赖文件后缀名
- **后缀名自动修正** — 检测到错误后缀名时自动重命名为正确后缀，分卷文件（.001/.r00/.part1.rar）不会被误改名
- **分卷解压** — 自动识别并合并 .part1.rar / .r00 / .zip.001 / .7z.001 等分卷压缩包
- **密码字典** — 内置约 200 个常见密码（中英文），支持自定义密码库（导入/编辑/导出），密码本自动持久化到 `passwords.txt`，按文件单独设置密码
- **智能嵌套解压** — 解压后全自动检测：
  - 单文件夹内含单个压缩包 → 自动解压（继承上级密码）
  - 多文件/文件夹结构 → 自动扫描并解压所有内部压缩包
  - 自动展平单层包装目录，清理残留压缩包
- **双面板文件列表** — 左侧「待解压」+ 右侧「已解压」，支持右键设置密码、还原已解压文件到待解压列表
- **解压后处理** — 三种模式：保留压缩包 / 移到回收站 / 直接删除，解压完成自动打开文件夹
- **Windows 原生拖放** — 支持从资源管理器直接拖入文件/文件夹
- **7 套 UI 主题** — system / light / dark / midnight / moss / sepia / mono，一键切换
- **零控制台闪烁** — 所有 subprocess 调用均在后台静默执行，`main.pyw` 无控制台启动

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

### 方式一：源码运行

**依赖**

- **Python 3.9+**（3.8 不支持 `list[str]` 语法）
- **7-Zip** — 需安装并确保 `7z.exe` 在 PATH 中，或安装到 `C:\Program Files\7-Zip\`
- **windnd** — Windows 原生拖放支持

**步骤**

```bash
git clone https://github.com/Adnixzhong/Smart-Archive-Extractord.git
cd Smart-Archive-Extractord
pip install windnd
python main.py       # 控制台启动（调试用）
# 或双击 main.pyw    # 无控制台启动（推荐）
```

### 方式二：打包的 EXE

使用 PyInstaller 打包为独立可执行文件（无需安装 Python）：

```bash
pip install PyInstaller
pyinstaller --onefile --windowed --name "Smart Archive Extractor" main.py
# 输出在 dist/Smart Archive Extractor.exe
```

**注意**：打包后的 EXE 仍需要目标机器安装 7-Zip。

## 使用说明

1. **添加文件** — 点击「添加文件」/「添加文件夹」，或直接从资源管理器拖入
2. **设置输出目录** — 默认使用第一个文件所在目录下的 `Extracted` 文件夹
3. **配置密码** — 可加载密码字典文件（每行一个密码），或右键文件列表单独设置密码
4. **解压** — 点击「开始解压」，工具会依次：
   - 检测格式 → 识别分卷 → 修正后缀名 → 解压 → 智能检测嵌套
5. **嵌套解压** — 解压完成后自动检查输出内容，智能决定是否继续解压

### 密码优先级

对于每个文件，按以下顺序尝试密码：

1. 文件级别的「指定密码」（右键设置）
2. 无密码尝试
3. 密码字典（跳过已尝试的和上级密码）

嵌套压缩包会优先尝试上级压缩包的密码（通常同一套密码）。

## 项目结构

```
smart-archive-extractor/
├── main.py                  # 入口文件
├── README.md
├── core/
│   ├── __init__.py
│   ├── signatures.py        # 魔数签名数据库
│   ├── detector.py          # 格式检测（含 tar.gz 等组合检测）
│   ├── split_detector.py    # 分卷压缩包识别与卷查找
│   ├── renamer.py           # 后缀名自动修正
│   ├── extractor.py         # 7-Zip 解压封装
│   └── password.py          # 密码管理与内置字典
└── ui/
    ├── __init__.py
    └── app.py               # Tkinter GUI 主程序
```

### 模块职责

| 模块 | 职责 |
|------|------|
| `core/signatures.py` | 定义 FormatInfo 数据类和 SIGNATURES 魔数列表（包含 ISO 和 TAR 的特殊偏移量检测） |
| `core/detector.py` | `detect()` 读取文件头 512 字节匹配魔数；`detect_with_tar_combo()` 识别 GZ/BZ2/XZ/ZST 内的 TAR 组合 |
| `core/split_detector.py` | 正则匹配分卷模式，`find_volumes()` 返回完整卷列表，`get_first_volume()` 取第一分卷 |
| `core/renamer.py` | `needs_rename()` / `get_correct_path()` — 分卷文件直接跳过，普通文件剥离已知后缀并附加正确后缀 |
| `core/extractor.py` | `find_7z()` 搜索 7z.exe；`extract()` 通过 subprocess 调用 7z 并解析进度；`extract_with_password_list()` 遍历密码列表；`scan_for_archives()` 递归扫描目录 |
| `core/password.py` | `PasswordManager` 管理内置 + 自定义密码，支持去重、增删、导入导出 |
| `ui/app.py` | 完整 GUI：双面板文件列表、选项面板、日志、进度条、拖放支持、智能嵌套检测流程 |

## 技术要点

### 魔数检测

读取文件前 512 字节，从 SIGNATURES 列表中按顺序匹配。TAR 检测在 offset 257 处查找 `ustar` 字符串。ISO 9660 在 offset 32769/34817/36865 处查找 `CD001`。

### 分卷处理

不解压单个分卷 — 必须识别所有卷后，将第一个卷路径传给 7-Zip，由 7-Zip 自动读取其余卷。

### 后缀名修正

取文件名，移除所有已知压缩包后缀（如 `.tar.gz`、`.zip`、`.rar`），移除 `.partN` 后缀，然后附加检测到的正确后缀。分卷文件（`.001`、`.r00`、`.part1.rar`）**不会**被重命名。

### 嵌套解压

解压完成后检查输出目录结构：
- 仅含 1 个文件夹且该文件夹内仅 1 个文件 → 若该文件是压缩包则自动解压（继承上级密码）
- 含多个文件/文件夹 → 列出树状结构并弹出对话框询问用户

## License

MIT
