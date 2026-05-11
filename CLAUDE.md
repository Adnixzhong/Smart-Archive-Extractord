# SmartArchiveExtractor

## 项目概述
Python Tkinter GUI 应用 — 带密码破解功能的压缩包解压工具，支持智能嵌套解压、自动展平、分卷识别、自动改名。
通过输出目录前的复选框切换智能模式与普通模式。

版本: v2.1.0 | Python 3.13 + Nuitka v4.0.8 C 编译

## 关键路径
- `main.py` — 入口
- `ui/app.py` — 主界面 (`SmartExtractorApp`)，含全部智能解压逻辑与递归提取算法
- `ui/crack_dialog.py` — 密码破解配置/进度对话框 (`CrackDialog`)
- `core/extractor.py` — 7z 命令行封装 (`extract()`, `find_7z()`, `verify_password()`)
- `core/detector.py` — 格式检测 (magic bytes)
- `core/signatures.py` — 所有支持格式的 magic bytes 签名
- `core/split_detector.py` — 分卷检测与分组 (文件名模式匹配)
- `core/renamer.py` — 自动改名 (扩展名匹配实际格式，保留分卷标记)
- `core/cracker.py` — CPU 破解引擎 (`CrackSession`, `CrackConfig`, 5 种密码生成器)
- `core/password.py` — 密码字典管理 (`PasswordManager`)
- `core/binary_detect.py` — 可执行二进制头检测 (PE/ELF/Mach-O)

## 技术要点
- Python 3.13 + Nuitka v4.0.8 C 编译打包
- 所有 `.py` 文件必须包含 `from __future__ import annotations`
- 破解引擎 producer-consumer 架构：一个生产者线程 + N 个消费者线程，`queue.Queue` 分发
- ZIP 暴力破解用 multiprocessing 分片 (offset/stride)，worker 内 7z 确认
- 密码验证：zipfile 快速检查 + 7z t 确认（避免 CRC 误判）
- 智能模式可执行检测用二进制头（`MZ`/`\x7fELF`/Mach-O），不依赖文件后缀

## 智能模式 vs 普通模式

输出目录前的复选框 `_custom_output` 控制：

| | ☑ 智能模式（默认） | ☐ 普通模式 |
|---|---|---|
| 解压方式 | 外层解压到临时工作区 → 递归提取 → 移入输出 | 直接解压，不移动任何文件 |
| 嵌套处理 | 递归提取，所有嵌套压缩包就地解压 | 不解压任何嵌套压缩包 |
| 文件夹结构 | 递归提取后统一展平 | 保留原始文件夹结构 |
| 压缩包清理 | 外层 + 嵌套全部处理 | 仅处理外层压缩包 |
| 解压到目录/同名 | ✓ | ✓ |
| 可执行检测 | 二进制头 | 不检测 |

## 递归提取算法 (v2.1.0)

`_peel_recursive()` — 单一递归函数取代旧的三方法决策链：

```
peel_recursive(dir):
    while True:
        if cancel: return
        扫描目录所有条目，跳过已递归提取的路径

        if 任何文件有可执行二进制头:
            return  (该目录到此为止，不碰任何压缩包)

        递归进入所有子目录  (深度优先)

        重新扫描，收集未递归提取的压缩包
        if 无压缩包: return

        取第一个压缩包:
          分卷检测 → 改名 → 密码尝试(继承→无→字典) → 7z 解压  (就地)
          删除压缩包外壳，标记为已递归提取
          继续循环 — 新内容可能包含更多压缩包或可执行文件
```

### 与旧版 (v2.0.x) 的区别

| | v2.0.x | v2.1.0 |
|---|---|---|
| 扫描 | `_check_smart_nested` 只看一层 | 每揭一层重新扫描全部 |
| 可执行检测 | 文件后缀黑名单 | 二进制头 |
| 嵌套产物位置 | 根据 output_mode 创建子文件夹 | 就地解压到压缩包所在目录 |
| 展平 | 边解边展平 | 全部揭完统一展平 |
| 方法数 | 4 个 | 2 个 (`_peel_recursive` + `_flatten_and_clean`) |

## 解压流水线

`_extraction_worker()` 对每个压缩包执行：

```
Step 1  格式检测   → detect_with_tar_combo() magic bytes 识别
Step 2  分卷识别   → 文件名模式匹配，找齐同目录分卷，以第一卷为入口
Step 3  自动改名   → 扩展名不匹配实际格式则改正
Step 2b 改名后重检 → 改名后重新检测分卷（处理 .part1.jpg → .part1.rar）
Step 4  解压       → 智能模式: 工作区 → 递归提取 → 移入输出 → 展平
                      普通模式: 直接解压到输出目录
Step 5  清理       → 删除/回收已解压的压缩包
```

## 分卷处理

支持三种分卷命名模式（文件名匹配，不检测二进制内容）：

| 模式 | 示例 |
|------|------|
| `.partN.rar` | archive.part1.rar, archive.part2.rar |
| `.NNN` | archive.7z.001, archive.7z.002 |
| `.rNN` | archive.rar, archive.r00, archive.r01 |

## 密码破解引擎

五种攻击模式，统一 `next_batch()` 接口：

| 模式 | 类 |
|------|-----|
| 暴力破解 | `BruteForceGenerator` (offset/stride 并行) |
| 字典 | `DictionaryGenerator` (流式逐行读取) |
| 掩码 | `MaskGenerator` (? = 字符集字符) |
| 规则 | `RuleBasedGenerator` (大小写/leet/数字/符号) |
| 混合 | `HybridGenerator` (字典词 + 掩码前后缀) |

ZIP 暴力破解自动启用 multiprocessing（`_zip_mp_worker`，GIL-free）。

## 存储路径

| 版本 | config.json / passwords.txt 位置 |
|------|----------------------------------|
| Nuitka onefile | `%APPDATA%\SmartArchiveExtractor\` |
| 便携版 (main.dist/) | EXE 同目录 |
| 源码 | 项目根目录 |

Onefile 检测：`exe_dir.name.startswith("onefile_")`

## 构建命令

```bash
# Onefile (单文件 EXE)
python -m nuitka --onefile --windows-console-mode=disable --enable-plugin=tk-inter \
    --output-dir=dist/nuitka --output-filename=SmartArchiveExtractor.exe main.py

# Portable (独立文件夹)
python -m nuitka --standalone --windows-console-mode=disable --enable-plugin=tk-inter \
    --output-dir=dist/nuitka-portable --output-filename=SmartArchiveExtractor.exe main.py
```

## GPU 加速
GPU 代码已从项目移除，独立存放于 `F:\Claude Code\gpu加速模块\`。
