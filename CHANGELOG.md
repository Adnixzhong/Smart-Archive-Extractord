# Changelog

## v2.1.0 (2026-05-11)

### 重构 — 嵌套解压递归算法
- 完全重写智能嵌套解压逻辑，用单一递归函数替代旧的四方法决策链
  - 新增 `_peel_recursive()`：自底向上深度优先树遍历，每解一层即时重新扫描
  - 嵌套压缩包就地解压到所在目录（不再创建子文件夹），解完后继续探查
  - 外层压缩包仅在最外层创建一次临时工作区，完成后移入输出目录并删除
- 可执行文件检测改为二进制头识别（PE `MZ` / ELF `\x7fELF` / Mach-O 四种魔数）
  - 新增 `core/binary_detect.py` — `is_executable_binary()`
  - 移除旧的后缀黑名单（`_EXEC_EXTS`）
- 删除 `_check_smart_nested()` / `_process_single_nested()` / `_process_nested_dir()`
- `_extract_one()` 新增可选 `output_dir` 参数，支持智能模式工作区提取

### 模式分离
- ☑ 智能模式：工作区 → 递归提取 → 移入输出 → 展平
- ☐ 普通模式：直接解压到输出目录，保留原始文件夹结构，不移动任何文件
- 两模式下"解压后"压缩包清理独立运行

### 构建
- Nuitka v4.0.8, Python 3.13
- 单文件 EXE 37MB（`dist/nuitka/SmartArchiveExtractor.exe`）
- 便携版 39MB（`dist/nuitka-portable/main.dist/`）

## v2.0.1 (2026-05-11)

### 重构
- 完全重写 `core/cracker.py` 破解引擎
  - 改为 producer-consumer 架构：单生产者线程 + N 个消费者线程，通过 `queue.Queue` 分发
  - ZIP 暴力破解使用 multiprocessing + offset/stride 分片
  - 密码验证改为 zipfile 快检 + 7z t 确认，避免 CRC 误判
  - 统一 `next_batch()` 接口覆盖所有生成器

### 修复
- `BruteForceGenerator` 重复生成密码（`_current_limit` 跨长度累加导致）
- `RuleBasedGenerator` 误丢弃正确密码（`results.discard(word)` 删除了小写变体）
- `_try_zip_read()` 跳过目录条目查找第一个文件
- 所有文件添加 `from __future__ import annotations` 兼容 Python 3.9+ 类型语法

### 构建
- 切换到 Python 3.13 + PyInstaller 打包
- 单文件 EXE ~15 MB（`dist/SmartArchiveExtractor.exe`）
