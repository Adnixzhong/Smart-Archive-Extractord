# Changelog

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
