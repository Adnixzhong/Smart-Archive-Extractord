# SmartArchiveExtractor-Crack

## 项目概述
Python Tkinter GUI 应用 — 带密码破解功能的压缩包解压工具。

## 关键路径
- `main.py` — 入口
- `ui/app.py` — 主界面 (`SmartExtractorApp`)
- `ui/crack_dialog.py` — 密码破解对话框 (`CrackDialog`)
- `core/cracker.py` — CPU 破解引擎 (`CrackSession`, `CrackConfig`, 密码生成器)

## 技术要点
- Python 3.13 + PyInstaller 打包 (`dist/SmartArchiveExtractor.exe`)
- 所有文件已加 `from __future__ import annotations`（兼容类型注解）
- 破解引擎用 producer-consumer 架构：一个生产者线程 + N 个消费者线程，通过 `queue.Queue` 分发
- ZIP 暴力破解用 multiprocessing 分片（offset/stride），worker 内用 7z 验证
- 密码验证：zipfile 快速检查 + 7z t 确认（避免 CRC 误判）

## GPU 加速
GPU 代码已从项目移除，独立存放于 `F:\Claude Code\gpu加速模块\`。
包含：gpu_crack.py (GpuCrackMixin), hashcat.py, hash_extractor.py, tool_manager.py
以后需要时从那里取回。
