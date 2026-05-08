"""Smart Archive Extractor — Entry point."""

import sys
import traceback
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from ui.app import main
except Exception as e:
    import tkinter.messagebox as mb
    mb.showerror("启动错误", f"导入模块失败:\n{traceback.format_exc()}")
    sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except Exception:
        import tkinter.messagebox as mb
        mb.showerror("运行错误", f"程序异常:\n{traceback.format_exc()}")
