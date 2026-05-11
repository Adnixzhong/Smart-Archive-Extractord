"""Smart Archive Extractor — GUI Application."""

from __future__ import annotations

import os
import sys
import shutil
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from pathlib import Path
import threading
import json
import re
import time
import ctypes

import windnd

from core.binary_detect import is_executable_binary
from core.detector import detect_with_tar_combo, detect
from core.split_detector import find_volumes, is_split_archive, get_first_volume
from core.renamer import get_correct_path, needs_rename
from core.extractor import extract, find_7z, ExtractError
from core.password import PasswordManager
from ui.crack_dialog import CrackDialog


def _get_monitor_work_area(x: int, y: int) -> tuple[int, int, int, int]:
    """Return (left, top, right, bottom) of the monitor containing (x, y)."""
    from ctypes import wintypes

    class RECT(ctypes.Structure):
        _fields_ = [
            ("left", ctypes.c_long),
            ("top", ctypes.c_long),
            ("right", ctypes.c_long),
            ("bottom", ctypes.c_long),
        ]

    class MONITORINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("rcMonitor", RECT),
            ("rcWork", RECT),
            ("dwFlags", wintypes.DWORD),
        ]

    pt = wintypes.POINT(x, y)
    monitor = ctypes.windll.user32.MonitorFromPoint(pt, 2)  # MONITOR_DEFAULTTONEAREST
    info = MONITORINFO()
    info.cbSize = ctypes.sizeof(MONITORINFO)
    ctypes.windll.user32.GetMonitorInfoW(monitor, ctypes.byref(info))
    r = info.rcWork
    return (r.left, r.top, r.right, r.bottom)


class _SHFILEOPSTRUCTW(ctypes.Structure):
    """Shared struct for SHFileOperationW — used by recycle and restore operations."""
    _fields_ = [
        ("hwnd", ctypes.c_void_p),
        ("wFunc", ctypes.c_uint),
        ("pFrom", ctypes.c_wchar_p),
        ("pTo", ctypes.c_wchar_p),
        ("fFlags", ctypes.c_ushort),
        ("fAnyOperationsAborted", ctypes.c_int),
        ("hNameMappings", ctypes.c_void_p),
        ("lpszProgressTitle", ctypes.c_wchar_p),
    ]


class LogHandler:
    def __init__(self, text_widget: tk.Text):
        self._text = text_widget

    def log(self, message: str):
        self._text.configure(state="normal")
        self._text.insert(tk.END, message + "\n")
        self._text.see(tk.END)
        self._text.configure(state="disabled")

    def clear(self):
        self._text.configure(state="normal")
        self._text.delete("1.0", tk.END)
        self._text.configure(state="disabled")


class ArchiveFileItem:
    def __init__(self, path: Path):
        self.path = path.resolve()
        self.detected_format: str = ""
        self.will_rename = False
        self.target_name: str = ""
        self.is_split = False
        self.volume_count = 0
        self.status = "pending"
        self.error_msg = ""
        self.specific_password: str = ""
        self.output_path: str = ""


class PasswordEditorDialog(tk.Toplevel):
    def __init__(self, parent, password_manager: PasswordManager, *,
                 app_colors=None, config_file=None, on_change=None):
        super().__init__(parent)
        self.title("密码库")
        self.geometry("500x620")
        self.minsize(400, 420)
        self._C = app_colors or {
            "canvas": "#15181d", "surface": "#1c2026", "elevated": "#22262d",
            "card": "#292d35", "hairline": "#343840", "ink": "#e8eaed",
            "body": "#b8bcc4", "mute": "#8a8f98", "blue": "#5dade2",
        }
        self.configure(bg=self._C["canvas"])
        self._pm = password_manager
        self._config_file = config_file
        self._on_change = on_change
        self.transient(parent)
        self.grab_set()
        self._build_ui()
        self._refresh_list()
        windnd.hook_dropfiles(self, func=self._on_drop_files)

    def _build_ui(self):
        C = self._C

        # Drop hint / drag area
        self._drop_frame = tk.Frame(self, bg=C["surface"], height=56,
                                     highlightbackground=C["hairline"],
                                     highlightthickness=1)
        self._drop_frame.pack(fill=tk.X, padx=12, pady=(12, 4))
        self._drop_frame.pack_propagate(False)
        self._drop_hint = tk.Label(self._drop_frame,
                                    text="拖入 .txt 文件到此处自动导入 (一行一个密码)",
                                    bg=C["surface"], fg=C["mute"],
                                    font=("Segoe UI", 10))
        self._drop_hint.pack(expand=True)
        self._drop_frame.bind("<Enter>", self._on_drop_enter)
        self._drop_frame.bind("<Leave>", self._on_drop_leave)

        # Multi-line paste area + buttons
        add_label = ttk.Label(self, text="或粘贴密码（一行一个）", font=("Segoe UI", 9))
        add_label.pack(fill=tk.X, padx=12, pady=(8, 4))
        self._add_text = tk.Text(self, height=4, wrap=tk.WORD,
                                  bg=C["surface"], fg=C["body"],
                                  insertbackground=C["body"],
                                  borderwidth=1, highlightthickness=0,
                                  font=("Cascadia Code", 10),
                                  selectbackground=C["blue"],
                                  selectforeground=C["canvas"])
        self._add_text.pack(fill=tk.X, padx=12, pady=(0, 4))
        btn_row = ttk.Frame(self)
        btn_row.pack(fill=tk.X, padx=12, pady=(0, 8))
        ttk.Button(btn_row, text="导入文件...", command=self._import_file).pack(side=tk.LEFT)
        ttk.Button(btn_row, text="添加以上密码", command=self._add_passwords).pack(side=tk.RIGHT)

        # Password list
        list_frame = ttk.Frame(self)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)
        self._listbox = tk.Listbox(list_frame, font=("Cascadia Code", 10), selectmode="extended",
                                    bg=C["surface"], fg=C["body"],
                                    selectbackground=C["blue"], selectforeground=C["canvas"],
                                    borderwidth=1, highlightthickness=0,
                                    relief="solid", activestyle="none")
        scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self._listbox.yview)
        self._listbox.configure(yscrollcommand=scroll.set)
        self._listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=12, pady=4)
        ttk.Button(btn_frame, text="删除选中", command=self._delete_selected).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_frame, text="导出文件", command=self._export_file).pack(side=tk.LEFT, padx=4)

        # Password file path row
        path_frame = ttk.Frame(self)
        path_frame.pack(fill=tk.X, padx=12, pady=(8, 0))
        ttk.Label(path_frame, text="密码库路径:", font=("Segoe UI", 9)).pack(side=tk.LEFT)
        current_path = str(self._pm.persist_path) if self._pm.persist_path else ""
        self._path_var = tk.StringVar(value=current_path)
        self._path_entry = tk.Entry(path_frame, textvariable=self._path_var,
                                     bg=C["surface"], fg=C["body"],
                                     insertbackground=C["body"],
                                     font=("Segoe UI", 9), relief="solid", borderwidth=1)
        self._path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        ttk.Button(path_frame, text="浏览...", command=self._browse_password_path).pack(side=tk.LEFT)
        ttk.Button(path_frame, text="应用", command=self._apply_password_path).pack(side=tk.LEFT, padx=(4, 0))

        self._status_label = ttk.Label(self, text="", foreground=C["mute"])
        self._status_label.pack(fill=tk.X, padx=12, pady=(6, 12))
        ttk.Button(self, text="关闭", command=self._close).pack(pady=(0, 12))

    def _close(self):
        if self._on_change:
            self._on_change()
        self.destroy()

    def _on_drop_enter(self, event):
        self._drop_frame.configure(highlightbackground=self._C["blue"])
        self._drop_hint.configure(text="释放以导入密码文件", fg=self._C["blue"])

    def _on_drop_leave(self, event):
        self._drop_frame.configure(highlightbackground=self._C["hairline"])
        self._drop_hint.configure(text="拖入 .txt 文件到此处自动导入 (一行一个密码)",
                                  fg=self._C["mute"])

    def _on_drop_files(self, files):
        self._on_drop_leave(None)
        added_total = 0
        for f in files:
            if isinstance(f, bytes):
                f = f.decode("gbk", errors="replace")
            p = f.strip()
            if p:
                added = self._import_password_file(p)
                added_total += added
        if added_total > 0:
            self._refresh_list()
            self._status_label.configure(text=f"已从拖入文件导入 {added_total} 个密码")

    def _import_password_file(self, path_str: str) -> int:
        """Import passwords from a text file (one per line). Returns count added."""
        try:
            with open(path_str, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            return 0
        return self._pm.add_multiple(content)

    def _import_file(self):
        path = filedialog.askopenfilename(
            parent=self, title="导入密码文件",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
        )
        if path:
            added = self._import_password_file(path)
            if added:
                self._refresh_list()
                self._status_label.configure(text=f"已导入 {added} 个密码")
            else:
                self._status_label.configure(text="文件无有效密码或密码已存在")

    def _refresh_list(self):
        self._listbox.delete(0, tk.END)
        for p in self._pm.get_all_passwords():
            self._listbox.insert(tk.END, p)
        self._status_label.configure(text=f"共 {self._pm.total_count} 个密码")

    def _add_passwords(self):
        text = self._add_text.get("1.0", "end-1c")
        if not text.strip():
            return
        added = self._pm.add_multiple(text)
        if added:
            self._add_text.delete("1.0", tk.END)
            self._refresh_list()
        else:
            messagebox.showinfo("提示", "密码已存在或无效", parent=self)

    def _delete_selected(self):
        selected = self._listbox.curselection()
        if not selected:
            return
        passwords = self._pm.get_all_passwords()
        for idx in reversed(selected):
            if 0 <= idx < len(passwords):
                self._pm.remove(passwords[idx])
        self._refresh_list()

    def _export_file(self):
        path = filedialog.asksaveasfilename(parent=self, title="导出密码",
                                            defaultextension=".txt",
                                            filetypes=[("文本文件", "*.txt")])
        if path:
            count = self._pm.save(path)
            if count > 0:
                messagebox.showinfo("提示", f"已导出 {count} 个密码", parent=self)
            else:
                messagebox.showinfo("提示", "密码列表为空，未导出", parent=self)

    def _browse_password_path(self):
        path = filedialog.askopenfilename(parent=self, title="选择密码库文件",
                                          filetypes=[("文本文件", "*.txt")])
        if path:
            self._path_var.set(path)

    def _apply_password_path(self):
        new_path = self._path_var.get().strip()
        if not new_path:
            messagebox.showwarning("提示", "路径不能为空", parent=self)
            return
        if not new_path.lower().endswith(".txt"):
            messagebox.showwarning("提示", "密码库文件必须以 .txt 结尾", parent=self)
            return
        from pathlib import Path
        new = Path(new_path)
        self._pm.set_persistence(str(new))
        if new.is_file():
            count = self._pm.load(str(new))
            self._refresh_list()
            self._status_label.configure(text=f"已切换并加载 {count} 个密码")
        else:
            self._pm.save()
            self._status_label.configure(text=f"密码库路径已更新（新文件将在保存时创建）")
        # Persist to config so it survives restart
        if self._config_file:
            self._save_config_to(self._config_file, str(new))

    @staticmethod
    def _save_config_to(config_file, password_path: str):
        try:
            import json
            config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(config_file, "w", encoding="utf-8") as f:
                json.dump({"password_file": password_path}, f)
        except Exception:
            pass


class SmartExtractorApp:
    _PLACEHOLDER = "留空则默认输出到压缩包路径（不打钩=普通解压，保留文件夹结构）"

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("智能解压工具")
        self.root.geometry("900x700")
        self.root.minsize(800, 550)
        self.root.withdraw()  # hide until positioned at mouse

        self._files: list[ArchiveFileItem] = []
        self._completed: list[ArchiveFileItem] = []
        self._recycled_items: list[tuple[str, float]] = []  # (original_path, timestamp)
        self._password_manager = PasswordManager()
        if getattr(sys, "frozen", False):
            exe_dir = Path(sys.executable).resolve().parent
            # Nuitka onefile extracts to a temp dir named "onefile_<pid>_<random>"
            if exe_dir.name.startswith("onefile_"):
                self._config_dir = Path(os.environ["APPDATA"]) / "SmartArchiveExtractor"
            else:
                self._config_dir = exe_dir          # portable
        else:
            self._config_dir = Path(__file__).resolve().parent.parent  # source
        self._config_file = self._config_dir / "config.json"
        self._password_file = self._config_dir / "passwords.txt"
        # Load custom password path from config (single-file EXE can persist settings this way)
        custom = self._load_config()
        if custom and Path(custom).is_file():
            self._password_file = Path(custom)
        self._password_manager.set_persistence(self._password_file)
        self._auto_rename = tk.BooleanVar(value=True)
        self._auto_password = tk.BooleanVar(value=True)
        self._delete_mode = tk.StringVar(value="none")  # "none" | "delete" | "recycle"
        self._output_mode = tk.StringVar(value="subfolder")  # "flat" | "subfolder"
        self._subfolder_name = tk.StringVar(value="")
        self._output_dir = tk.StringVar(value="")
        self._custom_output = tk.BooleanVar(value=True)
        self._open_after = tk.BooleanVar(value=False)
        self._pwd_overlays: list[tk.Frame] = []
        self._cancel_flag = threading.Event()
        self._current_thread: threading.Thread | None = None
        self._theme = tk.StringVar(value="slate")

        self._build_ui()
        self._apply_theme()
        self._load_persistent_passwords()
        self._update_pwd_count_display()
        self._update_output_preview()
        self._refresh_status()
        # Center on the screen where the mouse cursor is
        self.root.update_idletasks()
        w = self.root.winfo_width()
        h = self.root.winfo_height()
        mx = self.root.winfo_pointerx()
        my = self.root.winfo_pointery()
        ml, mt, mr, mb = _get_monitor_work_area(mx, my)
        left = ml + (mr - ml - w) // 2
        top = mt + (mb - mt - h) // 2
        self.root.geometry(f"+{left}+{top}")
        self.root.deiconify()

    # ============================================================
    #  UI Construction
    # ============================================================

    def _build_ui(self):
        # --- Top bar ---
        top_frame = ttk.Frame(self.root, padding=(16, 12))
        top_frame.pack(fill=tk.X)
        ttk.Label(top_frame, text="Smart Archive Extractor",
                  font=("Segoe UI", 16, "bold")).pack(side=tk.LEFT)
        theme_cb = ttk.Combobox(top_frame, textvariable=self._theme,
                                values=["slate", "midnight"],
                                state="readonly", width=10)
        theme_cb.pack(side=tk.LEFT, padx=(16, 0))
        theme_cb.bind("<<ComboboxSelected>>", lambda e: self._apply_theme())
        sz = find_7z()
        if sz:
            ttk.Label(top_frame, text="7-Zip ✓", foreground=self._C["green"]).pack(side=tk.RIGHT, padx=10)
        else:
            ttk.Label(top_frame, text="7-Zip ✗", foreground=self._C["red"]).pack(side=tk.RIGHT, padx=10)

        # --- Dual-panel file list ---
        list_frame = ttk.Frame(self.root)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 8))

        # Left panel: pending
        pending_frame = ttk.LabelFrame(list_frame, text="待解压", padding=4)
        pending_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._tree_pending = ttk.Treeview(pending_frame,
                                          columns=("#", "文件名", "格式", "密码", "文件路径"),
                                          show="headings", selectmode="extended", height=6)
        self._tree_pending.column("#", width=28, anchor="center")
        self._tree_pending.column("文件名", width=160)
        self._tree_pending.column("格式", width=56, anchor="center")
        self._tree_pending.column("密码", width=70, anchor="center")
        self._tree_pending.column("文件路径", width=200)
        for c in ("#", "文件名", "格式", "密码", "文件路径"):
            self._tree_pending.heading(c, text=c)

        p_scroll = ttk.Scrollbar(pending_frame, orient=tk.VERTICAL,
                                  command=self._on_tree_scroll)
        self._tree_pending.configure(yscrollcommand=p_scroll.set)
        self._tree_pending.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        p_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._tree_pending.bind("<Configure>", lambda e: self._tree_pending.after_idle(self._create_pwd_overlays))

        # Drop hint — placed inside treeview area, hidden when files exist
        self._pending_drop_hint = tk.Label(self._tree_pending,
            text="拖入文件/文件夹到此处添加",
            bg=self._C["surface"], fg=self._C["mute"],
            font=("Segoe UI", 11))
        self._pending_drop_hint.place(relx=0.5, rely=0.5, anchor="center")

        # Right-click menu for pending
        self._pwd_menu = tk.Menu(self.root, tearoff=0,
                                 bg=self._C["elevated"], fg=self._C["body"],
                                 activebackground=self._C["card"], activeforeground=self._C["ink"],
                                 borderwidth=1, relief="solid",
                                 font=("Segoe UI", 10))
        self._pwd_menu.add_command(label="设置密码...", command=self._set_file_password)
        self._pwd_menu.add_command(label="清除密码", command=self._clear_file_password)
        self._pwd_menu.add_separator()
        self._pwd_menu.add_command(label="复制路径", command=self._copy_file_path)
        self._pwd_menu.add_command(label="破解密码...", command=self._open_crack_from_menu)
        self._pwd_edit_entry: tk.Entry | None = None
        self._pwd_edit_iid: str | None = None
        self._tree_pending.bind("<Button-3>", self._on_pending_right_click)
        self._tree_pending.bind("<Button-1>", self._on_tree_click)
        self._tree_pending.bind("<Control-c>", lambda e: self._copy_file_path())

        # Right panel: completed
        done_frame = ttk.LabelFrame(list_frame, text="已解压", padding=4)
        done_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(6, 0))

        self._tree_done = ttk.Treeview(done_frame,
                                       columns=("文件名", "输出路径", "状态"),
                                       show="headings", selectmode="extended", height=6)
        self._tree_done.column("文件名", width=160)
        self._tree_done.column("输出路径", width=160)
        self._tree_done.column("状态", width=50, anchor="center")
        for c in ("文件名", "输出路径", "状态"):
            self._tree_done.heading(c, text=c)

        d_scroll = ttk.Scrollbar(done_frame, orient=tk.VERTICAL, command=self._tree_done.yview)
        self._tree_done.configure(yscrollcommand=d_scroll.set)
        self._tree_done.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        d_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # --- Toolbars below panels (left = pending, right = done) ---
        toolbar_frame = ttk.Frame(self.root)
        toolbar_frame.pack(fill=tk.X, padx=12, pady=(0, 8))

        # Left toolbar — aligned with pending panel
        toolbar_left = ttk.Frame(toolbar_frame)
        toolbar_left.pack(side=tk.LEFT)
        ttk.Button(toolbar_left, text="添加文件", command=self._add_files).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(toolbar_left, text="添加文件夹", command=self._add_directory).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar_left, text="移除选中", command=self._remove_selected).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar_left, text="清空列表", command=self._clear_pending).pack(side=tk.LEFT, padx=4)

        # Right toolbar — aligned with done panel
        toolbar_right = ttk.Frame(toolbar_frame)
        toolbar_right.pack(side=tk.RIGHT)
        ttk.Button(toolbar_right, text="清空已完成", command=self._clear_completed).pack(side=tk.RIGHT, padx=4)
        ttk.Button(toolbar_right, text="打开回收站", command=self._open_recycle_restore).pack(side=tk.RIGHT, padx=4)

        # --- Options panel ---
        opt_frame = ttk.LabelFrame(self.root, text="选项", padding=(12, 10))
        opt_frame.pack(fill=tk.X, padx=12, pady=(0, 8))

        row2 = ttk.Frame(opt_frame)
        row2.pack(fill=tk.X, pady=6)
        ttk.Label(row2, text="密码字典").pack(side=tk.LEFT)
        ttk.Button(row2, text="编辑", command=self._open_password_editor).pack(side=tk.LEFT, padx=(8, 4))
        ttk.Button(row2, text="密码破解", command=self._open_crack_dialog).pack(side=tk.RIGHT)
        ttk.Button(row2, text="导出", command=self._export_passwords).pack(side=tk.LEFT, padx=4)

        row3 = ttk.Frame(opt_frame)
        row3.pack(fill=tk.X, pady=6)
        self._chk_rename = tk.Checkbutton(row3, text="自动修正后缀名", variable=self._auto_rename)
        self._chk_rename.pack(side=tk.LEFT, padx=(0, 16))
        self._chk_pwd = tk.Checkbutton(row3, text="自动尝试密码", variable=self._auto_password)
        self._chk_pwd.pack(side=tk.LEFT, padx=(0, 16))
        self._pwd_count_label = ttk.Label(row3, text="")
        self._pwd_count_label.pack(side=tk.LEFT)
        self._update_pwd_count_display()

        row4 = ttk.Frame(opt_frame)
        row4.pack(fill=tk.X, pady=6)
        ttk.Label(row4, text="输出方式").pack(side=tk.LEFT)
        ttk.Radiobutton(row4, text="解压到目录", variable=self._output_mode,
                        value="flat", command=self._update_output_preview).pack(side=tk.LEFT, padx=(8, 8))
        ttk.Radiobutton(row4, text="解压到同名/", variable=self._output_mode,
                        value="subfolder", command=self._update_output_preview).pack(side=tk.LEFT)
        self._subfolder_entry = tk.Entry(row4, textvariable=self._subfolder_name,
                                          bg=self._C["surface"], fg=self._C["body"],
                                          insertbackground=self._C["body"],
                                          font=("Segoe UI", 10),
                                          relief="solid", borderwidth=1, width=12)
        self._subfolder_entry.pack(side=tk.LEFT, padx=(2, 0))
        self._subfolder_name.trace_add("write", self._update_output_preview)
        ttk.Label(row4, text=" 文件夹（留空=压缩包名）").pack(side=tk.LEFT)

        # Output directory — checkbox toggles smart/simple mode
        row4b = ttk.Frame(opt_frame)
        row4b.pack(fill=tk.X, pady=(2, 6))
        self._chk_custom_output = tk.Checkbutton(row4b, text="", variable=self._custom_output,
                                                   command=self._on_custom_output_toggle)
        self._chk_custom_output.pack(side=tk.LEFT)
        ttk.Label(row4b, text="输出目录:").pack(side=tk.LEFT, padx=(2, 0))
        self._output_dir_entry = tk.Entry(row4b,
                                           bg=self._C["surface"], fg=self._C["mute"],
                                           insertbackground=self._C["body"],
                                           font=("Segoe UI", 10),
                                           relief="solid", borderwidth=1)
        self._output_dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 4))
        self._output_dir_entry.insert(0, self._PLACEHOLDER)
        self._output_dir_entry.bind("<FocusIn>", self._on_output_dir_focus_in)
        self._output_dir_entry.bind("<FocusOut>", self._on_output_dir_focus_out)
        self._output_dir_entry.bind("<KeyRelease>", self._on_output_dir_key)
        self._browse_output_btn = ttk.Button(row4b, text="浏览...", command=self._browse_output_dir)
        self._browse_output_btn.pack(side=tk.LEFT)

        row5 = ttk.Frame(opt_frame)
        row5.pack(fill=tk.X, pady=(6, 0))
        ttk.Label(row5, text="解压后").pack(side=tk.LEFT)
        ttk.Radiobutton(row5, text="保留压缩包", variable=self._delete_mode, value="none").pack(side=tk.LEFT, padx=(8, 16))
        ttk.Radiobutton(row5, text="移到回收站", variable=self._delete_mode, value="recycle").pack(side=tk.LEFT, padx=(0, 16))
        ttk.Radiobutton(row5, text="直接删除", variable=self._delete_mode, value="delete").pack(side=tk.LEFT, padx=(0, 16))
        self._chk_open = tk.Checkbutton(row5, text="完成后打开文件夹", variable=self._open_after)
        self._chk_open.pack(side=tk.LEFT)

        # --- Progress bar ---
        self._progress = ttk.Progressbar(self.root, mode="determinate", length=400)
        self._progress.pack(fill=tk.X, padx=12, pady=(8, 0))

        # --- Action buttons ---
        bottom = ttk.Frame(self.root, padding=(12, 8))
        bottom.pack(fill=tk.X)
        self._extract_btn = ttk.Button(bottom, text="开始解压",
                                       command=self._start_extraction, width=12,
                                       style="Primary.TButton")
        self._extract_btn.pack(side=tk.LEFT, padx=(0, 4))
        self._stop_btn = ttk.Button(bottom, text="停止", command=self._stop_extraction, state="disabled", width=8)
        self._stop_btn.pack(side=tk.LEFT, padx=4)
        self._clear_log_btn = ttk.Button(bottom, text="清空日志", width=8)
        self._clear_log_btn.pack(side=tk.LEFT, padx=4)
        self._status_label = ttk.Label(bottom, text="就绪")
        self._status_label.pack(side=tk.RIGHT, padx=10)

        # --- Log area ---
        log_frame = ttk.LabelFrame(self.root, text="日志", padding=4)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 8))

        self._log_text = tk.Text(log_frame, height=5, state="disabled", wrap=tk.WORD)
        log_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self._log_text.yview)
        self._log_text.configure(yscrollcommand=log_scroll.set)
        self._log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._logger = LogHandler(self._log_text)
        self._clear_log_btn.configure(command=self._logger.clear)

        # Enable drag-and-drop
        windnd.hook_dropfiles(self.root, func=self._on_drop_files)

    # ============================================================
    #  Theme system
    # ============================================================

    _THEME_PALETTES = {
        "slate": {   # medium dark — readable
            "canvas": "#15181d", "surface": "#1c2026", "elevated": "#22262d",
            "card": "#292d35", "hairline": "#343840",
            "ink": "#e8eaed", "body": "#b8bcc4", "mute": "#8a8f98",
            "ash": "#5f646e", "stone": "#41454d",
            "blue": "#5dade2", "green": "#58d68d", "red": "#ec7063", "yellow": "#f4d03f",
        },
        "midnight": { # deeper dark — OLED friendly
            "canvas": "#0a0c10", "surface": "#111318", "elevated": "#171a21",
            "card": "#1e2129", "hairline": "#2a2d36",
            "ink": "#e4e6eb", "body": "#b0b4bd", "mute": "#828790",
            "ash": "#5a5e67", "stone": "#3e4149",
            "blue": "#4da6e8", "green": "#4dc987", "red": "#e06055", "yellow": "#e8c43a",
        },
    }

    @property
    def _C(self):
        return self._THEME_PALETTES[self._theme.get()]

    def _apply_theme(self):
        C = self._C
        style = ttk.Style()
        available = style.theme_names()
        base = "clam" if "clam" in available else available[0]
        style.theme_use(base)
        # --- Frames ---
        style.configure("TFrame", background=C["canvas"])
        style.configure("TLabelframe", background=C["canvas"], foreground=C["ink"],
                        borderwidth=1, bordercolor=C["hairline"], relief="solid")
        style.configure("TLabelframe.Label", background=C["canvas"], foreground=C["ink"],
                        font=("Segoe UI", 10, "bold"))

        # --- Labels ---
        style.configure("TLabel", background=C["canvas"], foreground=C["body"],
                        font=("Segoe UI", 10))

        # --- Buttons ---
        style.configure("TButton",
                        background=C["elevated"], foreground=C["ink"],
                        borderwidth=1, bordercolor=C["hairline"],
                        focusthickness=0, font=("Segoe UI", 10),
                        padding=(12, 6))
        style.map("TButton",
                  background=[("active", C["card"]), ("pressed", C["surface"])],
                  foreground=[("active", C["ink"]), ("pressed", C["ink"]),
                              ("disabled", C["ash"])],
                  bordercolor=[("active", C["hairline"])])

        # --- Primary button ---
        style.configure("Primary.TButton",
                        background=C["ink"], foreground=C["canvas"],
                        borderwidth=0, focusthickness=0,
                        font=("Segoe UI", 10, "bold"),
                        padding=(16, 6))
        style.map("Primary.TButton",
                  background=[("active", "#e8e8e8"), ("pressed", "#d0d0d0")],
                  foreground=[("active", C["canvas"]), ("pressed", C["canvas"]),
                              ("disabled", C["stone"])])

        # --- Check & Radio ---
        # --- Checkbuttons (tk) ---
        for chk in [self._chk_rename, self._chk_pwd, self._chk_open]:
            chk.configure(
                bg=C["canvas"], fg=C["body"],
                selectcolor=C["elevated"],
                activebackground=C["elevated"],
                activeforeground=C["ink"],
                highlightthickness=0,
                font=("Segoe UI", 10),
            )

        for entry in [self._subfolder_entry, self._output_dir_entry]:
            entry.configure(
                bg=C["surface"], fg=C["body"],
                insertbackground=C["body"],
            )

        style.configure("TRadiobutton", background=C["canvas"], foreground=C["body"],
                        font=("Segoe UI", 10))
        style.map("TRadiobutton",
                  background=[("active", C["elevated"]), ("hover", C["elevated"]),
                              ("focus", C["canvas"]), ("!active", C["canvas"])],
                  foreground=[("active", C["ink"])])

        # --- Entries ---
        style.configure("TEntry", fieldbackground=C["elevated"], foreground=C["ink"],
                        borderwidth=1, bordercolor=C["hairline"],
                        font=("Segoe UI", 10))
        style.map("TEntry", bordercolor=[("focus", C["stone"])])

        # --- Combobox ---
        style.configure("TCombobox", fieldbackground=C["elevated"], foreground=C["ink"],
                        background=C["elevated"], arrowcolor=C["body"],
                        borderwidth=1, bordercolor=C["hairline"],
                        font=("Segoe UI", 10))
        style.map("TCombobox",
                  fieldbackground=[("readonly", C["elevated"])],
                  foreground=[("readonly", C["ink"])])

        # --- Progress bar ---
        style.configure("TProgressbar", background=C["blue"],
                        troughcolor=C["elevated"], borderwidth=1,
                        bordercolor=C["hairline"])

        # --- Treeview ---
        style.configure("Treeview", background=C["surface"], foreground=C["body"],
                        fieldbackground=C["surface"], borderwidth=1,
                        bordercolor=C["hairline"], font=("Segoe UI", 10))
        style.configure("Treeview.Heading", background=C["elevated"],
                        foreground=C["ink"], borderwidth=1,
                        bordercolor=C["hairline"],
                        font=("Segoe UI", 9, "bold"))
        style.map("Treeview.Heading",
                  background=[("active", C["card"])],
                  foreground=[("active", C["ink"])])
        style.map("Treeview",
                  background=[("selected", C["blue"])],
                  foreground=[("selected", C["canvas"])])

        # --- Root ---
        self.root.configure(bg=C["canvas"])

        # --- Separators ---
        style.configure("TSeparator", background=C["hairline"])

        # --- Log ---
        self._log_text.configure(
            bg=C["surface"], fg=C["body"], insertbackground=C["body"],
            font=("Cascadia Code", 9),
            borderwidth=1, highlightthickness=0,
            padx=8, pady=4,
            selectbackground=C["blue"],
            selectforeground=C["canvas"],
        )

        # --- Status ---
        self._status_label.configure(foreground=C["mute"])

        # --- Primary extract button ---
        self._extract_btn.configure(style="Primary.TButton")

        # --- Update 7z status indicator ---
        for c in self.root.winfo_children():
            if isinstance(c, ttk.Frame):
                for w in c.winfo_children():
                    pass  # no-op — the top labels are already built
        self.root.update_idletasks()

    # ============================================================
    #  File management
    # ============================================================

    def _add_files(self):
        paths = filedialog.askopenfilenames(
            title="选择压缩包",
            filetypes=[("所有文件", "*.*"),
                       ("压缩包格式", "*.zip;*.rar;*.7z;*.tar;*.gz;*.bz2;*.xz;*.zst;"
                        "*.cab;*.iso;*.arj;*.lzh;*.lha;*.tgz;*.tbz2;*.txz;*.001")])
        for p in paths:
            self._add_file_item(Path(p))

    def _add_directory(self):
        path = filedialog.askdirectory(title="选择包含压缩包的文件夹")
        if not path:
            return
        base = Path(path)
        for f in base.rglob("*"):
            if not f.is_file() or f.stat().st_size < 2:
                continue
            fmt = detect(f)
            if fmt is not None:
                self._add_file_item(f)
                continue
            lower = f.name.lower()
            if re.match(r".+\.\d{3,}$", lower) or re.match(r".+\.r\d{2,}$", lower) or \
               re.match(r".+\.part\d+\.rar$", lower):
                self._add_file_item(f)

    def _on_drop_files(self, files):
        for f in files:
            if isinstance(f, bytes):
                f = f.decode("gbk", errors="replace")
            p = f.strip()
            if p:
                self._add_file_item(Path(p))

    def _get_split_dedup_key(self, path: Path) -> Path | None:
        """Return canonical first-volume path for dedup.
        Covers files that are already split archives and files that will
        become split archives after rename (e.g. .part1.jpg → .part1.rar)."""
        if is_split_archive(path):
            return get_first_volume(path).resolve()
        if needs_rename(path):
            target = get_correct_path(path)
            if target and is_split_archive(target):
                target_vols = find_volumes(target)
                if target_vols:
                    return (path.parent / target_vols[0].name).resolve()
        return None

    def _add_file_item(self, path: Path):
        if path.is_dir():
            for f in path.iterdir():
                if f.is_file() and f.stat().st_size >= 2:
                    fmt = detect(f)
                    if fmt is not None:
                        self._add_file_item(f)
                        continue
                    lower = f.name.lower()
                    if re.match(r".+\.\d{3,}$", lower) or re.match(r".+\.r\d{2,}$", lower) or \
                       re.match(r".+\.part\d+\.rar$", lower):
                        self._add_file_item(f)
            return
        if not path.is_file():
            return
        # Resolve split archives to first volume for dedup, including
        # files that will become split archives after rename (e.g. .part1.jpg → .part1.rar).
        dedup_key = self._get_split_dedup_key(path) or path.resolve()
        for f in self._files:
            f_key = self._get_split_dedup_key(f.path) or f.path.resolve()
            if dedup_key == f_key:
                return
        item = ArchiveFileItem(path)
        fmt = detect_with_tar_combo(path)
        item.detected_format = fmt.name if fmt else "未知"
        if needs_rename(path):
            item.will_rename = True
            correct = get_correct_path(path)
            item.target_name = correct.name if correct else ""
        if is_split_archive(path):
            item.is_split = True
            vols = find_volumes(path)
            item.volume_count = len(vols)
        elif item.will_rename and item.target_name:
            target = path.with_name(item.target_name)
            if is_split_archive(target):
                item.is_split = True
                item.volume_count = len(find_volumes(target))
        # Save currently selected paths before refresh clears them
        selected_paths = set()
        for iid in self._tree_pending.selection():
            idx = int(self._tree_pending.index(iid))
            if 0 <= idx < len(self._files):
                selected_paths.add(self._files[idx].path)
        self._files.append(item)
        selected_paths.add(item.path)  # new item should be selected too
        self._refresh_pending_list()
        # Restore selections (old + new) by matching paths
        for iid in self._tree_pending.get_children():
            idx = int(iid)
            if 0 <= idx < len(self._files) and self._files[idx].path in selected_paths:
                self._tree_pending.selection_add(iid)

    def _remove_selected(self):
        selected = self._tree_pending.selection()
        if not selected:
            return
        indices = sorted([int(self._tree_pending.index(iid)) for iid in selected], reverse=True)
        for i in indices:
            if 0 <= i < len(self._files):
                del self._files[i]
        self._refresh_pending_list()

    def _clear_pending(self):
        self._files.clear()
        self._refresh_pending_list()

    def _clear_completed(self):
        self._completed.clear()
        self._refresh_completed_list()

    def _refresh_pending_list(self):
        self._tree_pending.delete(*self._tree_pending.get_children())
        self._destroy_pwd_overlays()
        for i, f in enumerate(self._files):
            pwd_display = f.specific_password if f.specific_password else "□"

            self._tree_pending.insert("", "end", iid=str(i),
                                      values=(i + 1, f.path.name, f.detected_format,
                                              pwd_display, str(f.path.parent)))
        # Toggle drop hint based on whether there are any items
        if self._tree_pending.get_children():
            self._pending_drop_hint.place_forget()
        else:
            self._pending_drop_hint.place(relx=0.5, rely=0.5, anchor="center")
        self._update_output_preview()
        self._tree_pending.after_idle(self._create_pwd_overlays)

    def _on_tree_scroll(self, *args):
        """Scroll handler that also refreshes pwd overlays."""
        self._tree_pending.yview(*args)
        self._tree_pending.after_idle(self._create_pwd_overlays)

    # ── Password cell overlay boxes ──────────────────────────────

    def _create_pwd_overlays(self):
        """Draw subtle border boxes over password cells."""
        self._destroy_pwd_overlays()
        self._pwd_overlays = []
        C = self._C
        inset = 2  # px inset from cell edge
        for iid in self._tree_pending.get_children():
            bbox = self._tree_pending.bbox(iid, "密码")
            if not bbox:
                continue
            x, y, w, h = bbox
            f = tk.Frame(self._tree_pending, bg=C["hairline"],
                         width=w - inset * 2, height=h - inset * 2)
            f.place(x=x + inset, y=y + inset, width=w - inset * 2, height=h - inset * 2)
            f.bind("<Button-1>", lambda e, i=iid: self._on_overlay_click(i))
            f.bind("<Enter>", lambda e, fr=f: fr.configure(bg=C["mute"]))
            f.bind("<Leave>", lambda e, fr=f: fr.configure(bg=C["hairline"]))
            # Inner fill (gives the "hollow box" appearance)
            inner = tk.Frame(f, bg=C["canvas"], width=(w - inset * 2) - 2,
                             height=(h - inset * 2) - 2)
            inner.place(x=1, y=1, relwidth=1, relheight=1, width=-2, height=-2)
            for wgt in (f, inner):
                wgt.bind("<Button-1>", lambda e, i=iid: self._on_overlay_click(i))
            self._pwd_overlays.append(f)

    def _destroy_pwd_overlays(self):
        for f in getattr(self, "_pwd_overlays", []):
            try:
                f.destroy()
            except Exception:
                pass
        self._pwd_overlays = []

    def _on_overlay_click(self, iid: str):
        """Handle click on password overlay box."""
        self._tree_pending.selection_set(iid)
        self._tree_pending.after(50, lambda: self._begin_pwd_edit(iid))

    def _refresh_completed_list(self):
        self._tree_done.delete(*self._tree_done.get_children())
        for f in self._completed:
            status_icon = "✓" if f.status == "done" else "✗"
            self._tree_done.insert("", "end",
                                   values=(f.path.name, f.output_path or "-", status_icon))

    def _refresh_status(self):
        pending = len(self._files)
        done = len(self._completed)
        self._status_label.configure(text=f"待解压: {pending} | 已完成: {done}")

    # ============================================================
    #  Right-click menu
    # ============================================================

    def _on_pending_right_click(self, event):
        iid = self._tree_pending.identify_row(event.y)
        if iid:
            if iid not in self._tree_pending.selection():
                self._tree_pending.selection_set(iid)
            self._pwd_menu.post(event.x_root, event.y_root)

    def _copy_file_path(self):
        """Copy the path of selected pending files to clipboard."""
        selected = self._tree_pending.selection()
        if not selected:
            return
        paths = []
        for iid in selected:
            idx = int(iid)
            if 0 <= idx < len(self._files):
                paths.append(str(self._files[idx].path))
        if paths:
            self.root.clipboard_clear()
            self.root.clipboard_append("\n".join(paths))

    def _on_tree_click(self, event):
        """Handle left-click: toggle row selection, or inline edit on password column."""
        self._end_pwd_edit()
        region = self._tree_pending.identify_region(event.x, event.y)
        if region != "cell":
            return
        iid = self._tree_pending.identify_row(event.y)
        if not iid:
            return
        col = self._tree_pending.identify_column(event.x)

        if col == "#4":
            # Password column — open inline edit
            self._begin_pwd_edit(iid)
        else:
            # Toggle clicked row: select if unselected, deselect if already selected
            if iid in self._tree_pending.selection():
                self._tree_pending.selection_remove(iid)
            else:
                self._tree_pending.selection_add(iid)
        return "break"  # prevent tkinter's default selection behavior

    def _begin_pwd_edit(self, iid: str):
        """Overlay an Entry widget on the password cell."""
        idx = int(iid)
        if idx < 0 or idx >= len(self._files):
            return
        bbox = self._tree_pending.bbox(iid, "密码")
        if not bbox:
            return
        x, y, w, h = bbox
        current = self._files[idx].specific_password
        entry = tk.Entry(self._tree_pending,
                         bg=self._C["surface"], fg=self._C["body"],
                         insertbackground=self._C["body"],
                         font=("Segoe UI", 10),
                         relief="solid", borderwidth=1)
        entry.place(x=x, y=y, width=w, height=h)
        entry.insert(0, current)
        entry.focus_set()
        entry.bind("<Return>", lambda e: self._end_pwd_edit(save=True))
        entry.bind("<Escape>", lambda e: self._end_pwd_edit(save=False))
        entry.bind("<FocusOut>", lambda e: self._end_pwd_edit(save=True))
        self._pwd_edit_entry = entry
        self._pwd_edit_iid = iid

    def _end_pwd_edit(self, save: bool = True):
        """Destroy overlay entry. If save, persist the password."""
        if self._pwd_edit_entry is None:
            return
        if save and self._pwd_edit_iid is not None:
            idx = int(self._pwd_edit_iid)
            if 0 <= idx < len(self._files):
                pwd = self._pwd_edit_entry.get().strip()
                self._files[idx].specific_password = pwd
        try:
            self._pwd_edit_entry.destroy()
        except Exception:
            pass
        self._pwd_edit_entry = None
        self._pwd_edit_iid = None
        if save:
            self._refresh_pending_list()

    def _set_file_password(self):
        selected = self._tree_pending.selection()
        if not selected:
            return
        pwd = simpledialog.askstring("设置密码", "为该文件指定解压密码（留空则不使用密码）:",
                                     parent=self.root, show="*")
        if pwd is None:
            return
        for iid in selected:
            idx = int(self._tree_pending.index(iid))
            if 0 <= idx < len(self._files):
                self._files[idx].specific_password = pwd.strip()
        self._refresh_pending_list()

    def _clear_file_password(self):
        selected = self._tree_pending.selection()
        if not selected:
            return
        for iid in selected:
            idx = int(self._tree_pending.index(iid))
            if 0 <= idx < len(self._files):
                self._files[idx].specific_password = ""
        self._refresh_pending_list()

    # ============================================================
    #  Options
    # ============================================================

    def _open_password_editor(self):
        dlg = PasswordEditorDialog(self.root, self._password_manager,
                                    app_colors=self._C,
                                    config_file=self._config_file,
                                    on_change=lambda: None)
        self._position_dialog(dlg, side="left")
        self._update_pwd_count_display()

    def _export_passwords(self):
        path = filedialog.asksaveasfilename(title="导出密码", defaultextension=".txt",
                                            filetypes=[("文本文件", "*.txt")])
        if path:
            count = self._password_manager.save(path)
            if count > 0:
                self._logger.log(f"密码已导出到: {path} ({count} 个)")
            else:
                self._logger.log("密码列表为空，未导出")

    def _load_config(self):
        try:
            if self._config_file.is_file():
                with open(self._config_file, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                return cfg.get("password_file", "")
        except Exception:
            pass
        return ""

    def _save_config(self, password_file_path: str):
        try:
            self._config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._config_file, "w", encoding="utf-8") as f:
                json.dump({"password_file": str(password_file_path)}, f)
        except Exception:
            pass

    def _load_persistent_passwords(self):
        """Auto-load passwords on startup."""
        if self._password_file.is_file():
            count = self._password_manager.load()
            if count:
                self._logger.log(f"已加载 {count} 个密码")

    def _update_pwd_count_display(self):
        total = self._password_manager.total_count
        if total:
            self._pwd_count_label.configure(text=f"({total} 个密码)")
        else:
            self._pwd_count_label.configure(text="(暂无密码)")

    def _get_default_output_dir(self) -> Path | None:
        """Return the parent directory of the first pending file, or None."""
        if self._files:
            return self._files[0].path.parent
        return None

    def _update_output_preview(self, *_):
        pass

    def _on_output_dir_focus_in(self, event):
        """Clear placeholder when user clicks into the output dir entry."""
        if self._output_dir_entry.get() == self._PLACEHOLDER:
            self._output_dir_entry.delete(0, "end")
            self._output_dir_entry.configure(fg=self._C["body"])

    def _on_output_dir_key(self, event):
        """Sync entry content to _output_dir on each keystroke."""
        text = self._output_dir_entry.get().strip()
        if text == self._PLACEHOLDER:
            self._output_dir.set("")
        else:
            self._output_dir.set(text)

    def _on_output_dir_focus_out(self, event):
        """Restore placeholder if user left the entry empty."""
        if not self._output_dir_entry.get().strip():
            self._output_dir.set("")
            self._output_dir_entry.delete(0, "end")
            self._output_dir_entry.insert(0, self._PLACEHOLDER)
            self._output_dir_entry.configure(fg=self._C["mute"])

    def _on_custom_output_toggle(self):
        """Enable/disable output directory entry when checkbox toggles."""
        if self._custom_output.get():
            self._output_dir_entry.configure(state="normal")
            self._browse_output_btn.configure(state="normal")
        else:
            self._output_dir_entry.configure(state="disabled")
            self._browse_output_btn.configure(state="disabled")

    def _browse_output_dir(self):
        """Open folder picker to override the output directory."""
        current = self._output_dir.get() or str(self._get_default_output_dir() or ".")
        path = filedialog.askdirectory(title="选择输出目录", initialdir=current)
        if path:
            self._output_dir.set(path)
            self._output_dir_entry.delete(0, "end")
            self._output_dir_entry.insert(0, path)
            self._output_dir_entry.configure(fg=self._C["body"])

    def _get_output_path(self, item) -> Path:
        """Compute the output directory for an archive item."""
        if self._custom_output.get():
            override = self._output_dir.get()
            base_dir = Path(override) if override else item.path.parent
        else:
            base_dir = item.path.parent
        if self._output_mode.get() == "subfolder":
            name = self._subfolder_name.get().strip() or item.path.stem
            return base_dir / name
        else:
            return base_dir

    # ============================================================
    #  Extraction flow
    # ============================================================

    def _get_selected_items(self) -> list[ArchiveFileItem]:
        """Return file items selected in the pending treeview."""
        selected = self._tree_pending.selection()
        items = []
        for iid in selected:
            idx = int(self._tree_pending.index(iid))
            if 0 <= idx < len(self._files):
                items.append(self._files[idx])
        return items

    def _start_extraction(self):
        selected_items = self._get_selected_items()
        if not selected_items:
            messagebox.showinfo("提示", "请先在待解压列表中选中要解压的文件（蓝色项）")
            return
        pending = [f for f in selected_items if f.status not in ("done", "processing")]
        if not pending:
            if messagebox.askyesno("提示", "所选文件已处理完毕，是否重新解压？"):
                # Move completed back to pending
                self._files.extend(self._completed)
                self._completed.clear()
                for f in self._files:
                    f.status = "pending"
                    f.error_msg = ""
                self._refresh_pending_list()
                self._refresh_completed_list()
            else:
                return
        self._cancel_flag.clear()
        self._extract_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._progress.configure(value=0)
        self._logger.log("=" * 50)
        self._logger.log("开始解压任务...")
        self._current_thread = threading.Thread(target=self._extraction_worker, daemon=True)
        self._current_thread.start()

    def _stop_extraction(self):
        self._cancel_flag.set()
        self._logger.log("[用户] 正在停止...")

    @staticmethod
    def _recycle_file(filepath: Path) -> bool:
        """Move a file to the Windows recycle bin. Returns True on success."""
        try:
            path_str = str(filepath.resolve())
            buf = ctypes.create_unicode_buffer(path_str + "\0\0")

            fop = _SHFILEOPSTRUCTW()
            fop.hwnd = None
            fop.wFunc = 3  # FO_DELETE
            fop.pFrom = ctypes.cast(buf, ctypes.c_wchar_p)
            fop.pTo = None
            fop.fFlags = 0x0040 | 0x0010 | 0x0400  # FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_NOERRORUI
            result = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(fop))
            return result == 0 and not fop.fAnyOperationsAborted
        except Exception:
            return False

    def _delete_archive_files(self, archive_path: Path) -> int:
        """Delete or recycle archive file(s) after successful extraction.

        For split archives, processes all volumes. Returns count of processed files.
        """
        mode = self._delete_mode.get()
        if mode == "none":
            return 0

        files: list[Path] = []
        if is_split_archive(archive_path):
            files = [v for v in find_volumes(archive_path) if v.exists()]
        elif archive_path.exists():
            files = [archive_path]

        processed = 0
        for f in files:
            try:
                if mode == "recycle":
                    if self._recycle_file(f):
                        self._ui_log(f"  已移到回收站: {f.name}")
                        processed += 1
                    else:
                        self._ui_log(f"  ⚠ 回收失败: {f.name}")
                elif mode == "delete":
                    f.unlink()
                    self._ui_log(f"  已删除: {f.name}")
                    processed += 1
            except OSError as e:
                self._ui_log(f"  ⚠ 处理失败: {f.name} - {e}")
        return processed

    def _try_password_list(self, archive_path, output_dir, passwords, progress_cb):
        tried = 0
        for pwd in passwords:
            if self._cancel_flag.is_set():
                return (False, None, "已取消")
            tried += 1
            try:
                result = extract(archive_path, output_dir, password=pwd, progress_callback=progress_cb)
                if result.success:
                    return (True, pwd, None)
                if not result.password_wrong:
                    return (False, None, result.error)
            except ExtractError as e:
                return (False, None, str(e))
            if tried % 50 == 0:
                self._ui_log(f"  已尝试 {tried}/{len(passwords)} 个密码...")
        return (False, None, "密码字典未找到正确密码")

    def _extract_one(self, archive_path, item, output_dir=None):
        """Extract one archive. Returns (output_dir, password_used).

        If output_dir is given, extract there directly (used by smart-mode
        work-dir extraction). Otherwise the directory is determined by
        output_mode, subfolder_name, and _output_dir.
        """
        item_output = Path(output_dir) if output_dir else self._get_output_path(item)
        item_output.mkdir(parents=True, exist_ok=True)
        auto_pwd = self._auto_password.get()
        final_password = None

        def progress_cb(pct, line):
            if "Ok" in line or "Everything is Ok" in line:
                return
            self.root.after(0, lambda: self._progress.configure(value=pct))

        # Step 1: per-file specific password
        if item.specific_password:
            self._ui_log(f"  尝试指定密码...")
            try:
                result = extract(archive_path, item_output, password=item.specific_password,
                                 progress_callback=progress_cb)
                if result.success:
                    self._ui_log(f"  ✓ 指定密码正确")
                    self._save_password_to_library(item.specific_password)
                    item.status = "done"
                    return (str(item_output), item.specific_password)
                elif result.password_wrong:
                    self._ui_log(f"  ✗ 指定密码错误")
                    if not auto_pwd:
                        item.status = "error"
                        item.error_msg = "指定密码错误"
                        return (str(item_output), None)
                else:
                    self._ui_log(f"  ✗ {result.error}")
                    item.status = "error"
                    item.error_msg = result.error
                    return (str(item_output), None)
            except ExtractError as e:
                self._ui_log(f"  ✗ {e}")
                item.status = "error"
                item.error_msg = str(e)
                return (str(item_output), None)

        # Step 2: no password
        if item.status != "done":
            try:
                result = extract(archive_path, item_output, progress_callback=progress_cb)
                if result.success:
                    self._ui_log(f"  ✓ 解压完成 ({result.files_extracted} 个文件)")
                    item.status = "done"
                    return (str(item_output), None)
            except ExtractError as e:
                self._ui_log(f"  ✗ {e}")
                item.status = "error"
                item.error_msg = str(e)
                return (str(item_output), None)

        # Step 3: dictionary
        if auto_pwd and item.status != "done":
            passwords = [p for p in self._password_manager.get_all_passwords() if p != ""]
            self._ui_log(f"  需要密码，开始尝试字典 ({len(passwords)} 个)...")
            success, pwd, err = self._try_password_list(archive_path, item_output, passwords, progress_cb)
            if success:
                self._ui_log(f"  ✓ 找到密码: {pwd}")
                self._save_password_to_library(pwd)
                final_password = pwd
                item.status = "done"
            else:
                if err:
                    self._ui_log(f"  ✗ {err}")
                item.status = "error"
                item.error_msg = err or "密码错误"
        elif item.status != "done":
            self._ui_log(f"  需要密码，但未开启自动尝试")
            item.status = "error"
            item.error_msg = "需要密码"

        if item.status == "done":
            self._ui_log(f"  ✓ 解压到: {item_output}")
        return (str(item_output), final_password)

    # ============================================================
    #  Smart nested detection — peel algorithm
    # ============================================================

    def _peel_recursive(self, dirpath: Path, peeled: set, password_ctx: str | None):
        """Recursively peel nested archives in-place.

        For each directory: if an executable binary is found the directory
        is left untouched (archives stay). Otherwise every compressible
        archive is extracted into the *same* directory (no subfolder) and
        added to ``peeled`` for later cleanup.

        The outer caller is responsible for creating the initial work
        directory — this function never creates subfolders for extraction.
        """
        while True:
            if self._cancel_flag.is_set():
                return

            entries = list(dirpath.iterdir())
            files = [e for e in entries if e.is_file() and e.resolve() not in peeled]
            subdirs = [e for e in entries if e.is_dir()]

            # Stop condition: executable binary → don't touch archives here
            for f in files:
                if is_executable_binary(f):
                    return

            # Recurse into subdirectories first (depth-first)
            for sd in sorted(subdirs):
                self._peel_recursive(sd, peeled, password_ctx)

            # Re-read after recursion may have changed subdirs
            entries = list(dirpath.iterdir())
            files = [e for e in entries if e.is_file() and e.resolve() not in peeled]

            # Collect unpeeled archives
            archives: list[Path] = []
            for f in files:
                if is_split_archive(f):
                    first = get_first_volume(f)
                    if first.resolve() not in peeled:
                        archives.append(first)
                elif detect(f) is not None:
                    archives.append(f)

            if not archives:
                return

            # Peel one archive — extract in-place, no subfolder
            archive = archives[0]

            # Split volumes
            if is_split_archive(archive):
                vols = find_volumes(archive)
                first_vol = vols[0] if vols else archive
            else:
                vols = [archive]
                first_vol = archive

            # Rename if needed
            working = first_vol
            if not is_split_archive(working) and self._auto_rename.get() and needs_rename(working):
                correct = get_correct_path(working)
                if correct:
                    new_path = working.with_name(correct.name)
                    if not new_path.exists():
                        try:
                            working.rename(new_path)
                            self._ui_log(f"  已改名: {working.name} → {correct.name}")
                            working = new_path
                            first_vol = new_path
                        except OSError:
                            pass

            self._ui_log(f"  [揭皮] {first_vol.name}")

            # Attempt extraction: inherit parent password → no password → dictionary
            success = False
            found_pwd = None
            auto_pwd = self._auto_password.get()

            # Try parent password
            if password_ctx:
                try:
                    r = extract(first_vol, dirpath, password=password_ctx)
                    if r.success:
                        self._ui_log(f"    ✓ 解压完成 (继承密码)")
                        success = True
                        found_pwd = password_ctx
                except ExtractError:
                    pass

            # Try no password
            if not success:
                try:
                    r = extract(first_vol, dirpath)
                    if r.success:
                        self._ui_log(f"    ✓ 解压完成 (无密码)")
                        success = True
                except ExtractError:
                    pass

            # Try dictionary
            if not success and auto_pwd:
                passwords = [p for p in self._password_manager.get_all_passwords()
                             if p not in {password_ctx, ""}]
                for pwd in passwords:
                    if self._cancel_flag.is_set():
                        break
                    try:
                        r = extract(first_vol, dirpath, password=pwd)
                        if r.success:
                            self._ui_log(f"    ✓ 解压完成 (密码: {pwd})")
                            self._save_password_to_library(pwd)
                            success = True
                            found_pwd = pwd
                            break
                    except ExtractError:
                        break
                if not success:
                    self._ui_log(f"    ⚠ 密码字典未匹配")

            # Mark all volumes as peeled and remove them immediately.
            # Nested archives are deleted on the spot — "peeling" means
            # extracting their contents then discarding the shell.
            for v in vols:
                peeled.add(v.resolve())
                try:
                    v.unlink()
                except OSError:
                    pass

            if success and found_pwd:
                password_ctx = found_pwd

            # Loop — new content may contain more archives or executables

    def _flatten_and_clean(self, output_dir: str):
        """Collapse single-folder wrappers recursively (bottom-up)."""
        path = Path(output_dir)
        if not path.is_dir():
            return
        changed = True
        while changed:
            changed = False
            contents = list(path.iterdir())
            dirs = [d for d in contents if d.is_dir()]

            # Recurse into subdirectories first (bottom-up)
            for d in sorted(dirs):
                self._flatten_and_clean(str(d))

            # Re-read after recursion may have collapsed subdirectories
            contents = list(path.iterdir())
            dirs = [d for d in contents if d.is_dir()]

            # Collapse if a single directory with no sibling files,
            # or if the sole directory name matches a file's stem (extraction shell).
            files = [f for f in contents if f.is_file()]
            should_flatten = False
            if len(dirs) == 1:
                if len(files) == 0:
                    should_flatten = True
                elif any(dirs[0].name.lower() == f.stem.lower() for f in files):
                    should_flatten = True
            if should_flatten:
                inner = dirs[0]
                moved = 0
                for item in inner.iterdir():
                    target = path / item.name
                    if not target.exists():
                        item.rename(target)
                        moved += 1
                try:
                    inner.rmdir()
                except OSError:
                    pass
                if moved > 0:
                    self._ui_log(f"  [展平] {inner.name}/ → {path.name}/")
                    changed = True


    # ============================================================
    #  Extraction worker
    # ============================================================

    def _extraction_worker(self):
        # Iterate a snapshot since we mutate self._files during the loop
        snapshot = list(self._files)
        all_to_delete: list[Path] = []

        for i, item in enumerate(snapshot):
            if self._cancel_flag.is_set():
                break
            if item.status == "done":
                continue

            item.status = "processing"
            self._ui_update_all()

            self._ui_log(f"[{i + 1}/{len(snapshot)}] {item.path.name}")

            # Step 1: Detect format
            fmt = detect_with_tar_combo(item.path)
            if fmt is None:
                self._ui_log(f"  ✗ 无法识别格式，跳过")
                item.status = "error"
                item.error_msg = "无法识别格式"
                self._ui_update_all()
                continue
            self._ui_log(f"  检测格式: {fmt.name} ({', '.join(fmt.extensions)})")

            # Step 2: Split volumes
            archive_path = item.path
            if is_split_archive(archive_path):
                vols = find_volumes(archive_path)
                if len(vols) > 1:
                    self._ui_log(f"  检测到分卷: {len(vols)} 个")
                    for v in vols:
                        self._ui_log(f"    - {v.name}")
                first_vol = vols[0] if vols else archive_path
            else:
                first_vol = archive_path

            # Step 3: Rename
            if not is_split_archive(archive_path) and self._auto_rename.get() and needs_rename(item.path):
                correct = get_correct_path(item.path)
                if correct:
                    new_path = item.path.with_name(correct.name)
                    if not new_path.exists():
                        try:
                            item.path.rename(new_path)
                            self._ui_log(f"  已改名: {item.path.name} → {correct.name}")
                            archive_path = new_path
                            first_vol = new_path
                            item.path = new_path
                        except OSError as e:
                            self._ui_log(f"  ⚠ 改名失败: {e}")
                    else:
                        self._ui_log(f"  ⚠ 目标文件已存在，跳过改名")

            # Step 2b: Re-check split after rename (.part1.jpg → .part1.rar)
            if not item.is_split and is_split_archive(archive_path):
                vols = find_volumes(archive_path)
                if len(vols) > 1:
                    self._ui_log(f"  检测到分卷 (改名后): {len(vols)} 个")
                    for v in vols[:6]:
                        self._ui_log(f"    - {v.name}")
                first_vol = vols[0] if vols else archive_path
                item.is_split = True
                item.volume_count = len(vols)

            # Step 4: Extract — smart mode uses a temporary work directory,
            # normal mode extracts directly to the output directory.
            if self._custom_output.get():
                # --- Smart mode ---
                work_dir = item.path.parent / item.path.stem
                if work_dir.exists():
                    work_dir = item.path.parent / (item.path.stem + "_extract")
                item_output, parent_pwd = self._extract_one(first_vol, item,
                                                            output_dir=str(work_dir))
                item.output_path = item_output

                if item.status == "done":
                    # Peel nested archives in-place (they are deleted as they are peeled)
                    peeled: set[Path] = set()
                    self._peel_recursive(work_dir, peeled, parent_pwd)

                    # Move contents to final output directory
                    final_output = self._get_output_path(item)
                    final_output.mkdir(parents=True, exist_ok=True)
                    for entry in list(work_dir.iterdir()):
                        target = final_output / entry.name
                        if not target.exists():
                            shutil.move(str(entry), str(target))
                    item.output_path = str(final_output)

                    # Remove empty work directory
                    try:
                        work_dir.rmdir()
                    except OSError:
                        self._ui_log(f"  ⚠ 工作目录非空: {work_dir.name}")

                    # Flatten
                    self._flatten_and_clean(str(final_output))
            else:
                # --- Normal mode ---
                item_output, parent_pwd = self._extract_one(first_vol, item)
                item.output_path = item_output

            # Step 5: Collect outer archive for deferred deletion
            if item.status == "done" and self._delete_mode.get() != "none":
                if is_split_archive(archive_path):
                    all_to_delete.extend([v for v in find_volumes(archive_path) if v.exists()])
                elif archive_path.exists():
                    all_to_delete.append(archive_path)

            # Move to completed — schedule on main thread to avoid race conditions
            if item.status in ("done", "error"):
                self.root.after(0, lambda i=item: (self._files.remove(i), self._completed.append(i)))

            self._ui_update_all()
            self.root.after(0, lambda: self._progress.configure(value=0))

        # Step 7: Delete all successfully extracted archives (outer + nested)
        if all_to_delete and self._delete_mode.get() != "none":
            self._ui_log("")
            self._ui_log(f"清理压缩包 ({len(all_to_delete)} 个)...")
            for p in sorted(set(all_to_delete), key=lambda x: str(x)):
                if not p.exists() or self._cancel_flag.is_set():
                    continue
                if self._delete_mode.get() == "recycle":
                    if self._recycle_file(p):
                        self._ui_log(f"  已移到回收站: {p.name}")
                        self._recycled_items.append((str(p.resolve()), time.time()))
                    else:
                        self._ui_log(f"  ⚠ 回收失败: {p.name}")
                elif self._delete_mode.get() == "delete":
                    try:
                        p.unlink()
                        self._ui_log(f"  已删除: {p.name}")
                    except OSError as e:
                        self._ui_log(f"  ⚠ 删除失败: {p.name} - {e}")

        self.root.after(0, self._on_extraction_done)

    def _on_extraction_done(self):
        self._extract_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        done_count = sum(1 for f in self._completed if f.status == "done")
        fail_count = sum(1 for f in self._completed if f.status == "error")
        self._logger.log(f"完成: {done_count} 成功, {fail_count} 失败")
        self._refresh_status()
        if fail_count == 0 and done_count > 0:
            self._progress.configure(value=100)
        if self._open_after.get() and done_count > 0:
            last = next((f for f in reversed(self._completed) if f.status == "done"), None)
            if last and last.output_path:
                os.startfile(last.output_path)

    def _open_recycle_restore(self):
        """Open Windows recycle bin."""
        import subprocess
        subprocess.Popen(["explorer", "shell:RecycleBinFolder"])

    def _on_recycled_items_changed(self, remaining):
        """Callback when recycle items list is modified by restore dialog."""
        self._recycled_items[:] = remaining

    # ============================================================
    #  Password cracking
    # ============================================================

    def _get_selected_file_paths(self) -> list[str]:
        """Return paths of all selected pending files (may be empty)."""
        selected = self._tree_pending.selection()
        paths = []
        for iid in selected:
            idx = int(self._tree_pending.index(iid))
            if 0 <= idx < len(self._files):
                paths.append(str(self._files[idx].path))
        return paths

    def _open_crack_from_menu(self):
        """Open crack dialog from right-click menu."""
        paths = self._get_selected_file_paths()
        if not paths:
            return
        self._open_crack_dialog_for_paths(paths)

    def _open_crack_dialog(self):
        """Open crack dialog from toolbar button (uses all selected files)."""
        paths = self._get_selected_file_paths()
        if not paths:
            messagebox.showinfo("提示", "请先在待解压列表中选中要破解的文件（蓝色项）", parent=self.root)
            return
        self._open_crack_dialog_for_paths(paths)

    def _open_crack_dialog_for_paths(self, archive_paths: list[str]):
        """Open the crack dialog for multiple selected archive files."""
        dlg = CrackDialog(self.root, archive_paths,
                          app_colors=self._C,
                          on_password_found=lambda pwd: self._on_crack_passwords_found(archive_paths, pwd))
        self._position_dialog(dlg, side="right")

    @staticmethod
    def _position_dialog(dialog: tk.Toplevel, side: str = "left"):
        """Snap dialog to main-window midline, vertically centered."""
        dialog.withdraw()
        dialog.update_idletasks()
        master = dialog.master
        m_x = master.winfo_rootx()
        m_y = master.winfo_rooty()
        m_w = master.winfo_width()
        m_h = master.winfo_height()
        # Actual size (1 means unmapped → fall back to requested)
        d_w = dialog.winfo_width()
        d_h = dialog.winfo_height()
        if d_w <= 1:
            d_w = dialog.winfo_reqwidth()
        if d_h <= 1:
            d_h = dialog.winfo_reqheight()
        mid_x = m_x + m_w // 2
        top = m_y + (m_h - d_h) // 2
        if side == "left":
            left = mid_x - d_w   # right edge touches midline
        else:
            left = mid_x         # left edge touches midline
        dialog.geometry(f"{d_w}x{d_h}+{max(0, left)}+{max(0, top)}")
        dialog.deiconify()

    def _save_password_to_library(self, password: str):
        """Save a working password to the password library."""
        if password and self._password_manager.add(password):
            self._update_pwd_count_display()

    def _on_crack_passwords_found(self, archive_paths: list[str], password: str):
        """When password is cracked, set it on all matching file items and save to library."""
        norms = {str(Path(p).resolve()) for p in archive_paths}
        for f in self._files:
            if str(f.path.resolve()) in norms:
                f.specific_password = password
                self._logger.log(f"密码已填入: {f.path.name}")
        self._save_password_to_library(password)
        self._refresh_pending_list()

    # ============================================================
    #  UI helpers
    # ============================================================

    def _ui_log(self, message: str):
        self.root.after(0, lambda: self._logger.log(message))

    def _ui_update_all(self):
        self.root.after(0, self._refresh_pending_list)
        self.root.after(0, self._refresh_completed_list)
        self.root.after(0, self._refresh_status)


class RecycleBinRestoreDialog(tk.Toplevel):
    """Dialog to restore files from Windows Recycle Bin."""

    def __init__(self, parent, recycled_items: list, *,
                 app_colors=None, on_restore=None):
        super().__init__(parent)
        self.title("从回收站还原")
        self.geometry("650x420")
        self.minsize(500, 300)
        self._C = app_colors or {"canvas": "#15181d", "surface": "#1c2026",
                                  "elevated": "#22262d", "card": "#292d35",
                                  "hairline": "#343840", "ink": "#e8eaed",
                                  "body": "#b8bcc4", "mute": "#8a8f98",
                                  "blue": "#5dade2", "green": "#58d68d",
                                  "red": "#ec7063"}
        self.configure(bg=self._C["canvas"])
        self._items = recycled_items  # list of (path_str, timestamp)
        self._on_restore = on_restore
        self._check_vars: list[tk.BooleanVar] = []
        self.transient(parent)
        self.grab_set()
        self._build_ui()
        self._populate()

    def _build_ui(self):
        C = self._C
        ttk.Label(self, text="以下文件已被本软件移入回收站，选中后点「还原」恢复：",
                  font=("Segoe UI", 10)).pack(fill=tk.X, padx=12, pady=(12, 8))

        tree_frame = ttk.Frame(self)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

        self._tree = ttk.Treeview(tree_frame,
                                  columns=("文件名", "原始路径", "删除时间"),
                                  show="headings", selectmode="extended")
        self._tree.column("文件名", width=180)
        self._tree.column("原始路径", width=280)
        self._tree.column("删除时间", width=140)
        self._tree.heading("文件名", text="文件名")
        self._tree.heading("原始路径", text="原始路径")
        self._tree.heading("删除时间", text="删除时间")

        scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=scroll.set)
        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self._status_label = ttk.Label(self, text="", foreground=C["mute"])
        self._status_label.pack(fill=tk.X, padx=12, pady=(4, 8))

        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=12, pady=(0, 12))
        ttk.Button(btn_frame, text="全选", command=self._select_all).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_frame, text="取消全选", command=self._deselect_all).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="还原选中", command=self._restore_selected).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="关闭", command=self._close).pack(side=tk.RIGHT, padx=4)

    def _populate(self):
        from datetime import datetime
        self._tree.delete(*self._tree.get_children())
        for path_str, ts in self._items:
            p = Path(path_str)
            dt = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            self._tree.insert("", "end", values=(p.name, str(p.parent), dt))
        self._status_label.configure(text=f"共 {len(self._items)} 条记录")

    def _close(self):
        self.destroy()

    def _select_all(self):
        self._tree.selection_set(self._tree.get_children())

    def _deselect_all(self):
        self._tree.selection_set()

    def _get_user_sid(self) -> str | None:
        """Get the current user's SID string."""
        import ctypes.wintypes
        name = ctypes.create_unicode_buffer(256)
        name_size = ctypes.wintypes.DWORD(256)
        if not ctypes.windll.advapi32.GetUserNameW(name, ctypes.byref(name_size)):
            return None
        sid_size = ctypes.wintypes.DWORD(0)
        dom_size = ctypes.wintypes.DWORD(0)
        sid_use = ctypes.c_int()
        ctypes.windll.advapi32.LookupAccountNameW(
            None, name, None, ctypes.byref(sid_size),
            None, ctypes.byref(dom_size), ctypes.byref(sid_use))
        sid = ctypes.create_string_buffer(sid_size.value)
        domain = ctypes.create_unicode_buffer(dom_size.value)
        if not ctypes.windll.advapi32.LookupAccountNameW(
                None, name, sid, ctypes.byref(sid_size),
                domain, ctypes.byref(dom_size), ctypes.byref(sid_use)):
            return None
        sid_str = ctypes.c_wchar_p()
        if not ctypes.windll.advapi32.ConvertSidToStringSidW(sid, ctypes.byref(sid_str)):
            return None
        return sid_str.value

    def _scan_recycle_bin(self, target_paths: set) -> dict:
        """Scan recycle bin on relevant drives. Returns {original_path: r_file_path}."""
        sid = self._get_user_sid()
        if not sid:
            return {}

        # Collect unique drives from target paths
        drives = set()
        for p in target_paths:
            if len(p) >= 2 and p[1] == ":":
                drives.add(p[0].upper())

        import struct
        matches = {}
        for drive in drives:
            rb_dir = Path(f"{drive}:/$Recycle.Bin/{sid}")
            if not rb_dir.is_dir():
                continue
            for f in rb_dir.iterdir():
                if not f.name.startswith("$I"):
                    continue
                try:
                    data = f.read_bytes()
                    if len(data) < 28:
                        continue
                    header = struct.unpack_from("<Q", data, 0)[0]
                    if header != 2:
                        continue
                    path_len = struct.unpack_from("<I", data, 24)[0]
                    if 28 + path_len * 2 > len(data):
                        continue
                    raw = data[28:28 + path_len * 2]
                    orig = raw.decode("utf-16-le")
                    norm = str(Path(orig).resolve())
                    if norm in target_paths:
                        r_file = rb_dir / ("$R" + f.name[2:])
                        if r_file.is_file():
                            matches[norm] = r_file
                except Exception:
                    continue
        return matches

    def _restore_selected(self):
        selected = self._tree.selection()
        if not selected:
            return
        indices = sorted([int(self._tree.index(iid)) for iid in selected])
        target_paths = {str(Path(self._items[i][0]).resolve()) for i in indices if 0 <= i < len(self._items)}

        # Debug: check SID and drives
        sid = self._get_user_sid()
        drives = set()
        for p in target_paths:
            if len(p) >= 2 and p[1] == ":":
                drives.add(p[0].upper())

        matches = self._scan_recycle_bin(target_paths)

        restored_indices = set()
        failed = 0
        errors = []
        for idx in reversed(indices):
            if idx < 0 or idx >= len(self._items):
                continue
            path_str, ts = self._items[idx]
            norm = str(Path(path_str).resolve())
            r_file = matches.get(norm)
            if not r_file:
                errors.append(f"未在回收站找到: {Path(path_str).name}")
                failed += 1
                continue
            if self._restore_file(r_file, path_str):
                restored_indices.add(idx)
            else:
                errors.append(f"还原失败: {Path(path_str).name}")
                failed += 1

        remaining = [item for i, item in enumerate(self._items) if i not in restored_indices]
        self._items[:] = remaining
        self._populate()

        msg = f"已还原 {len(restored_indices)} 个文件"
        if failed:
            msg += f"，{failed} 个失败"
        # Append debug info
        msg += f" | SID: {sid[:12] if sid else '无'}..."
        msg += f" 盘符: {','.join(sorted(drives)) if drives else '无'}"
        msg += f" 匹配: {len(matches)}/{len(target_paths)}"
        if errors:
            msg += f" ({'; '.join(errors[:2])})"
        self._status_label.configure(text=msg)
        if self._on_restore:
            self._on_restore(remaining)

    @staticmethod
    def _restore_file(r_file: Path, original_path: str) -> bool:
        """Move a file from recycle bin back to its original location."""
        try:
            orig = Path(original_path)
            orig.parent.mkdir(parents=True, exist_ok=True)
            r_str = str(r_file.resolve()) + "\0\0"
            buf = ctypes.create_unicode_buffer(r_str)
            dest_str = str(orig.resolve()) + "\0\0"
            dest_buf = ctypes.create_unicode_buffer(dest_str)

            fop = _SHFILEOPSTRUCTW()
            fop.hwnd = None
            fop.wFunc = 1  # FO_MOVE
            fop.pFrom = ctypes.cast(buf, ctypes.c_wchar_p)
            fop.pTo = ctypes.cast(dest_buf, ctypes.c_wchar_p)
            fop.fFlags = 0x0400  # FOF_NOERRORUI
            result = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(fop))
            return result == 0 and not fop.fAnyOperationsAborted
        except Exception:
            return False

    def _ui_log(self, message: str):
        self._status_label.configure(text=message)


def main():
    root = tk.Tk()
    SmartExtractorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
