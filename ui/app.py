"""Smart Archive Extractor — GUI Application."""

import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from pathlib import Path
import threading
import re
import ctypes

import windnd

from core.detector import detect_with_tar_combo, detect
from core.split_detector import find_volumes, is_split_archive
from core.renamer import get_correct_path, needs_rename
from core.extractor import extract, find_7z, ExtractError, scan_for_archives
from core.password import PasswordManager, save_builtin_passwords


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
                 app_colors=None, on_change=None):
        super().__init__(parent)
        self.title("密码库")
        self.geometry("480x480")
        self.minsize(400, 350)
        self._C = app_colors or {
            "canvas": "#15181d", "surface": "#1c2026", "elevated": "#22262d",
            "card": "#292d35", "hairline": "#343840", "ink": "#e8eaed",
            "body": "#b8bcc4", "mute": "#8a8f98", "blue": "#5dade2",
        }
        self.configure(bg=self._C["canvas"])
        self._pm = password_manager
        self._mode = tk.StringVar(value="builtin")
        self._on_change = on_change
        self.transient(parent)
        self.grab_set()
        self._build_ui()
        self._refresh_list()

    def _build_ui(self):
        C = self._C

        tab_frame = ttk.Frame(self)
        tab_frame.pack(fill=tk.X, padx=12, pady=(12, 8))
        ttk.Button(tab_frame, text="内置密码", command=lambda: self._switch("builtin")).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(tab_frame, text="自定义密码", command=lambda: self._switch("custom")).pack(side=tk.LEFT, padx=4)
        self._tab_label = ttk.Label(tab_frame, text="")
        self._tab_label.pack(side=tk.RIGHT)

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

        add_frame = ttk.Frame(self)
        add_frame.pack(fill=tk.X, padx=12, pady=4)
        ttk.Label(add_frame, text="新增").pack(side=tk.LEFT)
        self._add_entry = ttk.Entry(add_frame, width=25)
        self._add_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)
        self._add_entry.bind("<Return>", lambda e: self._add_password())
        ttk.Button(add_frame, text="添加", command=self._add_password).pack(side=tk.LEFT)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=12, pady=4)
        ttk.Button(btn_frame, text="删除选中", command=self._delete_selected).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_frame, text="导入文件", command=self._import_file).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="导出文件", command=self._export_file).pack(side=tk.LEFT, padx=4)

        self._status_label = ttk.Label(self, text="", foreground=C["mute"])
        self._status_label.pack(fill=tk.X, padx=12, pady=(6, 12))
        ttk.Button(self, text="关闭", command=self._close).pack(pady=(0, 12))

    def _close(self):
        if self._on_change:
            self._on_change()
        self.destroy()

    def _switch(self, mode):
        self._mode.set(mode)
        self._refresh_list()

    def _refresh_list(self):
        self._listbox.delete(0, tk.END)
        if self._mode.get() == "builtin":
            passwords = self._pm._builtin
            self._tab_label.configure(text=f"内置密码 ({len(passwords)} 个)")
        else:
            passwords = self._pm._custom
            self._tab_label.configure(text=f"自定义密码 ({len(passwords)} 个)")
        for p in passwords:
            display = p if p else "(空密码)"
            self._listbox.insert(tk.END, display)
        total = self._pm.total_count
        self._status_label.configure(
            text=f"共 {total} 个密码 (内置 {self._pm.builtin_count} + 自定义 {self._pm.custom_count})")

    def _add_password(self):
        pwd = self._add_entry.get().strip()
        if not pwd:
            return
        if self._pm.add(pwd):
            self._add_entry.delete(0, tk.END)
            if self._mode.get() != "custom":
                self._mode.set("custom")
            self._refresh_list()
        else:
            messagebox.showinfo("提示", "密码已存在或无效", parent=self)

    def _delete_selected(self):
        if self._mode.get() == "builtin":
            messagebox.showinfo("提示", "内置密码不可删除，请切换到自定义密码", parent=self)
            return
        selected = self._listbox.curselection()
        if not selected:
            return
        for idx in reversed(selected):
            if 0 <= idx < len(self._pm._custom):
                self._pm.remove(self._pm._custom[idx])
        self._refresh_list()

    def _import_file(self):
        path = filedialog.askopenfilename(parent=self, title="导入密码文件",
                                          filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if path:
            count = self._pm.load_custom(path)
            self._mode.set("custom")
            self._refresh_list()
            messagebox.showinfo("提示", f"已导入 {count} 个密码", parent=self)

    def _export_file(self):
        path = filedialog.asksaveasfilename(parent=self, title="导出自定义密码",
                                            defaultextension=".txt",
                                            filetypes=[("文本文件", "*.txt")])
        if path:
            count = self._pm.save_custom(path)
            if count > 0:
                messagebox.showinfo("提示", f"已导出 {count} 个自定义密码", parent=self)
            else:
                messagebox.showinfo("提示", "自定义密码为空，未导出", parent=self)


class SmartExtractorApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("智能解压工具")
        self.root.geometry("900x700")
        self.root.minsize(800, 550)

        self._files: list[ArchiveFileItem] = []
        self._completed: list[ArchiveFileItem] = []
        self._output_dir = Path.home() / "Extracted"
        self._password_manager = PasswordManager()
        # Store passwords next to the exe (PyInstaller) or in project root (source)
        if getattr(sys, "frozen", False):
            _exe_dir = Path(sys.executable).resolve().parent
        else:
            _exe_dir = Path(__file__).resolve().parent.parent
        self._password_file = _exe_dir / "passwords.txt"
        self._pwdfile_var = tk.StringVar()
        self._auto_rename = tk.BooleanVar(value=True)
        self._auto_password = tk.BooleanVar(value=True)
        self._delete_mode = tk.StringVar(value="none")  # "none" | "delete" | "recycle"
        self._wrap_folder = tk.BooleanVar(value=True)
        self._open_after = tk.BooleanVar(value=False)
        self._cancel_flag = threading.Event()
        self._current_thread: threading.Thread | None = None
        self._theme = tk.StringVar(value="slate")

        self._build_ui()
        self._apply_theme()
        self._load_persistent_passwords()
        self._update_pwd_count_display()
        self._refresh_status()

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
                                          columns=("#", "文件名", "格式", "操作"),
                                          show="headings", selectmode="extended", height=6)
        self._tree_pending.column("#", width=28, anchor="center")
        self._tree_pending.column("文件名", width=200)
        self._tree_pending.column("格式", width=70, anchor="center")
        self._tree_pending.column("操作", width=110, anchor="center")
        for c in ("#", "文件名", "格式", "操作"):
            self._tree_pending.heading(c, text=c)

        p_scroll = ttk.Scrollbar(pending_frame, orient=tk.VERTICAL, command=self._tree_pending.yview)
        self._tree_pending.configure(yscrollcommand=p_scroll.set)
        self._tree_pending.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        p_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Right-click menu for pending
        self._pwd_menu = tk.Menu(self.root, tearoff=0,
                                 bg=self._C["elevated"], fg=self._C["body"],
                                 activebackground=self._C["card"], activeforeground=self._C["ink"],
                                 borderwidth=1, relief="solid",
                                 font=("Segoe UI", 10))
        self._pwd_menu.add_command(label="设置密码...", command=self._set_file_password)
        self._pwd_menu.add_command(label="清除密码", command=self._clear_file_password)
        self._tree_pending.bind("<Button-3>", self._on_pending_right_click)

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

        # Right-click menu for completed
        self._done_menu = tk.Menu(self.root, tearoff=0,
                                  bg=self._C["elevated"], fg=self._C["body"],
                                  activebackground=self._C["card"], activeforeground=self._C["ink"],
                                  borderwidth=1, relief="solid",
                                  font=("Segoe UI", 10))
        self._done_menu.add_command(label="还原到待解压", command=self._restore_selected)
        self._tree_done.bind("<Button-3>", self._on_done_right_click)

        # --- Toolbar below panels ---
        toolbar = ttk.Frame(self.root)
        toolbar.pack(fill=tk.X, padx=12, pady=(0, 8))
        ttk.Button(toolbar, text="添加文件", command=self._add_files).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(toolbar, text="添加文件夹", command=self._add_directory).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="移除选中", command=self._remove_selected).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="清空列表", command=self._clear_pending).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="还原选中", command=self._restore_selected).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="清空已完成", command=self._clear_completed).pack(side=tk.LEFT, padx=4)

        # --- Options panel ---
        opt_frame = ttk.LabelFrame(self.root, text="选项", padding=(12, 10))
        opt_frame.pack(fill=tk.X, padx=12, pady=(0, 8))

        row1 = ttk.Frame(opt_frame)
        row1.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(row1, text="输出目录").pack(side=tk.LEFT)
        self._output_var = tk.StringVar(value=str(self._output_dir))
        ttk.Entry(row1, textvariable=self._output_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)
        ttk.Button(row1, text="浏览", command=self._browse_output).pack(side=tk.LEFT)

        row2 = ttk.Frame(opt_frame)
        row2.pack(fill=tk.X, pady=6)
        ttk.Label(row2, text="密码字典").pack(side=tk.LEFT)
        ttk.Entry(row2, textvariable=self._pwdfile_var, width=42).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)
        ttk.Button(row2, text="浏览", command=self._browse_password_file).pack(side=tk.LEFT)
        ttk.Button(row2, text="编辑", command=self._open_password_editor).pack(side=tk.LEFT, padx=(4, 0))
        ttk.Button(row2, text="导出", command=self._export_default_pwd).pack(side=tk.LEFT, padx=(4, 0))

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
        ttk.Radiobutton(row4, text="解压到压缩包目录", variable=self._wrap_folder, value=False).pack(side=tk.LEFT, padx=(8, 16))
        ttk.Radiobutton(row4, text="解压到同名文件夹", variable=self._wrap_folder, value=True).pack(side=tk.LEFT)

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

    def _add_file_item(self, path: Path):
        if not path.is_file():
            return
        for f in self._files:
            if f.path == path:
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
        self._files.append(item)
        self._refresh_pending_list()
        if len(self._files) == 1:
            self._output_dir = item.path.parent
            self._output_var.set(str(self._output_dir))

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
        for i, f in enumerate(self._files):
            action_parts = []
            if f.will_rename:
                action_parts.append(f"改名→{f.target_name}")
            if f.specific_password:
                action_parts.append("有密码")
            if f.is_split and f.volume_count > 1:
                action_parts.append(f"分卷({f.volume_count})")
            if not action_parts and f.detected_format != "未知":
                action_parts.append("直接解压")
            action = " ".join(action_parts)

            self._tree_pending.insert("", "end", iid=str(i),
                                      values=(i + 1, f.path.name, f.detected_format, action))

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

    def _on_done_right_click(self, event):
        iid = self._tree_done.identify_row(event.y)
        if iid:
            if iid not in self._tree_done.selection():
                self._tree_done.selection_set(iid)
            self._done_menu.post(event.x_root, event.y_root)

    def _restore_selected(self):
        """Move selected items from completed back to pending."""
        selected = self._tree_done.selection()
        if not selected:
            return
        indices = sorted([int(self._tree_done.index(iid)) for iid in selected], reverse=True)
        restored = 0
        for i in indices:
            if 0 <= i < len(self._completed):
                item = self._completed.pop(i)
                item.status = "pending"
                item.error_msg = ""
                item.output_path = ""
                self._files.append(item)
                restored += 1
        if restored:
            self._ui_log(f"已还原 {restored} 个文件到待解压列表")
        self._refresh_pending_list()
        self._refresh_completed_list()
        self._refresh_status()

    # ============================================================
    #  Options
    # ============================================================

    def _browse_output(self):
        path = filedialog.askdirectory(title="选择输出目录")
        if path:
            self._output_dir = Path(path)
            self._output_var.set(str(self._output_dir))

    def _browse_password_file(self):
        path = filedialog.askopenfilename(title="选择密码字典文件",
                                          filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if path:
            self._pwdfile_var.set(path)
            count = self._password_manager.load_custom(path)
            self._update_pwd_count_display()
            self._logger.log(f"已加载 {count} 个自定义密码")
            self._save_persistent_passwords()

    def _open_password_editor(self):
        PasswordEditorDialog(self.root, self._password_manager,
                             app_colors=self._C,
                             on_change=self._save_persistent_passwords)
        self._update_pwd_count_display()

    def _export_default_pwd(self):
        path = filedialog.asksaveasfilename(title="导出默认密码字典", defaultextension=".txt",
                                            filetypes=[("文本文件", "*.txt")])
        if path:
            save_builtin_passwords(path)
            self._logger.log(f"默认密码字典已导出到: {path}")

    def _load_persistent_passwords(self):
        """Auto-load custom passwords from passwords.txt on startup."""
        if self._password_file.is_file():
            count = self._password_manager.load_custom(self._password_file)
            if count:
                self._pwdfile_var.set(str(self._password_file))

    def _save_persistent_passwords(self):
        """Save custom passwords to passwords.txt."""
        if self._password_manager.custom_count > 0:
            self._password_manager.save_custom(self._password_file)
            self._pwdfile_var.set(str(self._password_file))

    def _update_pwd_count_display(self):
        total = self._password_manager.total_count
        custom = self._password_manager.custom_count
        if custom:
            self._pwd_count_label.configure(
                text=f"(内置{self._password_manager.builtin_count} + 自定义{custom} = {total}个密码)")
        else:
            self._pwd_count_label.configure(text=f"(内置 {self._password_manager.builtin_count} 个密码)")

    # ============================================================
    #  Extraction flow
    # ============================================================

    def _start_extraction(self):
        if not self._files:
            messagebox.showinfo("提示", "请先添加要解压的文件")
            return
        output = Path(self._output_var.get())
        if not output.exists():
            try:
                output.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                messagebox.showerror("错误", f"无法创建输出目录: {e}")
                return
        pending = [f for f in self._files if f.status not in ("done", "processing")]
        if not pending:
            if messagebox.askyesno("提示", "所有文件已处理完毕，是否重新解压？"):
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
        self._current_thread = threading.Thread(target=self._extraction_worker, args=(output,), daemon=True)
        self._current_thread.start()

    def _stop_extraction(self):
        self._cancel_flag.set()
        self._logger.log("[用户] 正在停止...")

    @staticmethod
    def _recycle_file(filepath: Path) -> bool:
        """Move a file to the Windows recycle bin. Returns True on success."""
        try:
            path_str = str(filepath.resolve())
            # SHFileOperationW expects double-null-terminated string
            buf = ctypes.create_unicode_buffer(path_str + "\0\0")
            op = ctypes.c_int(0)
            # FO_DELETE=3, FOF_ALLOWUNDO=0x40, FOF_WANTNUKEWARNING=0x4000
            result = ctypes.windll.shell32.SHFileOperationW(
                ctypes.byref(ctypes.c_uint(0)),  # hwnd
                op,                               # wFunc (unused by SHFileOperationW)
                ctypes.byref(ctypes.c_wchar_p(path_str)) if False else None,  # pFrom
                None,                             # pTo
                0x40 | 0x4000                     # fFlags: allow undo + no confirmation
            )
            # Correct way:
            import struct
            from ctypes import wintypes
            class SHFILEOPSTRUCTW(ctypes.Structure):
                _fields_ = [
                    ("hwnd", wintypes.HWND),
                    ("wFunc", ctypes.c_uint),
                    ("pFrom", ctypes.c_wchar_p),
                    ("pTo", ctypes.c_wchar_p),
                    ("fFlags", ctypes.c_ushort),
                    ("fAnyOperationsAborted", wintypes.BOOL),
                    ("hNameMappings", ctypes.c_void_p),
                    ("lpszProgressTitle", ctypes.c_wchar_p),
                ]
            fop = SHFILEOPSTRUCTW()
            fop.hwnd = 0
            fop.wFunc = 3  # FO_DELETE
            fop.pFrom = buf
            fop.pTo = None
            fop.fFlags = 0x0040  # FOF_ALLOWUNDO
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

    def _extract_one(self, archive_path, item, output):
        """Extract one archive. Returns (output_dir, password_used).

        Output always goes to the archive's original directory.
        'wrap_folder' controls whether a subfolder named after the archive is created.
        """
        base_dir = item.path.parent
        if self._wrap_folder.get():
            item_output = base_dir / item.path.stem
        else:
            item_output = base_dir
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
    #  Smart nested detection
    # ============================================================

    def _check_smart_nested(self, output_dir: str, parent_password: str | None):
        """Check extraction result. Auto-extract single wrapped archive,
        ask user for complex structures."""
        out_path = Path(output_dir)
        if not out_path.is_dir():
            return
        contents = list(out_path.iterdir())
        if len(contents) != 1 or not contents[0].is_dir():
            return  # multiple files or empty — nothing to auto-detect

        inner_dir = contents[0]
        inner_files = [f for f in inner_dir.iterdir() if f.is_file()]
        inner_dirs = [d for d in inner_dir.iterdir() if d.is_dir()]

        # Pattern A: single file, detected as archive → auto-extract
        if len(inner_files) == 1 and len(inner_dirs) == 0:
            sole = inner_files[0]
            if detect(sole) is not None:
                self._ui_log(f"  [智能] 检测到嵌套归档: {inner_dir.name}/{sole.name}")
                self._process_single_nested(sole, parent_password)
                return

        # Pattern B: complex structure → auto-scan for archives
        if len(inner_files) > 0 or len(inner_dirs) > 0:
            self._ui_log(f"  [嵌套] {out_path.name}/{inner_dir.name}/ 内含:")
            for f in inner_files:
                fmt = detect(f)
                tag = f" [{fmt.name}]" if fmt else ""
                self._ui_log(f"    - {f.name}{tag}")
            for d in inner_dirs:
                self._ui_log(f"    - {d.name}/")
            self._process_nested_dir(str(inner_dir), parent_password)

    def _process_single_nested(self, filepath: Path, parent_password: str | None):
        """Extract a single nested archive file."""
        if self._cancel_flag.is_set():
            return
        fmt = detect_with_tar_combo(filepath)
        if fmt is None:
            return
        self._ui_log(f"    → {filepath.name} [{fmt.name}]")

        working = filepath
        # Split detection
        if is_split_archive(working):
            vols = find_volumes(working)
            if len(vols) > 1:
                self._ui_log(f"      分卷: {len(vols)} 个")
                for v in vols[:6]:
                    self._ui_log(f"        - {v.name}")
            first_vol = vols[0] if vols else working
        else:
            first_vol = working

        # Rename if needed
        if not is_split_archive(working) and self._auto_rename.get() and needs_rename(working):
            correct = get_correct_path(working)
            if correct and not working.with_name(correct.name).exists():
                try:
                    new_path = working.with_name(correct.name)
                    working.rename(new_path)
                    working = new_path
                    first_vol = new_path
                    self._ui_log(f"      已改名: {filepath.name} → {correct.name}")
                except OSError:
                    pass

        # Output dir
        if self._wrap_folder.get():
            stem = Path(first_vol.name).stem
            stem = re.sub(r'\.part\d+', '', stem, flags=re.IGNORECASE)
            stem = re.sub(r'\.r\d{2,}$', '', stem, flags=re.IGNORECASE)
            stem = re.sub(r'\.\d{3,}$', '', stem, flags=re.IGNORECASE)
            stem = stem.rstrip('.') or first_vol.stem
            nest_output = first_vol.parent / stem
        else:
            nest_output = first_vol.parent
        nest_output.mkdir(parents=True, exist_ok=True)

        # Extract
        success = False
        nested_pwd = None
        auto_pwd = self._auto_password.get()

        # Parent password first
        if parent_password:
            try:
                r = extract(first_vol, nest_output, password=parent_password)
                if r.success:
                    self._ui_log(f"      ✓ 解压完成 (继承上级密码)")
                    success = True
                    nested_pwd = parent_password
            except ExtractError:
                pass

        # No password
        if not success:
            try:
                r = extract(first_vol, nest_output)
                if r.success:
                    self._ui_log(f"      ✓ 解压完成 (无密码)")
                    success = True
            except ExtractError:
                pass

        # Dictionary
        if not success and auto_pwd:
            passwords = [p for p in self._password_manager.get_all_passwords()
                         if p not in {parent_password, ""}]
            for pwd in passwords:
                if self._cancel_flag.is_set():
                    break
                try:
                    r = extract(first_vol, nest_output, password=pwd)
                    if r.success:
                        self._ui_log(f"      ✓ 解压完成 (密码: {pwd})")
                        success = True
                        nested_pwd = pwd
                        break
                except ExtractError:
                    break
            if not success:
                self._ui_log(f"      ⚠ 密码字典未匹配")

        if success:
            if (self._delete_mode.get() != "none"):
                self._delete_archive_files(first_vol)
            self._check_smart_nested(str(nest_output), nested_pwd or parent_password)

    def _flatten_and_clean(self, output_dir: str):
        """Collapse single-folder wrappers and delete leftover archives recursively."""
        path = Path(output_dir)
        changed = True
        while changed:
            changed = False
            # Delete any remaining archive files (e.g. missed inner archives)
            for f in sorted(path.iterdir()):
                if f.is_file() and detect(f) is not None:
                    self._ui_log(f"  [清理] 删除残留: {f.name}")
                    self._delete_archive_files(f)

            # If there's exactly one folder and nothing else, collapse it
            contents = list(path.iterdir())
            dirs = [d for d in contents if d.is_dir()]
            files = [f for f in contents if f.is_file()]
            if len(dirs) == 1 and len(files) == 0:
                inner = dirs[0]
                self._ui_log(f"  [展平] {inner.name}/ → {path.name}/")
                for item in inner.iterdir():
                    item.rename(path / item.name)
                inner.rmdir()
                changed = True

    def _process_nested_dir(self, dirpath: str, parent_password: str | None):
        """Scan a directory for archives and extract them."""
        nested = scan_for_archives(dirpath)
        if not nested:
            return
        self._ui_log(f"  [嵌套处理] 发现 {len(nested)} 个压缩包")
        for npath in nested:
            if self._cancel_flag.is_set():
                return
            self._process_single_nested(npath, parent_password)

    # ============================================================
    #  Extraction worker
    # ============================================================

    def _extraction_worker(self, output: Path):
        # Iterate a snapshot since we mutate self._files during the loop
        snapshot = list(self._files)
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

            # Step 4: Extract
            item_output, parent_pwd = self._extract_one(first_vol, item, output)
            item.output_path = item_output

            # Delete archive after successful extraction
            if item.status == "done" and (self._delete_mode.get() != "none"):
                self._delete_archive_files(first_vol)

            # Move to completed
            if item.status in ("done", "error"):
                self._files.remove(item)
                self._completed.append(item)

            self._ui_update_all()
            self.root.after(0, lambda: self._progress.configure(value=0))

            # Step 5: Smart nested detection
            if item.status == "done":
                self._check_smart_nested(item_output, parent_pwd)
                # Flatten single-folder wrappers and clean leftover archives
                self._flatten_and_clean(item_output)

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
            import os
            last = next((f for f in reversed(self._completed) if f.status == "done"), None)
            if last and last.output_path:
                os.startfile(last.output_path)

    # ============================================================
    #  UI helpers
    # ============================================================

    def _ui_log(self, message: str):
        self.root.after(0, lambda: self._logger.log(message))

    def _ui_update_all(self):
        self.root.after(0, self._refresh_pending_list)
        self.root.after(0, self._refresh_completed_list)
        self.root.after(0, self._refresh_status)


def main():
    root = tk.Tk()
    SmartExtractorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
