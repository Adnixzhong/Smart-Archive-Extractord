"""CrackDialog — password cracking configuration and progress UI."""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import threading

from core.cracker import (
    CHARSET_PRESETS,
    CrackConfig,
    CrackSession,
)
from core.tool_manager import (
    get_tool_status,
    download_tool,
    TOOL_DEFS,
    is_tool_available,
)


class CrackDialog(tk.Toplevel):
    """Dialog for configuring and running password cracking attacks."""

    def __init__(self, parent, archive_path: str, *,
                 app_colors=None, on_password_found=None):
        super().__init__(parent)
        self.title("密码破解")
        self.geometry("620x600")
        self.minsize(550, 500)
        self._C = app_colors or {
            "canvas": "#15181d", "surface": "#1c2026", "elevated": "#22262d",
            "card": "#292d35", "hairline": "#343840", "ink": "#e8eaed",
            "body": "#b8bcc4", "mute": "#8a8f98", "blue": "#5dade2",
            "green": "#58d68d", "red": "#ec7063", "yellow": "#f4d03f",
        }
        self.configure(bg=self._C["canvas"])
        self._archive_path = archive_path
        self._on_password_found = on_password_found

        self._running = False
        self._session: CrackSession | None = None
        self._worker_thread: threading.Thread | None = None
        self._cancel_flag = threading.Event()

        # GPU state
        self._gpu_enabled = tk.BooleanVar(value=False)
        self._gpu_tool_status: dict[str, bool] = {}
        self._gpu_downloading = False

        self.transient(parent)
        self.grab_set()
        self._build_ui()

    # ============================================================
    #  UI Construction
    # ============================================================

    def _build_ui(self):
        C = self._C
        p = Path(self._archive_path)

        # Buttons at the bottom (always visible, outside scroll area)
        btn_frame = ttk.Frame(self, padding=(12, 8))
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM)
        self._start_btn = ttk.Button(btn_frame, text="开始破解", command=self._start)
        self._start_btn.pack(side=tk.LEFT, padx=(0, 4))
        self._stop_btn = ttk.Button(btn_frame, text="停止", command=self._stop,
                                    state="disabled")
        self._stop_btn.pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="关闭", command=self._close).pack(side=tk.RIGHT, padx=4)

        # Scrollable canvas for all content above buttons
        canvas = tk.Canvas(self, bg=C["canvas"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        canvas.configure(yscrollcommand=scrollbar.set)

        self._content = ttk.Frame(canvas)
        self._content_id = canvas.create_window((0, 0), window=self._content, anchor="nw")

        # Bind configure for scrolling
        def _configure_scroll(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
        self._content.bind("<Configure>", _configure_scroll)

        def _canvas_configure(event):
            canvas.itemconfig(self._content_id, width=event.width)
        canvas.bind("<Configure>", _canvas_configure)

        # Mousewheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(-1 * (event.delta // 120), "units")
        canvas.bind("<Enter>", lambda e: canvas.bind_all("<MouseWheel>", _on_mousewheel))
        canvas.bind("<Leave>", lambda e: canvas.unbind_all("<MouseWheel>"))

        cf = self._content  # short alias — all content goes here

        # Header
        ttk.Label(cf, text=f"目标: {p.name}",
                  font=("Segoe UI", 11, "bold")).pack(fill=tk.X, padx=12, pady=(12, 4))

        # --- Attack type ---
        type_frame = ttk.LabelFrame(cf, text="攻击方式", padding=(10, 8))
        type_frame.pack(fill=tk.X, padx=12, pady=(8, 4))

        self._attack_type = tk.StringVar(value="bruteforce")
        types = [
            ("暴力破解 — 尝试所有字符组合", "bruteforce"),
            ("字典攻击 — 从密码字典文件加载", "dictionary"),
            ("掩码攻击 — 按模式生成 (? = 未知字符)", "mask"),
        ]
        for text, value in types:
            rb = ttk.Radiobutton(type_frame, text=text, variable=self._attack_type,
                                value=value, command=self._on_type_changed)
            rb.pack(anchor="w", pady=2)

        # --- Charset selection (for brute force & mask) ---
        self._charset_frame = ttk.LabelFrame(cf, text="字符集", padding=(10, 8))
        self._charset_frame.pack(fill=tk.X, padx=12, pady=4)

        self._charset_preset = tk.StringVar(value="数字 (0-9)")
        preset_cb = ttk.Combobox(self._charset_frame, textvariable=self._charset_preset,
                                values=list(CHARSET_PRESETS.keys()), state="readonly", width=30)
        preset_cb.pack(fill=tk.X, pady=2)
        preset_cb.bind("<<ComboboxSelected>>", lambda e: self._update_charset_preview())

        self._charset_custom_var = tk.StringVar(value="")
        ttk.Label(self._charset_frame, text="或自定义字符（留空则使用预设）:",
                  font=("Segoe UI", 9)).pack(anchor="w", pady=(6, 2))
        custom_entry = tk.Entry(self._charset_frame, textvariable=self._charset_custom_var,
                               bg=C["surface"], fg=C["body"], insertbackground=C["body"],
                               font=("Cascadia Code", 10), relief="solid", borderwidth=1)
        custom_entry.pack(fill=tk.X, pady=2)

        self._charset_preview = ttk.Label(self._charset_frame, text="", foreground=C["mute"])
        self._charset_preview.pack(anchor="w", pady=(4, 0))
        self._update_charset_preview()

        # --- Length range ---
        self._length_frame = ttk.LabelFrame(cf, text="长度范围", padding=(10, 8))
        self._length_frame.pack(fill=tk.X, padx=12, pady=4)

        len_inner = ttk.Frame(self._length_frame)
        len_inner.pack(fill=tk.X)
        ttk.Label(len_inner, text="最小").pack(side=tk.LEFT)
        self._min_len = tk.IntVar(value=1)
        ttk.Spinbox(len_inner, from_=1, to=20, textvariable=self._min_len,
                    width=5).pack(side=tk.LEFT, padx=(4, 16))
        ttk.Label(len_inner, text="最大").pack(side=tk.LEFT)
        self._max_len = tk.IntVar(value=6)
        ttk.Spinbox(len_inner, from_=1, to=20, textvariable=self._max_len,
                    width=5).pack(side=tk.LEFT, padx=4)

        # --- Mask pattern ---
        self._mask_frame = ttk.LabelFrame(cf, text="掩码模式", padding=(10, 8))
        mask_inner = ttk.Frame(self._mask_frame)
        mask_inner.pack(fill=tk.X)
        ttk.Label(mask_inner, text="模式 (? = 字符集中的字符):").pack(side=tk.LEFT)
        self._mask_var = tk.StringVar(value="???")
        mask_entry = tk.Entry(mask_inner, textvariable=self._mask_var,
                             bg=C["surface"], fg=C["body"], insertbackground=C["body"],
                             font=("Cascadia Code", 11), relief="solid", borderwidth=1)
        mask_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)

        # --- Dictionary file + rules ---
        self._dict_frame = ttk.LabelFrame(cf, text="字典文件 + 规则", padding=(10, 8))

        dict_inner = ttk.Frame(self._dict_frame)
        dict_inner.pack(fill=tk.X)
        self._dict_var = tk.StringVar(value="")
        dict_entry = tk.Entry(dict_inner, textvariable=self._dict_var,
                             bg=C["surface"], fg=C["body"], insertbackground=C["body"],
                             font=("Segoe UI", 10), relief="solid", borderwidth=1)
        dict_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(dict_inner, text="浏览...", command=self._browse_dict).pack(side=tk.LEFT, padx=(4, 0))

        rules_label = ttk.Label(self._dict_frame, text="叠加规则（对字典词做变形）:",
                                font=("Segoe UI", 9))
        rules_label.pack(anchor="w", pady=(8, 2))

        rules_frame = ttk.Frame(self._dict_frame)
        rules_frame.pack(fill=tk.X)
        self._rule_vars: dict[str, tk.BooleanVar] = {}
        rule_texts = [
            ("lowercase", "转小写"), ("uppercase", "转大写"), ("capitalize", "首字母大写"),
            ("leet", "Leet 替换 (a→4, e→3...)"), ("append_numbers", "末尾加数字/年份"),
            ("prepend_numbers", "开头加数字/年份"), ("append_symbols", "末尾加符号"),
            ("prepend_symbols", "开头加符号"), ("reverse", "反转"), ("double", "重复"),
        ]
        row = ttk.Frame(rules_frame)
        row.pack(fill=tk.X)
        for i, (key, label) in enumerate(rule_texts):
            if i == 5:
                row = ttk.Frame(rules_frame)
                row.pack(fill=tk.X, pady=(2, 0))
            var = tk.BooleanVar(value=(key in ("lowercase", "uppercase")))
            self._rule_vars[key] = var
            cb = tk.Checkbutton(row, text=label, variable=var,
                               bg=C["canvas"], fg=C["body"],
                               selectcolor=C["elevated"],
                               activebackground=C["elevated"],
                               activeforeground=C["ink"],
                               font=("Segoe UI", 9))
            cb.pack(side=tk.LEFT, padx=(0, 12))

        # --- Hybrid mask rules ---
        hybrid_label = ttk.Label(self._dict_frame, text="掩码组合（使用上方字符集，? = 字符集中字符）:",
                                 font=("Segoe UI", 9))
        hybrid_label.pack(anchor="w", pady=(8, 2))

        hybrid_inner = ttk.Frame(self._dict_frame)
        hybrid_inner.pack(fill=tk.X)
        self._append_mask_var = tk.BooleanVar(value=False)
        self._prepend_mask_var = tk.BooleanVar(value=False)
        append_cb = tk.Checkbutton(hybrid_inner, text="末尾追加掩码", variable=self._append_mask_var,
                                   bg=C["canvas"], fg=C["body"],
                                   selectcolor=C["elevated"],
                                   activebackground=C["elevated"],
                                   activeforeground=C["ink"],
                                   font=("Segoe UI", 9))
        append_cb.pack(side=tk.LEFT)
        self._append_mask_entry = tk.Entry(hybrid_inner,
                                           bg=C["surface"], fg=C["body"],
                                           insertbackground=C["body"],
                                           font=("Cascadia Code", 10),
                                           relief="solid", borderwidth=1, width=10)
        self._append_mask_entry.pack(side=tk.LEFT, padx=(6, 16))

        prepend_cb = tk.Checkbutton(hybrid_inner, text="开头追加掩码", variable=self._prepend_mask_var,
                                    bg=C["canvas"], fg=C["body"],
                                    selectcolor=C["elevated"],
                                    activebackground=C["elevated"],
                                    activeforeground=C["ink"],
                                    font=("Segoe UI", 9))
        prepend_cb.pack(side=tk.LEFT)
        self._prepend_mask_entry = tk.Entry(hybrid_inner,
                                            bg=C["surface"], fg=C["body"],
                                            insertbackground=C["body"],
                                            font=("Cascadia Code", 10),
                                            relief="solid", borderwidth=1, width=10)
        self._prepend_mask_entry.pack(side=tk.LEFT, padx=(6, 0))

        # --- Settings ---
        settings_frame = ttk.LabelFrame(cf, text="设置", padding=(10, 8))
        settings_frame.pack(fill=tk.X, padx=12, pady=4)

        settings_inner = ttk.Frame(settings_frame)
        settings_inner.pack(fill=tk.X)
        ttk.Label(settings_inner, text="并行线程").pack(side=tk.LEFT)
        self._threads = tk.IntVar(value=min(4, os.cpu_count() or 4))
        ttk.Spinbox(settings_inner, from_=1, to=16, textvariable=self._threads,
                    width=5).pack(side=tk.LEFT, padx=(4, 16))
        ttk.Label(settings_inner, text="时间限制(分钟, 0=不限)").pack(side=tk.LEFT)
        self._time_limit = tk.IntVar(value=0)
        ttk.Spinbox(settings_inner, from_=0, to=1440, textvariable=self._time_limit,
                    width=5).pack(side=tk.LEFT, padx=4)

        # --- GPU acceleration ---
        self._gpu_frame = ttk.LabelFrame(cf, text="GPU 加速 (hashcat)", padding=(10, 8))
        self._gpu_frame.pack(fill=tk.X, padx=12, pady=4)

        gpu_row1 = ttk.Frame(self._gpu_frame)
        gpu_row1.pack(fill=tk.X)
        gpu_cb = tk.Checkbutton(gpu_row1, text="启用 GPU 加速 (需要 hashcat + 兼容显卡)",
                                variable=self._gpu_enabled,
                                command=self._on_gpu_toggled,
                                bg=C["canvas"], fg=C["body"],
                                selectcolor=C["elevated"],
                                activebackground=C["elevated"],
                                activeforeground=C["ink"],
                                font=("Segoe UI", 9))
        gpu_cb.pack(side=tk.LEFT)

        # Tools directory picker
        from core.tool_manager import TOOLS_DIR
        gpu_tools_dir_row = ttk.Frame(self._gpu_frame)
        gpu_tools_dir_row.pack(fill=tk.X, pady=(6, 2))
        ttk.Label(gpu_tools_dir_row, text="工具目录:",
                  font=("Segoe UI", 9)).pack(side=tk.LEFT)
        self._tools_dir_var = tk.StringVar(value=str(TOOLS_DIR))
        tools_dir_entry = tk.Entry(gpu_tools_dir_row, textvariable=self._tools_dir_var,
                                   bg=C["surface"], fg=C["body"], insertbackground=C["body"],
                                   font=("Segoe UI", 9), relief="solid", borderwidth=1)
        tools_dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        ttk.Button(gpu_tools_dir_row, text="浏览...",
                   command=self._browse_tools_dir).pack(side=tk.LEFT)
        self._gpu_download_btn = ttk.Button(gpu_tools_dir_row, text="下载工具...",
                                             command=self._download_gpu_tools)
        self._gpu_download_btn.pack(side=tk.LEFT, padx=(4, 0))

        self._gpu_status_frame = ttk.Frame(self._gpu_frame)
        self._gpu_status_frame.pack(fill=tk.X, pady=(6, 0))
        self._gpu_status_labels: dict[str, ttk.Label] = {}
        for name in ["hashcat", "rar2john"]:
            lbl = ttk.Label(self._gpu_status_frame, text=f"  {name}: 检测中...",
                            font=("Segoe UI", 9), foreground=C["mute"])
            lbl.pack(anchor="w")
            self._gpu_status_labels[name] = lbl

        self._refresh_gpu_status()

        # --- Progress ---
        progress_frame = ttk.LabelFrame(cf, text="进度", padding=(10, 8))
        progress_frame.pack(fill=tk.X, padx=12, pady=4)

        self._status_label = ttk.Label(progress_frame, text="就绪",
                                       font=("Segoe UI", 10))
        self._status_label.pack(anchor="w")

        self._current_pwd_label = ttk.Label(progress_frame, text="",
                                            font=("Cascadia Code", 9), foreground=C["mute"])
        self._current_pwd_label.pack(anchor="w", pady=(2, 4))

        stats_inner = ttk.Frame(progress_frame)
        stats_inner.pack(fill=tk.X)
        self._speed_label = ttk.Label(stats_inner, text="速度: --", foreground=C["body"])
        self._speed_label.pack(side=tk.LEFT)
        self._attempts_label = ttk.Label(stats_inner, text="已尝试: --", foreground=C["body"])
        self._attempts_label.pack(side=tk.LEFT, padx=(16, 0))
        self._eta_label = ttk.Label(stats_inner, text="预计剩余: --", foreground=C["body"])
        self._eta_label.pack(side=tk.LEFT, padx=(16, 0))

        self._progress_bar = ttk.Progressbar(progress_frame, mode="indeterminate", length=400)
        self._progress_bar.pack(fill=tk.X, pady=(8, 0))

        self._on_type_changed()

    # ============================================================
    #  UI Callbacks
    # ============================================================

    def _on_type_changed(self):
        at = self._attack_type.get()
        # Length: only for bruteforce
        if at == "bruteforce":
            self._length_frame.pack(fill=tk.X, padx=12, pady=4,
                                    after=self._charset_frame)
        else:
            self._length_frame.pack_forget()
        # Mask: only for mask
        if at == "mask":
            self._mask_frame.pack(fill=tk.X, padx=12, pady=4,
                                  after=self._charset_frame)
        else:
            self._mask_frame.pack_forget()
        # Dictionary: only for dictionary
        if at == "dictionary":
            self._dict_frame.pack(fill=tk.X, padx=12, pady=4,
                                  after=self._charset_frame)
        else:
            self._dict_frame.pack_forget()
        # Charset is always visible (used by bruteforce, mask, and dictionary+mask hybrid)

    def _update_charset_preview(self):
        preset = self._charset_preset.get()
        chars = CHARSET_PRESETS.get(preset, "")
        preview = chars[:60] + ("..." if len(chars) > 60 else "")
        self._charset_preview.configure(text=f"字符: {preview}  (共 {len(chars)} 个字符)")

    def _browse_dict(self):
        path = filedialog.askopenfilename(
            title="选择密码字典文件",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
        )
        if path:
            self._dict_var.set(path)

    def _browse_tools_dir(self):
        path = filedialog.askdirectory(
            title="选择 GPU 工具安装目录",
            initialdir=self._tools_dir_var.get(),
        )
        if path:
            self._tools_dir_var.set(path)
            os.environ["SMART_AE_TOOLS_DIR"] = path
            # Invalidate cached tools_dir in tool_manager
            from core import tool_manager
            tool_manager.TOOLS_DIR = Path(path)
            self._refresh_gpu_status()

    def _get_selected_rules(self) -> list[str]:
        return [k for k, v in self._rule_vars.items() if v.get()]

    def _get_charset(self) -> str:
        custom = self._charset_custom_var.get().strip()
        if custom:
            return "".join(dict.fromkeys(custom))  # deduplicate, preserve order
        return CHARSET_PRESETS.get(self._charset_preset.get(), "0123456789")

    # ============================================================
    #  GPU
    # ============================================================

    def _refresh_gpu_status(self):
        self._gpu_tool_status = get_tool_status()
        for name, lbl in self._gpu_status_labels.items():
            ok = self._gpu_tool_status.get(name, False)
            lbl.configure(
                text=f"  {'✓' if ok else '✗'} {name}: {'已找到' if ok else '未找到'}",
                foreground=self._C["green"] if ok else self._C["red"],
            )

    def _on_gpu_toggled(self):
        self._refresh_gpu_status()
        if self._gpu_enabled.get():
            missing = [n for n, ok in self._gpu_tool_status.items() if not ok]
            if missing:
                messagebox.showwarning(
                    "GPU 工具缺失",
                    "以下工具未找到:\n  " + ", ".join(missing) + "\n\n请点击 [下载工具...] 按钮下载。",
                    parent=self,
                )

    def _download_gpu_tools(self):
        if self._gpu_downloading:
            return
        self._refresh_gpu_status()
        missing = [n for n, ok in self._gpu_tool_status.items() if not ok]
        if not missing:
            messagebox.showinfo("工具状态", "所有 GPU 工具已就绪。", parent=self)
            return

        msg = f"将下载以下工具:\n  {', '.join(missing)}\n\n下载可能需要几分钟。继续？"
        if not messagebox.askyesno("下载 GPU 工具", msg, parent=self):
            return

        self._gpu_downloading = True
        self._gpu_download_btn.configure(state="disabled")

        def _download_thread():
            for name in missing:
                self.after(0, lambda n=name: self._log_status(f"下载 {n}..."))
                ok, err_msg = download_tool(
                    name,
                    progress_callback=lambda pct, msg: self.after(
                        0, lambda p=msg: self._log_status(p)
                    ),
                )
                if not ok:
                    from core.tool_manager import TOOL_DEFS, TOOLS_DIR
                    exe = TOOL_DEFS[name]["exe"]
                    target = str(TOOLS_DIR / exe)
                    self.after(0, lambda n=name, e=err_msg, t=target:
                               messagebox.showerror("下载失败",
                                                    f"{n} 下载失败。\n\n"
                                                    f"错误: {e}\n\n"
                                                    f"请手动下载并放到:\n{t}",
                                                    parent=self))
            self._gpu_downloading = False
            self.after(0, self._refresh_gpu_status)
            self.after(0, lambda: self._gpu_download_btn.configure(state="normal"))
            self.after(0, lambda: self._log_status("就绪"))

        threading.Thread(target=_download_thread, daemon=True).start()

    def _close(self):
        if self._running:
            if messagebox.askyesno("确认", "破解正在进行中，确定要关闭吗？", parent=self):
                self._cancel_flag.set()
                self.destroy()
        else:
            self.destroy()

    # ============================================================
    #  Run
    # ============================================================

    def _start(self):
        if self._gpu_enabled.get():
            self._start_gpu()
            return

        at = self._attack_type.get()
        charset = self._get_charset()

        configs = []
        if at == "bruteforce":
            configs.append(CrackConfig(
                attack_type="bruteforce",
                charset=charset,
                min_length=self._min_len.get(),
                max_length=self._max_len.get(),
                threads=self._threads.get(),
                time_limit_minutes=self._time_limit.get(),
            ))
        elif at == "dictionary":
            dict_path = self._dict_var.get().strip()
            if not dict_path or not Path(dict_path).is_file():
                messagebox.showerror("错误", "请选择有效的字典文件", parent=self)
                return
            rules = self._get_selected_rules()
            append_mask = self._append_mask_entry.get().strip() if self._append_mask_var.get() else ""
            prepend_mask = self._prepend_mask_entry.get().strip() if self._prepend_mask_var.get() else ""
            configs.append(CrackConfig(
                attack_type="dictionary",
                charset=charset,
                dictionary_path=dict_path,
                rules=rules,
                append_mask=append_mask,
                prepend_mask=prepend_mask,
                threads=self._threads.get(),
                time_limit_minutes=self._time_limit.get(),
            ))
        elif at == "mask":
            pattern = self._mask_var.get().strip()
            if not pattern or "?" not in pattern:
                messagebox.showerror("错误", "掩码必须包含至少一个 ?", parent=self)
                return
            configs.append(CrackConfig(
                attack_type="mask",
                charset=charset,
                mask_pattern=pattern,
                threads=self._threads.get(),
                time_limit_minutes=self._time_limit.get(),
            ))

        if not configs:
            return

        self._running = True
        self._cancel_flag.clear()
        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._progress_bar.start(20)

        self._log_status("正在准备...")
        self._session = CrackSession(
            configs=configs,
            archive_path=self._archive_path,
            on_found=self._on_crack_found,
            on_progress=self._on_crack_progress,
            on_log=self._on_crack_log,
        )
        self._worker_thread = threading.Thread(target=self._crack_worker, daemon=True)
        self._worker_thread.start()

    # ============================================================
    #  GPU attack
    # ============================================================

    def _start_gpu(self):
        """Launch GPU-accelerated cracking via hashcat."""
        # Validate tools
        missing = [n for n in ["hashcat", "rar2john"]
                   if not is_tool_available(n)]
        if missing:
            messagebox.showerror("工具缺失",
                                 f"缺少: {', '.join(missing)}\n请先下载工具。",
                                 parent=self)
            return

        # Check for Bandizip incompatibility first
        from core.hash_extractor import extract_hash, is_zip_bandizip_incompatible

        bandizip_warning = is_zip_bandizip_incompatible(self._archive_path)
        if bandizip_warning:
            messagebox.showwarning("hashcat 兼容性警告", bandizip_warning, parent=self)
            # Don't block — user can still try, or cancel and switch to CPU

        self._log_status("提取哈希...")
        hash_result = extract_hash(self._archive_path)
        if hash_result is None:
            messagebox.showerror("提取失败",
                                 "无法提取密码哈希。\n可能原因：\n"
                                 "- 文件未加密\n- 格式不受支持\n"
                                 "- 缺少 rar2john / 7z2john",
                                 parent=self)
            return

        hash_str, hashcat_mode, fmt_name = hash_result
        self._log_status(f"哈希已提取 ({fmt_name}, 模式 {hashcat_mode})")

        # Build hashcat config
        from core.hashcat import HashcatConfig, HashcatSession

        at = self._attack_type.get()
        charset = self._get_charset()

        hc_config = HashcatConfig(
            attack_type=at,
            charset=charset,
            min_length=self._min_len.get(),
            max_length=self._max_len.get(),
            mask_pattern=self._mask_var.get().strip() if at == "mask" else "",
            dictionary_path=self._dict_var.get().strip() if at == "dictionary" else "",
            hashcat_mode=hashcat_mode,
            hash_str=hash_str,
            workload_profile=2,
            optimise_kernel=True,
            force=True,  # allow non-GPU OpenCL (CPU fallback via hashcat)
        )

        self._running = True
        self._cancel_flag.clear()
        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._progress_bar.start(20)
        self._log_status(f"启动 hashcat (模式 {hashcat_mode})...")

        self._hc_session = HashcatSession(
            config=hc_config,
            on_status=self._on_hashcat_status,
            on_cracked=self._on_hashcat_cracked,
            on_log=self._on_crack_log,
        )
        self._worker_thread = threading.Thread(target=self._gpu_worker, daemon=True)
        self._worker_thread.start()

    def _gpu_worker(self):
        try:
            password = self._hc_session.run() if hasattr(self, '_hc_session') else None
        except Exception as e:
            self.after(0, lambda: self._log_status(f"hashcat 错误: {e}"))
            password = None
        if password is None and hasattr(self, '_hc_session'):
            err = self._hc_session.error_message
            if err:
                self.after(0, lambda e=err: messagebox.showerror(
                    "hashcat 错误", f"GPU 破解失败:\n{e}", parent=self))
                self.after(0, lambda: self._on_crack_stopped())
                return
        # If hashcat exhausted without finding password, check for Bandizip
        if password is None and hasattr(self, '_hc_session'):
            from core.hash_extractor import is_zip_bandizip_incompatible
            bandizip_reason = is_zip_bandizip_incompatible(self._archive_path)
            if bandizip_reason:
                self.after(0, lambda r=bandizip_reason: messagebox.showwarning(
                    "Bandizip 兼容性提示",
                    f"hashcat 未找到密码。\n\n{r}\n\n"
                    "推荐使用 CPU 模式重试（取消勾选 GPU 加速）。",
                    parent=self))
        self.after(0, lambda: self._on_crack_done(password))

    def _on_hashcat_status(self, status: dict):
        """Parse hashcat machine-readable status."""
        speed = status.get("speed_hs", 0)
        progress_pct = status.get("progress_pct", 0)
        temp = status.get("gpu_temp", 0)
        eta = status.get("eta_seconds", 0)
        candidate = status.get("candidate", "")

        self.after(0, lambda: self._update_gpu_progress(speed, progress_pct, temp, eta, candidate))

    def _update_gpu_progress(self, speed: float, progress_pct: float, temp: int,
                             eta: int, candidate: str):
        if speed > 0:
            if speed >= 1_000_000_000:
                speed_str = f"{speed / 1_000_000_000:.1f} GH/s"
            elif speed >= 1_000_000:
                speed_str = f"{speed / 1_000_000:.1f} MH/s"
            elif speed >= 1_000:
                speed_str = f"{speed / 1_000:.1f} kH/s"
            else:
                speed_str = f"{speed:.0f} H/s"
        else:
            speed_str = "--"

        if eta > 0:
            h, m = int(eta // 3600), int((eta % 3600) // 60)
            if h > 0:
                eta_str = f"{h}h{m:02d}m"
            else:
                s = int(eta % 60)
                eta_str = f"{m}m{s:02d}s"
        else:
            eta_str = "--"

        self._speed_label.configure(text=f"GPU 速度: {speed_str}")
        self._attempts_label.configure(text=f"进度: {progress_pct:.1f}%")
        if temp > 0:
            self._eta_label.configure(text=f"GPU: {temp}°C | 预计剩余: {eta_str}")
        else:
            self._eta_label.configure(text=f"预计剩余: {eta_str}")
        if candidate:
            self._current_pwd_label.configure(text=f"候选: {candidate[:40]}")

    def _on_hashcat_cracked(self, password: str):
        pass  # handled in _on_crack_done

    def _stop(self):
        self._cancel_flag.set()
        if self._session:
            self._session.cancel()
        if hasattr(self, '_hc_session') and self._hc_session:
            self._hc_session.cancel()
        self._log_status("正在停止...")

    def _crack_worker(self):
        try:
            result = self._session.run() if self._session else None
        except Exception as e:
            self.after(0, lambda: self._log_status(f"错误: {e}"))
            result = None
        self.after(0, lambda: self._on_crack_done(result))

    def _on_crack_found(self, password: str):
        pass  # handled in _on_crack_done

    def _on_crack_progress(self, info: dict):
        pwd = info.get("current_password", "")
        speed = info.get("speed", 0)
        attempts = info.get("total_attempts", 0)
        total_est = info.get("total_estimate", 0)
        elapsed = info.get("elapsed", 0)

        self.after(0, lambda: self._update_progress_ui(pwd, speed, attempts, total_est, elapsed))

    def _on_crack_log(self, message: str):
        self.after(0, lambda: self._log_status(message))

    def _update_progress_ui(self, password: str, speed: float, attempts: int,
                             total_est: int, elapsed: float):
        self._current_pwd_label.configure(text=f"当前: {password}")
        speed_str = f"{speed:.0f} 次/秒" if speed > 0 else "--"
        self._speed_label.configure(text=f"速度: {speed_str}")
        self._attempts_label.configure(text=f"已尝试: {attempts:,}")
        if total_est > 0 and speed > 0:
            pct = attempts / total_est * 100
            remaining = total_est - attempts
            eta_s = remaining / speed
            h, m = int(eta_s // 3600), int((eta_s % 3600) // 60)
            if h > 0:
                eta_str = f"{h}h{m:02d}m"
            else:
                s = int(eta_s % 60)
                eta_str = f"{m}m{s:02d}s"
            self._eta_label.configure(text=f"进度: {pct:.1f}% | 预计剩余: {eta_str}")
        elif elapsed > 0:
            mins = int(elapsed // 60)
            secs = int(elapsed % 60)
            self._eta_label.configure(text=f"已运行: {mins}分{secs}秒")

    def _on_crack_stopped(self):
        """Reset UI after cancellation or error (no success/failure dialog)."""
        self._running = False
        self._progress_bar.stop()
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")

    def _on_crack_done(self, password: str | None):
        self._running = False
        self._progress_bar.stop()
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")

        if password:
            self._log_status(f"✓ 密码找到: {password}")
            self._current_pwd_label.configure(text=f"密码: {password}")
            if self._on_password_found:
                self._on_password_found(password)
            messagebox.showinfo("破解成功",
                               f"密码已找到:\n{password}\n\n将自动填入文件密码。",
                               parent=self)
        else:
            if not self._cancel_flag.is_set():
                self._log_status("未找到密码 — 攻击已穷尽")
                messagebox.showinfo("破解结束", "未找到密码，所有攻击方式已尝试完毕。", parent=self)
            else:
                self._log_status("已停止")

    def _log_status(self, msg: str):
        self._status_label.configure(text=msg)
