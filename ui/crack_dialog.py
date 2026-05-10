"""CrackDialog — password cracking configuration and progress UI."""

from __future__ import annotations

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


class CrackDialog(tk.Toplevel):
    """Dialog for configuring and running password cracking attacks."""

    def __init__(self, parent, archive_paths: list[str], *,
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
        self._archive_paths = archive_paths
        self._archive_path = archive_paths[0] if archive_paths else ""  # first as default
        self._on_password_found = on_password_found

        self._running = False
        self._session: CrackSession | None = None
        self._worker_thread: threading.Thread | None = None
        self._cancel_flag = threading.Event()
        self._cracked_passwords: dict[str, str] = {}

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

        # Scroll on mousewheel when cursor is over the canvas area,
        # EXCEPT when over a Spinbox — those handle their own value adjustment.
        # bind_all is needed because tkinter does NOT propagate <MouseWheel>
        # from child widgets (Buttons, Entries, etc.) to parent frames.
        def _on_spinbox_mousewheel(ev):
            """Adjust Spinbox value ±1, respecting the widget's range."""
            try:
                v = int(ev.widget.get())
                delta = 1 if ev.delta > 0 else -1
                new = v + delta
                lo = int(str(ev.widget['from']))
                hi = int(str(ev.widget['to']))
                if lo <= new <= hi:
                    ev.widget.set(str(new))
            except Exception:
                pass

        def _bind_spinboxes(parent):
            for child in parent.winfo_children():
                if isinstance(child, ttk.Spinbox):
                    child.bind("<MouseWheel>", _on_spinbox_mousewheel)
                else:
                    _bind_spinboxes(child)

        _bind_spinboxes(self._content)

        def _on_mousewheel(ev):
            # If over a Spinbox, let its own handler do the work
            w = canvas.winfo_containing(ev.x_root, ev.y_root)
            if w is not None and isinstance(w, ttk.Spinbox):
                return
            cx = canvas.winfo_rootx()
            cy = canvas.winfo_rooty()
            if cx <= ev.x_root <= cx + canvas.winfo_width() and \
               cy <= ev.y_root <= cy + canvas.winfo_height():
                canvas.yview_scroll(-1 * (ev.delta // 120), "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        cf = self._content  # short alias — all content goes here

        # Header
        p = Path(self._archive_path)
        count = len(self._archive_paths)
        header_text = f"目标: {p.name} 等 {count} 个文件"
        ttk.Label(cf, text=header_text,
                  font=("Segoe UI", 11, "bold")).pack(fill=tk.X, padx=12, pady=(12, 4))

        # --- Attack type + selected files ---
        type_frame = ttk.LabelFrame(cf, text="攻击方式", padding=(10, 8))
        type_frame.pack(fill=tk.X, padx=12, pady=(8, 4))

        type_row = ttk.Frame(type_frame)
        type_row.pack(fill=tk.X)

        # Left: attack type radio buttons
        type_left = ttk.Frame(type_row)
        type_left.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self._attack_type = tk.StringVar(value="bruteforce")
        types = [
            ("暴力破解 — 尝试所有字符组合", "bruteforce"),
            ("字典攻击 — 从密码字典文件加载", "dictionary"),
            ("掩码攻击 — 按模式生成 (? = 未知字符)", "mask"),
        ]
        for text, value in types:
            rb = ttk.Radiobutton(type_left, text=text, variable=self._attack_type,
                                value=value, command=self._on_type_changed)
            rb.pack(anchor="w", pady=2)

        # Right: selected files list
        type_right = ttk.Frame(type_row, width=200)
        type_right.pack(side=tk.RIGHT, fill=tk.Y, padx=(12, 0))
        ttk.Label(type_right, text="选中文件:",
                  font=("Segoe UI", 9, "bold")).pack(anchor="w")
        files_listbox = tk.Listbox(type_right, height=min(count, 6),
                                   bg=C["surface"], fg=C["body"],
                                   font=("Segoe UI", 9),
                                   borderwidth=1, highlightthickness=0,
                                   selectbackground=C["blue"],
                                   selectforeground=C["canvas"])
        files_listbox.pack(fill=tk.BOTH, expand=True)
        for ap in self._archive_paths:
            files_listbox.insert(tk.END, f"  {Path(ap).name}")
        files_listbox.configure(state="disabled")

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

        # Cracked results display
        self._cracked_label = ttk.Label(progress_frame, text="已破解:",
                                        font=("Segoe UI", 9, "bold"))
        self._cracked_text = tk.Text(progress_frame, height=4, wrap=tk.WORD,
                                      state="disabled",
                                      bg=C["surface"], fg=C["green"],
                                      font=("Cascadia Code", 10),
                                      borderwidth=1, highlightthickness=0,
                                      selectbackground=C["blue"],
                                      selectforeground=C["canvas"],
                                      padx=6, pady=4)

        self._progress_bar = ttk.Progressbar(progress_frame, mode="indeterminate", length=400)
        self._progress_bar.pack(fill=tk.X, pady=(8, 0))

        # --- Log output ---
        log_frame = ttk.LabelFrame(cf, text="输出日志", padding=(4, 4))
        log_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

        self._log_text = tk.Text(log_frame, height=6, wrap=tk.WORD, state="disabled",
                                 bg=C["surface"], fg=C["body"],
                                 font=("Cascadia Code", 9),
                                 borderwidth=1, highlightthickness=0,
                                 selectbackground=C["blue"],
                                 selectforeground=C["canvas"])
        log_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self._log_text.yview)
        self._log_text.configure(yscrollcommand=log_scroll.set)
        self._log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

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

    def _get_selected_rules(self) -> list[str]:
        return [k for k, v in self._rule_vars.items() if v.get()]

    def _get_charset(self) -> str:
        custom = self._charset_custom_var.get().strip()
        if custom:
            return "".join(dict.fromkeys(custom))  # deduplicate, preserve order
        return CHARSET_PRESETS.get(self._charset_preset.get(), "0123456789")

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

        # Skip already-cracked files
        uncracked = [ap for ap in self._archive_paths if ap not in self._cracked_passwords]
        if not uncracked:
            messagebox.showinfo("提示", "所有选中文件的密码已破解。", parent=self)
            return

        self._running = True
        self._cancel_flag.clear()
        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._progress_bar.start(20)

        self._log_status("正在准备...")
        self._crack_configs = configs
        self._worker_thread = threading.Thread(target=self._crack_worker, daemon=True)
        self._worker_thread.start()

    def _stop(self):
        self._cancel_flag.set()
        if self._session:
            self._session.cancel()
        self._log_status("正在停止...")

    def _crack_worker(self):
        for idx, archive_path in enumerate(self._archive_paths):
            if self._cancel_flag.is_set():
                break

            path = Path(archive_path)

            # Skip already-cracked files
            if archive_path in self._cracked_passwords:
                self.after(0, lambda i=idx, n=path.name:
                           self._append_log(f"[{i+1}/{len(self._archive_paths)}] {n}: 已破解，跳过"))
                continue

            self.after(0, lambda i=idx, n=path.name:
                       self._log_status(f"[{i+1}/{len(self._archive_paths)}] {n}"))

            self._session = CrackSession(
                configs=list(self._crack_configs),
                archive_path=str(path),
                on_found=self._on_crack_found,
                on_progress=self._on_crack_progress,
                on_log=self._on_crack_log,
            )
            try:
                result = self._session.run()
            except Exception as e:
                self.after(0, lambda e=e: self._log_status(f"错误: {e}"))
                result = None

            if result:
                self._cracked_passwords[archive_path] = result
                self._add_cracked_result(archive_path, result)
                self.after(0, lambda p=result: self._on_password_found and self._on_password_found(p))
                # Continue to next file — don't stop

        self.after(0, self._on_crack_all_done)

    def _on_crack_found(self, password: str):
        pass  # handled per-file in _crack_worker

    def _on_crack_progress(self, info: dict):
        pwd = info.get("current_password", "")
        speed = info.get("speed", 0)
        attempts = info.get("total_attempts", 0)
        total_est = info.get("total_estimate", 0)
        elapsed = info.get("elapsed", 0)

        self.after(0, lambda: self._update_progress_ui(pwd, speed, attempts, total_est, elapsed))

    def _on_crack_log(self, message: str):
        self.after(0, lambda: self._append_log(message))

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

    def _on_crack_all_done(self):
        self._running = False
        self._session = None
        self._progress_bar.stop()
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")

        found = self._cracked_passwords
        total = len(self._archive_paths)
        success_count = len(found)

        if success_count > 0:
            unique_pwds = list(set(found.values()))
            self._log_status(f"✓ 找到 {success_count}/{total} 个文件的密码")
            self._current_pwd_label.configure(text="")
            messagebox.showinfo("破解完成",
                               f"已找到 {success_count}/{total} 个文件的密码\n\n"
                               f"密码: {', '.join(unique_pwds)}",
                               parent=self)
        else:
            if not self._cancel_flag.is_set():
                self._log_status("未找到密码 — 攻击已穷尽")
                messagebox.showinfo("破解结束",
                                   f"已尝试 {total} 个文件，未找到密码。",
                                   parent=self)
            else:
                self._log_status("已停止")

    def _add_cracked_result(self, archive_path: str, password: str):
        """Add a cracked entry to the real-time results display."""
        self.after(0, lambda: self._add_cracked_result_ui(archive_path, password))

    def _add_cracked_result_ui(self, archive_path: str, password: str):
        name = Path(archive_path).name
        self._cracked_text.configure(state="normal")
        # Show the results widgets if they're hidden
        if not self._cracked_label.winfo_ismapped():
            self._cracked_label.pack(anchor="w", pady=(8, 2),
                                     after=self._eta_label)
            self._cracked_text.pack(fill=tk.BOTH, expand=True, pady=(0, 4),
                                    after=self._cracked_label)
        self._cracked_text.insert(tk.END, f"✓ {name}  →  {password}\n")
        self._cracked_text.see(tk.END)
        self._cracked_text.configure(state="disabled")

    def _clear_cracked_results(self):
        """Clear the cracked results display."""
        self._cracked_text.configure(state="normal")
        self._cracked_text.delete("1.0", tk.END)
        self._cracked_text.configure(state="disabled")
        if self._cracked_label.winfo_ismapped():
            self._cracked_label.pack_forget()
            self._cracked_text.pack_forget()

    def _log_status(self, msg: str):
        self._status_label.configure(text=msg)
        self._append_log(msg)

    def _append_log(self, msg: str):
        try:
            self._log_text.configure(state="normal")
            self._log_text.insert(tk.END, msg + "\n")
            self._log_text.see(tk.END)
            self._log_text.configure(state="disabled")
        except Exception:
            pass
