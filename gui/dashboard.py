"""
smart_autopsy/gui/dashboard.py
══════════════════════════════════════════════════════════════════════════════
Forensic Dashboard — CustomTkinter UI
Smart Autopsy | Digital Forensics Platform

UI layout
─────────────────────────────────────────────────────────────────
 ┌─────────────────────────────────────────────────────────────┐
 │  HEADER  — logo · title · root-privilege badge              │
 ├────────────────────────┬────────────────────────────────────┤
 │  LEFT PANEL            │  RIGHT PANEL                       │
 │  • Target selection    │  • Recovered files table           │
 │    (drive dropdown /   │    (scrollable, real-time)         │
 │     image browser)     │                                    │
 │  • Destination picker  │                                    │
 │  • Scan controls       │                                    │
 │  • Progress bar        │                                    │
 │  • Status label        │                                    │
 └────────────────────────┴────────────────────────────────────┘
 ┌─────────────────────────────────────────────────────────────┐
 │  FOOTER  — session stats · elapsed time                     │
 └─────────────────────────────────────────────────────────────┘

Threading model
───────────────
carve_stream() is executed inside a daemon threading.Thread.  All UI updates
from that thread are marshalled through CTk's after() mechanism to stay on
the main thread and satisfy Tk's single-thread requirement.

Author : Smart Autopsy Engineering Team
Python : 3.9+
"""

from __future__ import annotations

import os
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox
from typing import Dict, List, Optional

from PIL import Image

import customtkinter as ctk

from core.scanner import DriveScanner, list_physical_drives
from core.carver  import CarvedFile, FileCarver, SafetyViolationError

# ─────────────────────────────────────────────────────────────────────────────
# CustomTkinter global theme
# ─────────────────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ─────────────────────────────────────────────────────────────────────────────
# Palette — all colours defined in one place
# ─────────────────────────────────────────────────────────────────────────────
C = {
    # Backgrounds
    "bg_root":      "#0D1117",
    "bg_panel":     "#161B22",
    "bg_card":      "#1C2128",
    "bg_input":     "#21262D",
    "bg_table_hdr": "#1C2128",
    "bg_table_row": "#161B22",
    "bg_table_alt": "#1A2030",

    # Foreground / text
    "fg_primary":   "#E6EDF3",
    "fg_secondary": "#8B949E",
    "fg_accent":    "#58A6FF",
    "fg_success":   "#3FB950",
    "fg_warning":   "#D29922",
    "fg_danger":    "#F85149",
    "fg_header":    "#79C0FF",

    # Buttons
    "btn_start":    "#238636",
    "btn_start_hv": "#2EA043",
    "btn_stop":     "#DA3633",
    "btn_stop_hv":  "#F85149",
    "btn_browse":   "#1F6FEB",
    "btn_browse_hv":"#388BFD",

    # Borders
    "border":       "#30363D",
    "border_focus": "#58A6FF",

    # Progress
    "prog_fg":      "#1F6FEB",
    "prog_bg":      "#21262D",
}

# ─────────────────────────────────────────────────────────────────────────────
# Fonts
# ─────────────────────────────────────────────────────────────────────────────
FONT_TITLE  = ("JetBrains Mono", 20, "bold")
FONT_LABEL  = ("JetBrains Mono", 12)
FONT_SMALL  = ("JetBrains Mono", 10)
FONT_MONO   = ("JetBrains Mono", 10)
FONT_TABLE  = ("JetBrains Mono", 10)
FONT_BADGE  = ("JetBrains Mono", 10, "bold")
FONT_STAT   = ("JetBrains Mono", 11, "bold")

# Table column definitions: (heading, relative_weight, min_width)
TABLE_COLS = [
    ("File Name",    3, 160),
    ("Type",         1,  60),
    ("Start Offset", 2, 110),
    ("Size",         1,  80),
    ("MD5 (8 char)", 2, 100),
    ("Export Path",  4, 220),
]


# ══════════════════════════════════════════════════════════════════════════════
# SmartAutopsyApp
# ══════════════════════════════════════════════════════════════════════════════

class SmartAutopsyApp(ctk.CTk):
    """Main application window for Smart Autopsy."""

    def __init__(self) -> None:
        super().__init__()

        # ── Window setup ───────────────────────────────────────────────────
        self.title("Smart Autopsy — Digital Forensics Platform")
        self.geometry("1280x820")
        self.minsize(1100, 700)
        self.configure(fg_color=C["bg_root"])

        # ── State ──────────────────────────────────────────────────────────
        self._scan_thread:   Optional[threading.Thread] = None
        self._carver:        Optional[FileCarver]        = None
        self._is_scanning:   bool = False
        self._bytes_scanned: int  = 0
        self._total_bytes:   int  = 0
        self._carved_count:  int  = 0
        self._session_start: float = 0.0
        self._drives:        List[Dict[str, str]] = []

        # StringVars
        self._target_var:    tk.StringVar = tk.StringVar(value="")
        self._dest_var:      tk.StringVar = tk.StringVar(
            value=os.path.expanduser("~/smart_autopsy_exports")
        )
        self._status_var:    tk.StringVar = tk.StringVar(value="Ready — select a target and destination.")
        self._elapsed_var:   tk.StringVar = tk.StringVar(value="00:00:00")
        self._stats_var:     tk.StringVar = tk.StringVar(value="Files: 0  |  Scanned: 0 B  |  Speed: — B/s")

        # Build UI
        self._build_header()
        self._build_body()
        self._build_footer()

        # Populate drive list
        self._refresh_drives()

        # Kick off the elapsed-time ticker
        self._tick_timer()

    # ──────────────────────────────────────────────────────────────────────
    # UI construction helpers
    # ──────────────────────────────────────────────────────────────────────

    def _build_header(self) -> None:
        """Top banner: logo, title, root badge."""
        hdr = ctk.CTkFrame(self, fg_color=C["bg_panel"], corner_radius=0, height=64)
        hdr.pack(side="top", fill="x", padx=0, pady=0)
        hdr.pack_propagate(False)

        # Left side: logo image + subtitle
        left = ctk.CTkFrame(hdr, fg_color="transparent")
        left.pack(side="left", padx=20, pady=8)

        # Load logo image (assets/logo.png lives next to the gui/ package)
        _logo_path = os.path.join(os.path.dirname(__file__), "..", "assets", "logo.png")
        _logo_path = os.path.normpath(_logo_path)
        try:
            _pil_img   = Image.open(_logo_path).resize((48, 48), Image.LANCZOS)
            _ctk_img   = ctk.CTkImage(light_image=_pil_img, dark_image=_pil_img, size=(48, 48))
            ctk.CTkLabel(
                left, image=_ctk_img, text="",
            ).pack(side="left", padx=(0, 10))
        except Exception:
            # Fallback to text if image is missing
            ctk.CTkLabel(
                left, text="⬡",
                font=FONT_TITLE, text_color=C["fg_accent"],
            ).pack(side="left", padx=(0, 6))

        ctk.CTkLabel(
            left, text="SMART AUTOPSY",
            font=FONT_TITLE, text_color=C["fg_accent"],
        ).pack(side="left", padx=(0, 14))

        ctk.CTkLabel(
            left, text="Digital Forensics Platform  v2.0",
            font=FONT_SMALL, text_color=C["fg_secondary"],
        ).pack(side="left")

        # Right side: privilege badge + refresh button
        right = ctk.CTkFrame(hdr, fg_color="transparent")
        right.pack(side="right", padx=20, pady=8)

        # Root privilege badge
        is_root = (os.geteuid() == 0)
        badge_color = C["fg_success"] if is_root else C["fg_danger"]
        badge_text  = "✔  ROOT" if is_root else "✘  NOT ROOT"
        badge_bg    = "#0D2A12" if is_root else "#2A0D0D"

        priv_badge = ctk.CTkFrame(right, fg_color=badge_bg, corner_radius=6)
        priv_badge.pack(side="right", padx=(10, 0))
        ctk.CTkLabel(
            priv_badge, text=badge_text,
            font=FONT_BADGE, text_color=badge_color,
        ).pack(padx=10, pady=4)

        # Refresh drives button
        ctk.CTkButton(
            right, text="⟳  Refresh Drives",
            width=130, height=32, corner_radius=6,
            font=FONT_SMALL,
            fg_color=C["bg_input"], hover_color=C["border"],
            text_color=C["fg_secondary"],
            command=self._refresh_drives,
        ).pack(side="right")

    def _build_body(self) -> None:
        """Two-column body: left=controls, right=results table."""
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(side="top", fill="both", expand=True, padx=14, pady=(10, 6))
        body.grid_columnconfigure(0, weight=3, minsize=340)
        body.grid_columnconfigure(1, weight=7, minsize=560)
        body.grid_rowconfigure(0, weight=1)

        self._build_left_panel(body)
        self._build_right_panel(body)

    def _build_left_panel(self, parent: ctk.CTkFrame) -> None:
        """Left column: target, destination, controls, progress."""
        panel = ctk.CTkFrame(parent, fg_color=C["bg_panel"], corner_radius=10)
        panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        inner = ctk.CTkFrame(panel, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=16, pady=16)

        # ── Section: Target ───────────────────────────────────────────────
        self._section_label(inner, "① TARGET DEVICE / IMAGE")

        self._drive_menu: ctk.CTkOptionMenu = ctk.CTkOptionMenu(
            inner,
            variable=self._target_var,
            values=["— loading —"],
            width=280, height=34, corner_radius=6,
            font=FONT_SMALL, dropdown_font=FONT_MONO,
            fg_color=C["bg_input"], button_color=C["btn_browse"],
            button_hover_color=C["btn_browse_hv"],
            text_color=C["fg_primary"],
            dynamic_resizing=False,
            command=self._on_drive_selected,
        )
        self._drive_menu.pack(fill="x", pady=(4, 4))

        ctk.CTkButton(
            inner, text="Browse Image File (.dd / .img / .raw)",
            height=32, corner_radius=6, font=FONT_SMALL,
            fg_color=C["bg_input"], hover_color=C["border"],
            text_color=C["fg_accent"],
            border_width=1, border_color=C["border"],
            command=self._browse_image,
        ).pack(fill="x", pady=(0, 4))

        # Target info strip
        self._target_info = ctk.CTkLabel(
            inner, text="No target selected",
            font=FONT_SMALL, text_color=C["fg_secondary"],
            anchor="w", justify="left", wraplength=280,
        )
        self._target_info.pack(fill="x", pady=(0, 10))

        # ── Section: Destination ──────────────────────────────────────────
        self._section_label(inner, "② EXPORT DESTINATION")

        dest_row = ctk.CTkFrame(inner, fg_color="transparent")
        dest_row.pack(fill="x", pady=(4, 4))

        self._dest_entry = ctk.CTkEntry(
            dest_row, textvariable=self._dest_var,
            height=34, corner_radius=6, font=FONT_SMALL,
            fg_color=C["bg_input"], border_color=C["border"],
            text_color=C["fg_primary"],
        )
        self._dest_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))

        ctk.CTkButton(
            dest_row, text="…", width=36, height=34,
            corner_radius=6, font=FONT_LABEL,
            fg_color=C["btn_browse"], hover_color=C["btn_browse_hv"],
            command=self._browse_dest,
        ).pack(side="left")

        # Destination warning label
        self._dest_warn = ctk.CTkLabel(
            inner, text="",
            font=FONT_SMALL, text_color=C["fg_warning"],
            anchor="w", wraplength=280,
        )
        self._dest_warn.pack(fill="x", pady=(0, 10))

        # ── Section: File type filter ─────────────────────────────────────
        self._section_label(inner, "③ FILE TYPE FILTER")

        filter_grid = ctk.CTkFrame(inner, fg_color="transparent")
        filter_grid.pack(fill="x", pady=(4, 12))

        self._type_vars: Dict[str, tk.BooleanVar] = {}
        types = ["JPEG", "PDF", "PNG", "ZIP", "MP3", "GIF", "DOCX", "BMP"]
        for idx, ftype in enumerate(types):
            var = tk.BooleanVar(value=True)
            self._type_vars[ftype] = var
            cb = ctk.CTkCheckBox(
                filter_grid, text=ftype, variable=var,
                font=FONT_SMALL, text_color=C["fg_primary"],
                fg_color=C["btn_browse"], hover_color=C["btn_browse_hv"],
                border_color=C["border"], width=16, height=16,
            )
            cb.grid(row=idx // 4, column=idx % 4, sticky="w", padx=4, pady=2)

        # ── Section: Controls ─────────────────────────────────────────────
        self._section_label(inner, "④ SCAN CONTROLS")

        btn_row = ctk.CTkFrame(inner, fg_color="transparent")
        btn_row.pack(fill="x", pady=(4, 8))

        self._btn_start = ctk.CTkButton(
            btn_row, text="▶  Start Forensic Scan",
            height=40, corner_radius=8, font=FONT_LABEL,
            fg_color=C["btn_start"], hover_color=C["btn_start_hv"],
            command=self._start_scan,
        )
        self._btn_start.pack(side="left", fill="x", expand=True, padx=(0, 6))

        self._btn_stop = ctk.CTkButton(
            btn_row, text="■  Stop",
            height=40, width=80, corner_radius=8, font=FONT_LABEL,
            fg_color=C["btn_stop"], hover_color=C["btn_stop_hv"],
            state="disabled",
            command=self._stop_scan,
        )
        self._btn_stop.pack(side="left")

        # ── Progress bar ──────────────────────────────────────────────────
        self._progress = ctk.CTkProgressBar(
            inner, height=10, corner_radius=5,
            fg_color=C["prog_bg"], progress_color=C["prog_fg"],
        )
        self._progress.set(0)
        self._progress.pack(fill="x", pady=(0, 6))

        # Status label
        self._status_label = ctk.CTkLabel(
            inner, textvariable=self._status_var,
            font=FONT_SMALL, text_color=C["fg_secondary"],
            anchor="w", wraplength=290, justify="left",
        )
        self._status_label.pack(fill="x")

        # ── Stats strip ───────────────────────────────────────────────────
        ctk.CTkFrame(inner, fg_color=C["border"], height=1).pack(fill="x", pady=10)

        ctk.CTkLabel(
            inner, textvariable=self._stats_var,
            font=FONT_SMALL, text_color=C["fg_accent"],
            anchor="w",
        ).pack(fill="x")

    def _build_right_panel(self, parent: ctk.CTkFrame) -> None:
        """Right column: recovered files table."""
        panel = ctk.CTkFrame(parent, fg_color=C["bg_panel"], corner_radius=10)
        panel.grid(row=0, column=1, sticky="nsew")

        # Panel header
        phdr = ctk.CTkFrame(panel, fg_color=C["bg_card"], corner_radius=0, height=42)
        phdr.pack(fill="x")
        phdr.pack_propagate(False)

        ctk.CTkLabel(
            phdr, text="  📂  RECOVERED FILES",
            font=FONT_LABEL, text_color=C["fg_header"],
            anchor="w",
        ).pack(side="left", padx=14, pady=0, fill="y")

        self._table_count_label = ctk.CTkLabel(
            phdr, text="0 files recovered",
            font=FONT_SMALL, text_color=C["fg_secondary"],
        )
        self._table_count_label.pack(side="right", padx=14)

        # ttk.Treeview inside a CTkScrollableFrame wrapper frame
        tree_outer = ctk.CTkFrame(panel, fg_color=C["bg_card"], corner_radius=0)
        tree_outer.pack(fill="both", expand=True, padx=0, pady=0)

        # Use a tk.Frame to host the Treeview so we can apply standard scrollbars
        tv_host = tk.Frame(tree_outer, bg=C["bg_card"])
        tv_host.pack(fill="both", expand=True, padx=6, pady=6)

        # Style the Treeview
        style = tk.ttk.Style(self)
        style.theme_use("clam")
        style.configure("SA.Treeview",
            background=C["bg_table_row"],
            foreground=C["fg_primary"],
            fieldbackground=C["bg_table_row"],
            rowheight=24,
            font=FONT_TABLE,
            borderwidth=0,
        )
        style.configure("SA.Treeview.Heading",
            background=C["bg_table_hdr"],
            foreground=C["fg_header"],
            font=("JetBrains Mono", 10, "bold"),
            relief="flat",
            borderwidth=0,
        )
        style.map("SA.Treeview",
            background=[("selected", C["btn_browse"])],
            foreground=[("selected", C["fg_primary"])],
        )
        style.map("SA.Treeview.Heading",
            background=[("active", C["bg_input"])],
        )

        col_ids = [f"c{i}" for i in range(len(TABLE_COLS))]
        self._tree = tk.ttk.Treeview(
            tv_host,
            columns=col_ids,
            show="headings",
            style="SA.Treeview",
            selectmode="browse",
        )

        for i, (heading, weight, minw) in enumerate(TABLE_COLS):
            self._tree.heading(col_ids[i], text=heading)
            self._tree.column(col_ids[i], minwidth=minw, stretch=True, anchor="w")

        vsb = tk.ttk.Scrollbar(tv_host, orient="vertical",   command=self._tree.yview)
        hsb = tk.ttk.Scrollbar(tv_host, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tv_host.grid_rowconfigure(0, weight=1)
        tv_host.grid_columnconfigure(0, weight=1)

        # Alternating row tags
        self._tree.tag_configure("odd",  background=C["bg_table_row"])
        self._tree.tag_configure("even", background=C["bg_table_alt"])

    def _build_footer(self) -> None:
        """Bottom status bar: elapsed time."""
        footer = ctk.CTkFrame(self, fg_color=C["bg_panel"], corner_radius=0, height=32)
        footer.pack(side="bottom", fill="x")
        footer.pack_propagate(False)

        ctk.CTkLabel(
            footer, text="Smart Autopsy  |  Module 2: File Carver Engine",
            font=FONT_SMALL, text_color=C["fg_secondary"],
        ).pack(side="left", padx=16, pady=0)

        ctk.CTkLabel(
            footer, textvariable=self._elapsed_var,
            font=FONT_STAT, text_color=C["fg_accent"],
        ).pack(side="right", padx=16)

        ctk.CTkLabel(
            footer, text="⏱ Elapsed: ",
            font=FONT_SMALL, text_color=C["fg_secondary"],
        ).pack(side="right")

    # ──────────────────────────────────────────────────────────────────────
    # Helper: section label
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _section_label(parent: ctk.CTkFrame, text: str) -> None:
        ctk.CTkLabel(
            parent, text=text,
            font=FONT_BADGE, text_color=C["fg_secondary"],
            anchor="w",
        ).pack(fill="x", pady=(10, 2))

    # ──────────────────────────────────────────────────────────────────────
    # Drive discovery & target selection
    # ──────────────────────────────────────────────────────────────────────

    def _refresh_drives(self) -> None:
        """Re-run lsblk and repopulate the drive dropdown."""
        try:
            self._drives = list_physical_drives()
        except Exception as exc:  # noqa: BLE001
            self._drives = []
            self._status_var.set(f"Drive discovery failed: {exc}")

        labels = []
        for d in self._drives:
            mounted = f" [mounted: {d['mountpoint']}]" if d["mountpoint"] else ""
            label   = f"{d['path']}  {d['human_size']}  {d['model']}{mounted}"
            labels.append(label)

        if not labels:
            labels = ["No block devices found"]

        self._drive_menu.configure(values=labels)
        self._drive_menu.set(labels[0])
        self._on_drive_selected(labels[0])

    def _on_drive_selected(self, choice: str) -> None:
        """Update target info strip when a drive is chosen from the dropdown."""
        # Find the matching drive record
        path = choice.split("  ")[0].strip() if choice else ""
        match = next((d for d in self._drives if d["path"] == path), None)

        if match:
            self._target_var.set(match["path"])
            mp = match["mountpoint"] or "not mounted"
            info = (
                f"Path: {match['path']}\n"
                f"Size: {match['human_size']} ({match['size_bytes']} B)\n"
                f"Type: {match['type'].upper()}  |  Mount: {mp}\n"
                f"Model: {match['model'] or '—'}"
            )
            self._target_info.configure(text=info, text_color=C["fg_primary"])
            self._check_dest_safety()
        else:
            self._target_info.configure(text="No target selected", text_color=C["fg_secondary"])

    def _browse_image(self) -> None:
        """Open a file dialog to select a disk image."""
        path = filedialog.askopenfilename(
            title="Select Forensic Disk Image",
            filetypes=[
                ("Disk Images", "*.dd *.img *.raw *.iso *.bin *.E01"),
                ("All Files",   "*.*"),
            ],
        )
        if path:
            self._target_var.set(path)
            size = os.path.getsize(path)
            size_h = self._human(size)
            self._target_info.configure(
                text=f"Image: {os.path.basename(path)}\nSize: {size_h} ({size:,} B)\nPath: {path}",
                text_color=C["fg_primary"],
            )
            self._check_dest_safety()

    # ──────────────────────────────────────────────────────────────────────
    # Destination picker & safety validation
    # ──────────────────────────────────────────────────────────────────────

    def _browse_dest(self) -> None:
        path = filedialog.askdirectory(
            title="Select Export Destination Directory",
            initialdir=self._dest_var.get(),
        )
        if path:
            self._dest_var.set(path)
            self._check_dest_safety()

    def _check_dest_safety(self) -> bool:
        """Validate that destination is not on the same device as the source."""
        target = self._target_var.get()
        dest   = self._dest_var.get()

        if not target or not dest:
            self._dest_warn.configure(text="")
            return True

        try:
            os.makedirs(dest, exist_ok=True)
            src_dev  = os.stat(target).st_dev if os.path.exists(target) else None
            dest_dev = os.stat(dest).st_dev   if os.path.exists(dest)   else None

            if src_dev and dest_dev and src_dev == dest_dev:
                self._dest_warn.configure(
                    text="⚠ SAME DEVICE as source — choose a different drive!",
                    text_color=C["fg_danger"],
                )
                return False
            else:
                self._dest_warn.configure(
                    text="✔ Safe destination — different device.",
                    text_color=C["fg_success"],
                )
                return True
        except OSError:
            self._dest_warn.configure(text="")
            return True

    # ──────────────────────────────────────────────────────────────────────
    # Scan lifecycle
    # ──────────────────────────────────────────────────────────────────────

    def _start_scan(self) -> None:
        """Validate inputs and launch the carve thread."""
        target = self._target_var.get()
        dest   = self._dest_var.get()

        # Input validation
        if not target or not os.path.exists(target):
            messagebox.showerror(
                "Invalid Target",
                f"Target path does not exist:\n{target}\n\n"
                "Select a block device from the dropdown or browse for a disk image.",
            )
            return

        if not dest:
            messagebox.showerror("Missing Destination", "Please choose an export directory.")
            return

        if not self._check_dest_safety():
            messagebox.showerror(
                "Safety Violation",
                "The destination directory is on the same device as the source.\n\n"
                "Carving to the source drive would destroy evidence.\n"
                "Choose a destination on a different drive.",
            )
            return

        # Check root for block devices
        if target.startswith("/dev/") and os.geteuid() != 0:
            messagebox.showerror(
                "Insufficient Privileges",
                "Reading a raw block device requires root privileges.\n\n"
                "Restart Smart Autopsy with:\n    sudo python3 main.py",
            )
            return

        # Prepare UI
        self._is_scanning   = True
        self._carved_count  = 0
        self._bytes_scanned = 0
        self._session_start = time.monotonic()
        self._progress.set(0)
        self._status_var.set("Initialising scanner…")

        self._btn_start.configure(state="disabled")
        self._btn_stop.configure(state="normal")
        self._tree.delete(*self._tree.get_children())
        self._table_count_label.configure(text="0 files recovered")

        # Build carver with active file types
        active_types = {k.lower() for k, v in self._type_vars.items() if v.get()}
        from core.carver import _SIGNATURES  # local import to filter by selection
        filtered_sigs = [(ext, variants) for ext, variants in _SIGNATURES
                         if ext.lower() in active_types
                         or ext.lower() == "jpg" and "jpeg" in active_types]
        self._carver = FileCarver(signatures=filtered_sigs if filtered_sigs else None)

        # Launch background thread
        self._scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(target, dest),
            daemon=True,
        )
        self._scan_thread.start()

    def _stop_scan(self) -> None:
        """Signal the carver to stop after the current chunk."""
        if self._carver:
            self._carver.stop_flag = True
        self._status_var.set("Stop requested — finishing current block…")
        self._btn_stop.configure(state="disabled")

    def _scan_worker(self, target: str, dest: str) -> None:
        """Background thread: runs carve_stream and posts results to the UI."""
        try:
            scanner = DriveScanner(target_path=target, chunk_size=65536)
            self._total_bytes = scanner.get_total_size()

            results = self._carver.carve_stream(  # type: ignore[union-attr]
                scanner=scanner,
                output_dir=dest,
                progress_callback=self._on_progress,
            )

            # Post completion to UI thread
            self.after(0, self._on_scan_complete, results, None)

        except SafetyViolationError as exc:
            self.after(0, self._on_scan_complete, [], str(exc))
        except PermissionError:
            self.after(0, self._on_scan_complete, [],
                "Permission denied.  Restart with sudo.")
        except Exception as exc:  # noqa: BLE001
            self.after(0, self._on_scan_complete, [], f"Unexpected error: {exc}")

    def _on_progress(self, bytes_scanned: int, total_bytes: int, carved_count: int) -> None:
        """Called from the scan thread — marshals UI update to main thread."""
        self._bytes_scanned = bytes_scanned
        self._carved_count  = carved_count
        self.after(0, self._update_progress_ui, bytes_scanned, total_bytes, carved_count)

    def _update_progress_ui(self, bytes_scanned: int, total_bytes: int, carved_count: int) -> None:
        """Runs on the main thread to update progress widgets."""
        if total_bytes > 0:
            pct = min(bytes_scanned / total_bytes, 1.0)
            self._progress.set(pct)
            pct_str = f"{pct * 100:.1f}%"
        else:
            # Unknown size — pulse between 0 and 1 using mod
            pulse = (bytes_scanned // (1024 * 1024)) % 100 / 100.0
            self._progress.set(pulse)
            pct_str = "?%"

        elapsed = time.monotonic() - self._session_start if self._session_start else 0
        speed   = bytes_scanned / elapsed if elapsed > 0 else 0

        self._status_var.set(
            f"Scanning sector 0x{bytes_scanned:08X}  ({pct_str})  —  "
            f"{carved_count} file(s) carved"
        )
        self._stats_var.set(
            f"Files: {carved_count}  |  "
            f"Scanned: {self._human(bytes_scanned)}  |  "
            f"Speed: {self._human(int(speed))}/s"
        )

    def _on_scan_complete(self, results: List[CarvedFile], error: Optional[str]) -> None:
        """Runs on the main thread when the scan thread exits."""
        self._is_scanning = False
        self._btn_start.configure(state="normal")
        self._btn_stop.configure(state="disabled")
        self._progress.set(1.0 if not error else 0.0)

        if error:
            messagebox.showerror("Scan Error", error)
            self._status_var.set(f"Error: {error[:80]}")
            return

        # Populate results table
        for cf in results:
            self._add_table_row(cf)

        elapsed = time.monotonic() - self._session_start if self._session_start else 0
        m, s    = divmod(int(elapsed), 60)
        h, m    = divmod(m, 60)
        self._status_var.set(
            f"Scan complete — {len(results)} file(s) recovered in "
            f"{h:02d}:{m:02d}:{s:02d}."
        )
        self._table_count_label.configure(text=f"{len(results)} files recovered")

    # ──────────────────────────────────────────────────────────────────────
    # Table helpers
    # ──────────────────────────────────────────────────────────────────────

    def _add_table_row(self, cf: CarvedFile) -> None:
        """Insert one recovered-file row into the Treeview."""
        n = len(self._tree.get_children())
        tag = "even" if n % 2 == 0 else "odd"
        self._tree.insert(
            "", "end",
            values=(
                cf.name,
                cf.file_type,
                cf.offset_hex,
                cf.human_size,
                cf.md5[:8] + "…",
                cf.export_path,
            ),
            tags=(tag,),
        )
        # Auto-scroll to last row
        children = self._tree.get_children()
        if children:
            self._tree.see(children[-1])

        self._table_count_label.configure(text=f"{n + 1} files recovered")

    # ──────────────────────────────────────────────────────────────────────
    # Elapsed-time ticker
    # ──────────────────────────────────────────────────────────────────────

    def _tick_timer(self) -> None:
        """Updates the elapsed-time display every second."""
        if self._is_scanning and self._session_start:
            elapsed = time.monotonic() - self._session_start
            h, rem  = divmod(int(elapsed), 3600)
            m, s    = divmod(rem, 60)
            self._elapsed_var.set(f"{h:02d}:{m:02d}:{s:02d}")
        self.after(1000, self._tick_timer)

    # ──────────────────────────────────────────────────────────────────────
    # Utility
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _human(n: int) -> str:
        value = float(n)
        for s in ("B", "KiB", "MiB", "GiB", "TiB"):
            if value < 1024.0:
                return f"{int(value)} {s}" if s == "B" else f"{value:.1f} {s}"
            value /= 1024.0
        return f"{value:.1f} PiB"
