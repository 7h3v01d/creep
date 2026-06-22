"""
creep_gui.py — Desktop GUI
Part of Creep: Defensive Adversarial Security Scanner
Author: Leon Priest
License: Apache 2.0

PyQt6 dark-theme desktop interface. Provides:
  - Target configuration panel
  - Per-module opt-in checkboxes with scope controls
  - Live scan log with colour-coded output
  - Findings table with severity filtering
  - Integrated HTML report viewer
  - Export to JSON / HTML

Run:
    python creep_gui.py
"""

from __future__ import annotations

import json
import os
import sys
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import html as _html
from PyQt6.QtCore import (
    QObject, QRunnable, QThread, QThreadPool,
    Qt, pyqtSignal, pyqtSlot,
)
from PyQt6.QtGui import QColor, QFont, QPalette, QTextCursor
from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog,
    QFrame, QGroupBox, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMainWindow, QMessageBox,
    QProgressBar, QPushButton, QScrollArea, QSizePolicy,
    QSplitter, QStatusBar, QTabWidget, QTableWidget,
    QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
    QGridLayout, QSpinBox,
)

# ── Creep imports ────────────────────────────────────────────────────────────
# Each imported lazily inside the worker so the GUI stays responsive
from creep_gate import ScopeError

APP_NAME    = "Creep"
APP_VERSION = "0.1.0"
APP_TAGLINE = "Defensive Adversarial Security Scanner"

# ---------------------------------------------------------------------------
# Palette + stylesheet
# ---------------------------------------------------------------------------

_C = {
    "bg0":      "#0b0d11",
    "bg1":      "#0f1116",
    "bg2":      "#14161d",
    "bg3":      "#1a1d26",
    "border":   "#1f2333",
    "border2":  "#2a2e40",
    "fg0":      "#dde1ee",
    "fg1":      "#9aa3be",
    "fg2":      "#5a6278",
    "accent":   "#e03c3c",    # red — adversarial/security signal
    "accent2":  "#b02828",
    "critical": "#ff3333",
    "high":     "#ff7700",
    "medium":   "#ffcc00",
    "low":      "#3399ff",
    "info":     "#666688",
    "green":    "#22c55e",
    "sel":      "#1e2540",
}


def _build_palette() -> QPalette:
    p = QPalette()
    p.setColor(QPalette.ColorRole.Window,          QColor(_C["bg1"]))
    p.setColor(QPalette.ColorRole.WindowText,      QColor(_C["fg0"]))
    p.setColor(QPalette.ColorRole.Base,            QColor(_C["bg2"]))
    p.setColor(QPalette.ColorRole.AlternateBase,   QColor(_C["bg3"]))
    p.setColor(QPalette.ColorRole.Text,            QColor(_C["fg0"]))
    p.setColor(QPalette.ColorRole.Button,          QColor(_C["bg3"]))
    p.setColor(QPalette.ColorRole.ButtonText,      QColor(_C["fg1"]))
    p.setColor(QPalette.ColorRole.Highlight,       QColor(_C["sel"]))
    p.setColor(QPalette.ColorRole.HighlightedText, QColor(_C["fg0"]))
    p.setColor(QPalette.ColorRole.ToolTipBase,     QColor(_C["bg3"]))
    p.setColor(QPalette.ColorRole.ToolTipText,     QColor(_C["fg0"]))
    return p


STYLESHEET = f"""
QMainWindow, QDialog, QWidget {{
    background-color: {_C["bg1"]};
    color: {_C["fg0"]};
    font-family: "Consolas", "Cascadia Code", "Courier New", monospace;
    font-size: 13px;
}}

/* ── Header ─────────────────────────────────────────────────── */
QWidget#header {{
    background-color: {_C["bg0"]};
    border-bottom: 1px solid {_C["border"]};
}}
QLabel#logo {{
    color: {_C["accent"]};
    font-size: 22px;
    font-weight: 900;
    letter-spacing: 4px;
}}
QLabel#tagline {{
    color: {_C["fg2"]};
    font-size: 11px;
    letter-spacing: 1px;
}}

/* ── Tabs ───────────────────────────────────────────────────── */
QTabWidget::pane {{
    border: 1px solid {_C["border"]};
    background: {_C["bg2"]};
}}
QTabBar::tab {{
    background: {_C["bg1"]};
    color: {_C["fg2"]};
    padding: 7px 20px;
    border: none;
    border-bottom: 2px solid transparent;
    font-size: 11px;
    letter-spacing: 1px;
    text-transform: uppercase;
}}
QTabBar::tab:selected {{
    color: {_C["accent"]};
    border-bottom: 2px solid {_C["accent"]};
    background: {_C["bg2"]};
}}
QTabBar::tab:hover:!selected {{
    color: {_C["fg0"]};
    background: {_C["bg2"]};
}}

/* ── GroupBox ───────────────────────────────────────────────── */
QGroupBox {{
    background-color: {_C["bg2"]};
    border: 1px solid {_C["border"]};
    border-radius: 4px;
    color: {_C["fg2"]};
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
    margin-top: 12px;
    padding: 14px 12px 10px 12px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    top: -1px;
    background: {_C["bg2"]};
    padding: 0 6px;
    color: {_C["fg2"]};
}}

/* ── Inputs ─────────────────────────────────────────────────── */
QLineEdit, QSpinBox, QComboBox {{
    background-color: {_C["bg3"]};
    border: 1px solid {_C["border2"]};
    border-radius: 3px;
    color: {_C["fg0"]};
    padding: 5px 8px;
    selection-background-color: {_C["sel"]};
}}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{
    border-color: {_C["accent"]};
}}
QComboBox::drop-down {{ border: none; width: 20px; }}
QComboBox::down-arrow {{ width: 8px; height: 8px; }}
QComboBox QAbstractItemView {{
    background: {_C["bg3"]};
    border: 1px solid {_C["border2"]};
    selection-background-color: {_C["sel"]};
    color: {_C["fg0"]};
}}

/* ── Buttons ────────────────────────────────────────────────── */
QPushButton {{
    background-color: {_C["bg3"]};
    border: 1px solid {_C["border2"]};
    border-radius: 3px;
    color: {_C["fg1"]};
    padding: 6px 16px;
    font-size: 11px;
    letter-spacing: 0.5px;
}}
QPushButton:hover {{ background-color: {_C["border2"]}; color: {_C["fg0"]}; border-color: {_C["fg2"]}; }}
QPushButton:pressed {{ background-color: {_C["bg2"]}; }}
QPushButton:disabled {{ color: {_C["fg2"]}; border-color: {_C["border"]}; }}

QPushButton#btn_scan {{
    background-color: {_C["accent"]};
    border-color: {_C["accent"]};
    color: #fff;
    font-weight: 700;
    font-size: 12px;
    letter-spacing: 1px;
    padding: 8px 24px;
}}
QPushButton#btn_scan:hover {{ background-color: {_C["accent2"]}; }}
QPushButton#btn_scan:disabled {{ background-color: {_C["bg3"]}; color: {_C["fg2"]}; border-color: {_C["border"]}; }}

QPushButton#btn_stop {{
    background-color: transparent;
    border-color: {_C["accent"]};
    color: {_C["accent"]};
}}
QPushButton#btn_stop:hover {{ background-color: {_C["accent"]}22; }}

/* ── CheckBox ───────────────────────────────────────────────── */
QCheckBox {{
    color: {_C["fg1"]};
    spacing: 6px;
    font-size: 12px;
}}
QCheckBox::indicator {{
    width: 14px; height: 14px;
    border: 1px solid {_C["border2"]};
    border-radius: 2px;
    background: {_C["bg3"]};
}}
QCheckBox::indicator:checked {{
    background: {_C["accent"]};
    border-color: {_C["accent"]};
}}
QCheckBox:hover {{ color: {_C["fg0"]}; }}

/* ── Table ──────────────────────────────────────────────────── */
QTableWidget {{
    background-color: {_C["bg2"]};
    border: 1px solid {_C["border"]};
    gridline-color: {_C["border"]};
    color: {_C["fg0"]};
    selection-background-color: {_C["sel"]};
    alternate-background-color: {_C["bg3"]};
}}
QTableWidget::item {{ padding: 4px 8px; }}
QHeaderView::section {{
    background-color: {_C["bg3"]};
    border: none;
    border-right: 1px solid {_C["border"]};
    border-bottom: 1px solid {_C["border"]};
    color: {_C["fg2"]};
    font-size: 10px;
    letter-spacing: 1px;
    text-transform: uppercase;
    padding: 6px 8px;
    font-weight: 700;
}}

/* ── Log / TextEdit ─────────────────────────────────────────── */
QTextEdit {{
    background-color: {_C["bg0"]};
    border: 1px solid {_C["border"]};
    color: {_C["fg1"]};
    font-family: "Consolas", "Cascadia Code", monospace;
    font-size: 12px;
    selection-background-color: {_C["sel"]};
}}

/* ── Scrollbars ─────────────────────────────────────────────── */
QScrollBar:vertical {{
    background: {_C["bg1"]};
    width: 7px; border: none;
}}
QScrollBar::handle:vertical {{
    background: {_C["border2"]};
    border-radius: 3px; min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{ background: {_C["fg2"]}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{
    background: {_C["bg1"]};
    height: 7px; border: none;
}}
QScrollBar::handle:horizontal {{
    background: {_C["border2"]};
    border-radius: 3px; min-width: 24px;
}}
QScrollBar::handle:horizontal:hover {{ background: {_C["fg2"]}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

/* ── Progress ───────────────────────────────────────────────── */
QProgressBar {{
    background: {_C["bg3"]};
    border: 1px solid {_C["border"]};
    border-radius: 2px;
    height: 4px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background: {_C["accent"]};
    border-radius: 2px;
}}

/* ── Status bar ─────────────────────────────────────────────── */
QStatusBar {{
    background: {_C["bg0"]};
    border-top: 1px solid {_C["border"]};
    color: {_C["fg2"]};
    font-size: 11px;
}}
QStatusBar::item {{ border: none; }}

/* ── Splitter ───────────────────────────────────────────────── */
QSplitter::handle {{
    background: {_C["border"]};
}}
QSplitter::handle:horizontal {{ width: 1px; }}
QSplitter::handle:vertical   {{ height: 1px; }}

/* ── Separator ──────────────────────────────────────────────── */
QFrame#sep {{
    background: {_C["border"]};
    max-height: 1px; min-height: 1px;
}}
"""


# ---------------------------------------------------------------------------
# Severity colours (for table cells)
# ---------------------------------------------------------------------------

_SEV_COLOUR = {
    "CRITICAL": _C["critical"],
    "HIGH":     _C["high"],
    "MEDIUM":   _C["medium"],
    "LOW":      _C["low"],
    "INFO":     _C["info"],
}


# ---------------------------------------------------------------------------
# Worker signals + runnable
# ---------------------------------------------------------------------------

class ScanSignals(QObject):
    log     = pyqtSignal(str, str)      # (message, level: info/warn/ok/err)
    finding = pyqtSignal(object)         # Finding.to_dict()
    progress = pyqtSignal(int)           # 0–100
    finished = pyqtSignal(object)        # summary dict
    error    = pyqtSignal(str)


class ScanWorker(QRunnable):
    """Runs the full Creep scan pipeline in a thread pool worker."""

    def __init__(self, config: dict) -> None:
        super().__init__()
        self.config  = config
        self.signals = ScanSignals()
        self._abort  = False

    def abort(self) -> None:
        self._abort = True

    @pyqtSlot()
    def run(self) -> None:
        cfg = self.config
        sig = self.signals
        all_findings: list = []

        def log(msg: str, level: str = "info") -> None:
            sig.log.emit(msg, level)

        def emit_findings(flist: list) -> None:
            for f in flist:
                all_findings.append(f)
                sig.finding.emit(f.to_dict())

        target   = cfg.get("target", ".")
        base_url = cfg.get("base_url", "")

        try:
            step = 0
            total_steps = sum([
                cfg.get("static",  False),
                cfg.get("deps",    False),
                cfg.get("surface", False),
                cfg.get("network", False),
                cfg.get("fuzz",    False),
                cfg.get("auth",    False),
                cfg.get("ai",      False),
            ])
            if total_steps == 0:
                log("No modules selected.", "warn")
                sig.finished.emit({"total": 0})
                return

            def progress() -> None:
                nonlocal step
                step += 1
                sig.progress.emit(int(step / total_steps * 100))

            # ── Phase 1: Static ──────────────────────────────────────
            if cfg.get("static") and not self._abort:
                log("── Static analysis ──────────────────────────────", "info")
                from creep_static import run_static_scan
                findings = run_static_scan(
                    target,
                    scan_ast=cfg.get("static_ast", True),
                    scan_secrets=cfg.get("static_secrets", True),
                    scan_configs=cfg.get("static_configs", True),
                    progress_cb=lambda m: log(f"  {m}", "info"),
                )
                log(f"  Static: {len(findings)} finding(s)", "ok" if findings else "info")
                emit_findings(findings)
                progress()

            # ── Phase 1: Deps ────────────────────────────────────────
            if cfg.get("deps") and not self._abort:
                log("── Dependency audit ─────────────────────────────", "info")
                from creep_deps import run_deps_scan
                findings = run_deps_scan(
                    target,
                    progress_cb=lambda m: log(f"  {m}", "info"),
                )
                log(f"  Deps: {len(findings)} finding(s)", "ok" if findings else "info")
                emit_findings(findings)
                progress()

            # ── Phase 1: Surface ─────────────────────────────────────
            if cfg.get("surface") and not self._abort:
                log("── API surface mapping ──────────────────────────", "info")
                from creep_surface import run_surface_scan
                endpoints, findings = run_surface_scan(
                    target,
                    progress_cb=lambda m: log(f"  {m}", "info"),
                )
                log(f"  Surface: {len(endpoints)} endpoint(s), {len(findings)} finding(s)",
                    "ok" if findings else "info")
                emit_findings(findings)
                progress()

            # ── Phase 2: Network ─────────────────────────────────────
            if cfg.get("network") and not self._abort:
                network_target = cfg.get("network_target") or target
                log(f"── Network scan: {network_target} ──────────────", "warn")
                from creep_network import run_network_scan
                open_ports, findings = run_network_scan(
                    network_target,
                    timeout=float(cfg.get("net_timeout", 2)),
                    max_workers=int(cfg.get("net_workers", 100)),
                    authorized=cfg.get("authorized", False),
                    allow_public=cfg.get("allow_public", False),
                    scope=cfg.get("scope"),
                    progress_cb=lambda m: log(f"  {m}", "info"),
                )
                log(f"  Network: {len(open_ports)} open port(s), {len(findings)} finding(s)",
                    "ok" if findings else "info")
                emit_findings(findings)
                progress()

            # ── Phase 2: Fuzz ────────────────────────────────────────
            if cfg.get("fuzz") and not self._abort:
                if not base_url:
                    log("  Fuzz: no base URL set — skipping", "warn")
                else:
                    log(f"── API fuzzer: {base_url} ───────────────────────", "warn")
                    from creep_fuzz import fuzz_targets, FuzzTarget
                    from creep_surface import run_surface_scan

                    endpoints, _ = run_surface_scan(target)
                    from creep_fuzz import targets_from_surface
                    fuzz_tgts = targets_from_surface(endpoints, base_url)

                    # If no surface endpoints found, fuzz the base URL directly
                    if not fuzz_tgts:
                        fuzz_tgts = [FuzzTarget(url=base_url, method="GET")]

                    cats = cfg.get("fuzz_categories") or None
                    _, findings = fuzz_targets(
                        fuzz_tgts,
                        tier=cfg.get("fuzz_tier", "standard"),
                        categories=cats,
                        timeout=float(cfg.get("fuzz_timeout", 5)),
                        delay=float(cfg.get("fuzz_delay", 0.05)),
                        authorized=cfg.get("authorized", False),
                        allow_public=cfg.get("allow_public", False),
                        scope=cfg.get("scope"),
                        progress_cb=lambda m: log(f"  {m}", "info"),
                    )
                    log(f"  Fuzz: {len(findings)} finding(s)", "ok" if findings else "info")
                    emit_findings(findings)
                progress()

            # ── Phase 2: Auth ────────────────────────────────────────
            if cfg.get("auth") and not self._abort:
                if not base_url:
                    log("  Auth: no base URL set — skipping", "warn")
                else:
                    log(f"── Auth probes: {base_url} ──────────────────────", "warn")
                    from creep_auth import run_auth_scan
                    _, findings = run_auth_scan(
                        base_url,
                        jwt_token=cfg.get("jwt_token") or None,
                        login_url=cfg.get("login_url") or None,
                        protected_paths=cfg.get("protected_paths") or ["/admin", "/api/admin"],
                        timeout=float(cfg.get("auth_timeout", 5)),
                        authorized=cfg.get("authorized", False),
                        allow_public=cfg.get("allow_public", False),
                        scope=cfg.get("scope"),
                        progress_cb=lambda m: log(f"  {m}", "info"),
                    )
                    log(f"  Auth: {len(findings)} finding(s)", "ok" if findings else "info")
                    emit_findings(findings)
                progress()

            # ── Phase 2: AI ──────────────────────────────────────────
            if cfg.get("ai") and not self._abort:
                ai_endpoint = cfg.get("ai_endpoint", "")
                if not ai_endpoint:
                    log("  AI: no endpoint set — skipping", "warn")
                else:
                    log(f"── AI probes: {ai_endpoint} ─────────────────────", "warn")
                    from creep_ai import run_ai_scan
                    _, findings = run_ai_scan(
                        ai_endpoint,
                        model=cfg.get("ai_model", "llama3"),
                        ollama_base=cfg.get("ollama_base") or None,
                        ollama_management=cfg.get("ollama_management", False),
                        categories=cfg.get("ai_categories") or None,
                        timeout=float(cfg.get("ai_timeout", 30)),
                        delay=float(cfg.get("ai_delay", 0.5)),
                        authorized=cfg.get("authorized", False),
                        allow_public=cfg.get("allow_public", False),
                        scope=cfg.get("scope"),
                        progress_cb=lambda m: log(f"  {m}", "info"),
                    )
                    log(f"  AI: {len(findings)} finding(s)", "ok" if findings else "info")
                    emit_findings(findings)
                progress()

            # ── Report ───────────────────────────────────────────────
            from creep_report import build_report
            report = build_report(target, all_findings)

            log("", "info")
            log(f"  Risk: {report.risk_label()} (score {report.risk_score()}/100)", "ok")
            log(f"  Total findings: {report.counts()['TOTAL']}", "ok")

            sig.progress.emit(100)
            sig.finished.emit({
                "report":   report,
                "total":    len(all_findings),
                "risk":     report.risk_label(),
                "score":    report.risk_score(),
                "counts":   report.counts(),
            })

        except ScopeError as exc:
            sig.error.emit(f"SCOPE ERROR: {exc}")
            log(f"[SCOPE ERROR] {exc}", "err")
        except Exception as exc:
            import traceback
            sig.error.emit(traceback.format_exc())
            log(f"ERROR: {exc}", "err")


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

class CreepWindow(QMainWindow):

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {APP_VERSION} — {APP_TAGLINE}")
        self.resize(1280, 820)
        self._worker:  ScanWorker | None = None
        self._report   = None
        self._findings: list[dict] = []
        self._scope_path: str = ""       # path to loaded scope file
        self._scope_data: dict | None = None  # parsed scope dict (or None)

        self._build_ui()
        self._connect_signals()
        self._status("Ready.")

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        root_layout.addWidget(self._build_header())
        root_layout.addWidget(self._build_progress())

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._build_sidebar())
        splitter.addWidget(self._build_main())
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([300, 980])
        root_layout.addWidget(splitter, stretch=1)

        self.setStatusBar(QStatusBar())

    def _build_header(self) -> QWidget:
        w = QWidget()
        w.setObjectName("header")
        w.setFixedHeight(56)
        lay = QHBoxLayout(w)
        lay.setContentsMargins(20, 0, 20, 0)

        logo = QLabel("CREEP")
        logo.setObjectName("logo")
        lay.addWidget(logo)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        sep.setStyleSheet(f"color: {_C['border2']};")
        lay.addWidget(sep)

        tag = QLabel(APP_TAGLINE.upper())
        tag.setObjectName("tagline")
        lay.addWidget(tag)

        lay.addStretch()

        self._btn_scan = QPushButton("▶  RUN SCAN")
        self._btn_scan.setObjectName("btn_scan")
        self._btn_scan.setFixedHeight(34)
        lay.addWidget(self._btn_scan)

        self._btn_stop = QPushButton("■  STOP")
        self._btn_stop.setObjectName("btn_stop")
        self._btn_stop.setFixedHeight(34)
        self._btn_stop.setEnabled(False)
        lay.addWidget(self._btn_stop)

        self._btn_export_html = QPushButton("Export HTML")
        self._btn_export_html.setEnabled(False)
        lay.addWidget(self._btn_export_html)

        self._btn_export_json = QPushButton("Export JSON")
        self._btn_export_json.setEnabled(False)
        lay.addWidget(self._btn_export_json)

        return w

    def _build_progress(self) -> QProgressBar:
        self._progress = QProgressBar()
        self._progress.setFixedHeight(3)
        self._progress.setValue(0)
        self._progress.setTextVisible(False)
        return self._progress

    def _build_sidebar(self) -> QWidget:
        w = QWidget()
        w.setFixedWidth(290)
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(8)

        # ── Target ──────────────────────────────────────────────────
        grp_target = QGroupBox("Target")
        gl = QVBoxLayout(grp_target)
        gl.setSpacing(6)

        gl.addWidget(QLabel("Project path / directory:"))
        self._inp_target = QLineEdit()
        self._inp_target.setPlaceholderText("C:\\Projects\\myapp  or  .")
        gl.addWidget(self._inp_target)

        btn_browse = QPushButton("Browse…")
        btn_browse.clicked.connect(self._browse_target)
        gl.addWidget(btn_browse)

        gl.addWidget(QLabel("Service base URL (Phase 2):"))
        self._inp_base_url = QLineEdit()
        self._inp_base_url.setPlaceholderText("http://localhost:8000")
        gl.addWidget(self._inp_base_url)

        lay.addWidget(grp_target)

        # ── Phase 1 modules ─────────────────────────────────────────
        grp1 = QGroupBox("Phase 1 — Static (safe)")
        g1l = QVBoxLayout(grp1)
        g1l.setSpacing(4)
        self._chk_static  = QCheckBox("Static analysis (AST + secrets)")
        self._chk_deps    = QCheckBox("Dependency CVE audit")
        self._chk_surface = QCheckBox("API surface mapping")
        for chk in (self._chk_static, self._chk_deps, self._chk_surface):
            chk.setChecked(True)
            g1l.addWidget(chk)
        lay.addWidget(grp1)

        # ── Phase 2 modules ─────────────────────────────────────────
        grp2 = QGroupBox("Phase 2 — Active (opt-in)")
        g2l = QVBoxLayout(grp2)
        g2l.setSpacing(6)

        # Authorisation declaration — required to unlock active modules
        self._chk_authorized = QCheckBox(
            "I am authorised to scan this target"
        )
        self._chk_authorized.setChecked(False)
        self._chk_authorized.setStyleSheet(
            f"color: {_C['high']}; font-weight: 700; font-size: 12px;"
        )
        g2l.addWidget(self._chk_authorized)

        self._chk_allow_public = QCheckBox("Allow public IP targets")
        self._chk_allow_public.setChecked(False)
        self._chk_allow_public.setStyleSheet(f"color: {_C['medium']}; font-size: 11px;")
        g2l.addWidget(self._chk_allow_public)

        # ── Scope file ───────────────────────────────────────────────
        scope_row = QHBoxLayout()
        self._btn_scope = QPushButton("Load scope.json…")
        self._btn_scope.setFixedHeight(24)
        self._btn_scope.setStyleSheet(
            f"font-size: 11px; background: {_C['bg3']}; color: {_C['fg1']};"
            f"border: 1px solid {_C['border2']}; border-radius: 3px;"
        )
        self._btn_scope.clicked.connect(self._browse_scope)
        scope_row.addWidget(self._btn_scope)

        self._btn_scope_clear = QPushButton("✕")
        self._btn_scope_clear.setFixedSize(24, 24)
        self._btn_scope_clear.setToolTip("Clear loaded scope file")
        self._btn_scope_clear.setStyleSheet(
            f"font-size: 11px; background: {_C['bg3']}; color: {_C['fg2']};"
            f"border: 1px solid {_C['border2']}; border-radius: 3px;"
        )
        self._btn_scope_clear.clicked.connect(self._clear_scope)
        self._btn_scope_clear.setVisible(False)
        scope_row.addWidget(self._btn_scope_clear)
        g2l.addLayout(scope_row)

        self._lbl_scope = QLabel("No scope file loaded")
        self._lbl_scope.setStyleSheet(
            f"font-size: 10px; color: {_C['fg2']}; font-style: italic;"
        )
        self._lbl_scope.setWordWrap(True)
        g2l.addWidget(self._lbl_scope)

        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.HLine)
        sep2.setStyleSheet(f"color: {_C['border2']};")
        g2l.addWidget(sep2)

        self._chk_network = QCheckBox("Network scan")
        self._chk_fuzz    = QCheckBox("API fuzzer")
        self._chk_auth    = QCheckBox("Auth bypass probes")
        self._chk_ai      = QCheckBox("AI / LLM probes")
        for chk in (self._chk_network, self._chk_fuzz, self._chk_auth, self._chk_ai):
            chk.setChecked(False)
            g2l.addWidget(chk)

        lay.addWidget(grp2)

        # ── Network config ───────────────────────────────────────────
        grp_net = QGroupBox("Network Config")
        gnl = QVBoxLayout(grp_net)
        gnl.setSpacing(5)

        gnl.addWidget(QLabel("Scan host (IP or hostname):"))
        self._inp_net_target = QLineEdit()
        self._inp_net_target.setPlaceholderText("192.168.0.163")
        gnl.addWidget(self._inp_net_target)

        hrow = QHBoxLayout()
        hrow.addWidget(QLabel("Timeout (s):"))
        self._spn_net_timeout = QSpinBox()
        self._spn_net_timeout.setRange(1, 30)
        self._spn_net_timeout.setValue(2)
        hrow.addWidget(self._spn_net_timeout)
        gnl.addLayout(hrow)

        lay.addWidget(grp_net)

        # ── AI config ────────────────────────────────────────────────
        grp_ai = QGroupBox("AI Config")
        gal = QVBoxLayout(grp_ai)
        gal.setSpacing(5)

        gal.addWidget(QLabel("Chat endpoint URL:"))
        self._inp_ai_endpoint = QLineEdit()
        self._inp_ai_endpoint.setPlaceholderText("http://192.168.0.163:11434/api/chat")
        gal.addWidget(self._inp_ai_endpoint)

        gal.addWidget(QLabel("Model name:"))
        self._inp_ai_model = QLineEdit("llama3")
        gal.addWidget(self._inp_ai_model)

        gal.addWidget(QLabel("Ollama base URL (meta probes):"))
        self._inp_ollama_base = QLineEdit()
        self._inp_ollama_base.setPlaceholderText("http://192.168.0.163:11434")
        gal.addWidget(self._inp_ollama_base)

        self._chk_ollama_mgmt = QCheckBox("Enable management probes (pull/delete)")
        self._chk_ollama_mgmt.setChecked(False)
        self._chk_ollama_mgmt.setStyleSheet(f"color: {_C['high']}; font-size: 11px;")
        self._chk_ollama_mgmt.setToolTip(
            "Probes Ollama /api/pull and /api/delete for unauthenticated access.\n"
            "Uses a fake model name — no real models are affected.\n"
            "Opt-in only: these are write-class requests."
        )
        gal.addWidget(self._chk_ollama_mgmt)

        lay.addWidget(grp_ai)

        # ── Auth config ──────────────────────────────────────────────
        grp_auth = QGroupBox("Auth Config")
        gaul = QVBoxLayout(grp_auth)
        gaul.setSpacing(5)

        gaul.addWidget(QLabel("JWT token (optional):"))
        self._inp_jwt = QLineEdit()
        self._inp_jwt.setPlaceholderText("eyJ…")
        self._inp_jwt.setEchoMode(QLineEdit.EchoMode.Password)
        gaul.addWidget(self._inp_jwt)

        gaul.addWidget(QLabel("Login URL (optional):"))
        self._inp_login_url = QLineEdit()
        self._inp_login_url.setPlaceholderText("http://host/auth/login")
        gaul.addWidget(self._inp_login_url)

        lay.addWidget(grp_auth)
        lay.addStretch()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(w)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        return scroll

    def _build_main(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        tabs = QTabWidget()
        tabs.addTab(self._build_findings_tab(), "Findings")
        tabs.addTab(self._build_log_tab(),      "Scan Log")
        lay.addWidget(tabs)

        return w

    def _build_findings_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(8)

        # ── Summary bar ──────────────────────────────────────────────
        self._summary_bar = QWidget()
        sb_lay = QHBoxLayout(self._summary_bar)
        sb_lay.setContentsMargins(0, 0, 0, 0)
        sb_lay.setSpacing(16)

        self._lbl_risk = QLabel("Risk: —")
        self._lbl_risk.setStyleSheet(f"color: {_C['fg2']}; font-size: 12px; font-weight: 700;")
        sb_lay.addWidget(self._lbl_risk)

        self._sev_labels: dict[str, QLabel] = {}
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            lbl = QLabel(f"{sev}: 0")
            lbl.setStyleSheet(f"color: {_SEV_COLOUR[sev]}; font-size: 11px; font-weight: 600;")
            sb_lay.addWidget(lbl)
            self._sev_labels[sev] = lbl

        sb_lay.addStretch()

        # Filter
        self._filter_sev = QComboBox()
        self._filter_sev.addItems(["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self._filter_sev.currentTextChanged.connect(self._apply_filter)
        sb_lay.addWidget(QLabel("Filter:"))
        sb_lay.addWidget(self._filter_sev)

        self._filter_search = QLineEdit()
        self._filter_search.setPlaceholderText("Search…")
        self._filter_search.setFixedWidth(180)
        self._filter_search.textChanged.connect(self._apply_filter)
        sb_lay.addWidget(self._filter_search)

        lay.addWidget(self._summary_bar)

        # ── Findings table ───────────────────────────────────────────
        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(
            ["Severity", "Module", "Target", "Title", "Evidence"]
        )
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setColumnWidth(0, 90)
        self._table.setColumnWidth(1, 80)
        self._table.setColumnWidth(2, 180)
        self._table.setColumnWidth(3, 320)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setSortingEnabled(False)  # enabled after scan completes
        lay.addWidget(self._table)

        # ── Detail pane ──────────────────────────────────────────────
        self._detail = QTextEdit()
        self._detail.setReadOnly(True)
        self._detail.setFixedHeight(120)
        self._detail.setPlaceholderText("Select a finding to see details…")
        lay.addWidget(self._detail)

        self._table.selectionModel().currentRowChanged.connect(
            lambda current, _prev: self._show_detail(current.row())
        )

        return w

    def _build_log_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(8, 8, 8, 8)

        self._log = QTextEdit()
        self._log.setReadOnly(True)
        self._log.setFont(QFont("Consolas", 11))
        lay.addWidget(self._log)

        btn_clear = QPushButton("Clear log")
        btn_clear.setFixedWidth(100)
        btn_clear.clicked.connect(self._log.clear)
        lay.addWidget(btn_clear, alignment=Qt.AlignmentFlag.AlignRight)

        return w

    # ------------------------------------------------------------------
    # Signals
    # ------------------------------------------------------------------

    def _connect_signals(self) -> None:
        self._btn_scan.clicked.connect(self._run_scan)
        self._btn_stop.clicked.connect(self._stop_scan)
        self._btn_export_html.clicked.connect(self._export_html)
        self._btn_export_json.clicked.connect(self._export_json)

    # ------------------------------------------------------------------
    # Scan lifecycle
    # ------------------------------------------------------------------

    def _collect_config(self) -> dict:
        # Merge scope file values with checkbox state — most permissive wins
        scope_authorized  = bool(self._scope_data and self._scope_data.get("authorized"))
        scope_allow_public = bool(self._scope_data and self._scope_data.get("allow_public"))
        return {
            "target":        self._inp_target.text().strip() or ".",
            "base_url":      self._inp_base_url.text().strip(),
            "static":        self._chk_static.isChecked(),
            "deps":          self._chk_deps.isChecked(),
            "surface":       self._chk_surface.isChecked(),
            "network":       self._chk_network.isChecked(),
            "fuzz":          self._chk_fuzz.isChecked(),
            "auth":          self._chk_auth.isChecked(),
            "ai":            self._chk_ai.isChecked(),
            "network_target": self._inp_net_target.text().strip(),
            "net_timeout":   self._spn_net_timeout.value(),
            "ai_endpoint":   self._inp_ai_endpoint.text().strip(),
            "ai_model":      self._inp_ai_model.text().strip() or "llama3",
            "ollama_base":        self._inp_ollama_base.text().strip(),
            "ollama_management":  self._chk_ollama_mgmt.isChecked(),
            "jwt_token":     self._inp_jwt.text().strip(),
            "login_url":     self._inp_login_url.text().strip(),
            "authorized":    self._chk_authorized.isChecked() or scope_authorized,
            "allow_public":  self._chk_allow_public.isChecked() or scope_allow_public,
            "scope":         self._scope_data,  # None if not loaded
        }

    def _run_scan(self) -> None:
        cfg = self._collect_config()

        # Active module gate
        active_modules = [m for m in ("network", "fuzz", "auth", "ai") if cfg.get(m)]
        if active_modules:
            if not cfg.get("authorized"):
                QMessageBox.critical(
                    self, "Authorisation Required",
                    "You must authorise before running any active modules.\n\n"
                    "Either:\n"
                    "  • Check \"I am authorised to scan this target\"\n"
                    "  • Load a scope.json file with \"authorized\": true\n\n"
                    "Only scan systems you own or have written permission to probe.",
                )
                return
            reply = QMessageBox.warning(
                self, "Active Scan Confirmation",
                f"Active modules: {', '.join(m.upper() for m in active_modules)}\n\n"
                f"Target: {cfg.get('base_url') or cfg.get('network_target') or cfg.get('target')}\n\n"
                "You have confirmed authorisation.\n"
                "Scan will be logged to ~/.creep/\n\n"
                "Proceed?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        # Clear previous results
        self._table.setRowCount(0)
        self._findings.clear()
        self._log.clear()
        self._detail.clear()
        self._progress.setValue(0)
        self._btn_export_html.setEnabled(False)
        self._btn_export_json.setEnabled(False)
        self._report = None

        self._btn_scan.setEnabled(False)
        self._btn_stop.setEnabled(True)
        self._status("Scanning…")

        self._worker = ScanWorker(cfg)
        self._worker.signals.log.connect(self._on_log)
        self._worker.signals.finding.connect(self._on_finding)
        self._worker.signals.progress.connect(self._progress.setValue)
        self._worker.signals.finished.connect(self._on_finished)
        self._worker.signals.error.connect(self._on_error)

        QThreadPool.globalInstance().start(self._worker)

    def _stop_scan(self) -> None:
        if self._worker:
            self._worker.abort()
            self._log_line("  [STOP] Scan aborted by user.", "warn")
        self._scan_done()

    def _scan_done(self) -> None:
        self._btn_scan.setEnabled(True)
        self._btn_stop.setEnabled(False)

    # ------------------------------------------------------------------
    # Worker slots
    # ------------------------------------------------------------------

    @pyqtSlot(str, str)
    def _on_log(self, msg: str, level: str) -> None:
        self._log_line(msg, level)

    @pyqtSlot(object)
    def _on_finding(self, fd: dict) -> None:
        self._findings.append(fd)
        self._add_table_row(fd)
        self._update_counts()

    @pyqtSlot(object)
    def _on_finished(self, summary: dict) -> None:
        self._report = summary.get("report")
        self._scan_done()
        counts = summary.get("counts", {})
        risk   = summary.get("risk", "—")
        score  = summary.get("score", 0)
        colour = _SEV_COLOUR.get(risk, _C["fg2"])
        self._lbl_risk.setText(f"Risk: {risk} ({score}/100)")
        self._lbl_risk.setStyleSheet(f"color: {colour}; font-size: 12px; font-weight: 700;")
        self._btn_export_html.setEnabled(True)
        self._btn_export_json.setEnabled(True)
        # Re-enable sorting now that all rows are inserted
        self._table.setSortingEnabled(True)
        total = counts.get("TOTAL", 0)
        self._status(f"Scan complete — {total} finding(s) — Risk: {risk} ({score}/100)")
        self._log_line(f"\n  ✓ Scan complete. {total} finding(s). Risk: {risk} ({score}/100)", "ok")

    @pyqtSlot(str)
    def _on_error(self, tb: str) -> None:
        self._log_line(f"\n[ERROR]\n{tb}", "err")
        self._scan_done()
        self._status("Scan error — see log.")

    # ------------------------------------------------------------------
    # Table helpers
    # ------------------------------------------------------------------

    def _add_table_row(self, fd: dict) -> None:
        sev  = fd.get("severity", "INFO")
        col  = _SEV_COLOUR.get(sev, _C["info"])

        # Disable sorting during insert — setSortingEnabled(True) with live
        # insertRow/setItem causes Qt to re-sort mid-insert, so setItem calls
        # land on the wrong row. Disable, insert all cells, then re-enable.
        self._table.setSortingEnabled(False)
        row = self._table.rowCount()
        self._table.insertRow(row)

        items = [
            sev,
            fd.get("module", ""),
            fd.get("target", ""),
            fd.get("title",  ""),
            fd.get("evidence", ""),
        ]
        for col_idx, val in enumerate(items):
            item = QTableWidgetItem(str(val))
            if col_idx == 0:
                item.setForeground(QColor(col))
                item.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
            self._table.setItem(row, col_idx, item)

        self._table.scrollToBottom()

    def _apply_filter(self) -> None:
        sev_filter  = self._filter_sev.currentText()
        txt_filter  = self._filter_search.text().lower()

        for row in range(self._table.rowCount()):
            sev   = (self._table.item(row, 0) or QTableWidgetItem()).text()
            title = (self._table.item(row, 3) or QTableWidgetItem()).text().lower()
            tgt   = (self._table.item(row, 2) or QTableWidgetItem()).text().lower()

            sev_ok = (sev_filter == "All" or sev == sev_filter)
            txt_ok = (not txt_filter or txt_filter in title or txt_filter in tgt)
            self._table.setRowHidden(row, not (sev_ok and txt_ok))

    def _update_counts(self) -> None:
        from collections import Counter
        c = Counter(f.get("severity", "INFO") for f in self._findings)
        for sev, lbl in self._sev_labels.items():
            lbl.setText(f"{sev}: {c.get(sev, 0)}")

    def _show_detail(self, row: int) -> None:
        if row < 0 or row >= len(self._findings):
            return
        # Match visible row to findings list
        visible = [f for f in self._findings]
        matched = []
        for r in range(self._table.rowCount()):
            if not self._table.isRowHidden(r):
                matched.append(r)

        # Find which finding this row corresponds to
        try:
            fd_idx = matched.index(row) if row in matched else row
        except ValueError:
            fd_idx = row

        # Safer: read directly from table row
        if row >= self._table.rowCount():
            return
        sev    = (self._table.item(row, 0) or QTableWidgetItem()).text()
        module = (self._table.item(row, 1) or QTableWidgetItem()).text()
        target = (self._table.item(row, 2) or QTableWidgetItem()).text()
        title  = (self._table.item(row, 3) or QTableWidgetItem()).text()
        evid   = (self._table.item(row, 4) or QTableWidgetItem()).text()

        # Find matching finding for detail
        detail = ""
        for f in self._findings:
            if f.get("title") == title and f.get("target") == target:
                detail = f.get("detail", "")
                evid   = f.get("evidence", evid)
                break

        col = _SEV_COLOUR.get(sev, _C["info"])
        # Escape all finding content — findings can contain reflected payloads,
        # XSS strings, and injection probes. Never insert raw finding text into HTML.
        e_sev    = _html.escape(sev)
        e_title  = _html.escape(title)
        e_module = _html.escape(module)
        e_target = _html.escape(target)
        e_detail = _html.escape(detail)
        e_evid   = _html.escape(evid)
        self._detail.setHtml(f"""
        <div style='font-family:Consolas,monospace;font-size:12px;color:{_C["fg1"]};'>
        <span style='color:{col};font-weight:700;'>[{e_sev}]</span>
        &nbsp;<span style='color:{_C["fg0"]};'>{e_title}</span><br><br>
        <span style='color:{_C["fg2"]};'>Module:</span> {e_module} &nbsp;
        <span style='color:{_C["fg2"]};'>Target:</span> {e_target}<br><br>
        <span style='color:{_C["fg1"]};'>{e_detail}</span><br><br>
        <span style='color:{_C["fg2"]};font-size:11px;'>{e_evid}</span>
        </div>""")

    # ------------------------------------------------------------------
    # Log helper
    # ------------------------------------------------------------------

    def _log_line(self, msg: str, level: str = "info") -> None:
        colour_map = {
            "info":  _C["fg2"],
            "ok":    _C["green"],
            "warn":  _C["high"],
            "err":   _C["critical"],
        }
        col = colour_map.get(level, _C["fg2"])
        self._log.moveCursor(QTextCursor.MoveOperation.End)
        self._log.insertHtml(
            f'<span style="color:{col};font-family:Consolas,monospace;font-size:12px;">'
            f'{_html.escape(msg).replace(chr(10), "<br>").replace(" ", "&nbsp;")}'
            f'</span><br>'
        )
        self._log.moveCursor(QTextCursor.MoveOperation.End)

    # ------------------------------------------------------------------
    # Status bar
    # ------------------------------------------------------------------

    def _status(self, msg: str) -> None:
        self.statusBar().showMessage(f"  {msg}")

    # ------------------------------------------------------------------
    # Browse
    # ------------------------------------------------------------------

    def _browse_target(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select project directory")
        if path:
            self._inp_target.setText(path)

    def _browse_scope(self) -> None:
        """Open a scope.json file and load it into the GUI."""
        from creep_gate import load_scope_file, ScopeError as _SE
        path, _ = QFileDialog.getOpenFileName(
            self, "Load scope file", "", "JSON files (*.json);;All files (*)"
        )
        if not path:
            return
        try:
            data = load_scope_file(path)
        except _SE as e:
            QMessageBox.critical(self, "Scope File Error", str(e))
            return

        self._scope_path = path
        self._scope_data = data

        # Sync checkboxes with scope file values if they grant permissions
        if data.get("authorized"):
            self._chk_authorized.setChecked(True)
        if data.get("allow_public"):
            self._chk_allow_public.setChecked(True)

        # Show status
        targets = data.get("targets", [])
        note    = data.get("note", "")
        summary = f"✓ {path.split('/')[-1].split(chr(92))[-1]}"
        if targets:
            summary += f" | {len(targets)} target(s)"
        if note:
            summary += f"\n{note[:60]}"
        self._lbl_scope.setText(summary)
        self._lbl_scope.setStyleSheet(
            f"font-size: 10px; color: {_C['green']}; font-style: normal;"
        )
        self._btn_scope_clear.setVisible(True)
        self._status(f"Scope file loaded: {path}")

    def _clear_scope(self) -> None:
        """Clear the loaded scope file."""
        self._scope_path = ""
        self._scope_data = None
        self._lbl_scope.setText("No scope file loaded")
        self._lbl_scope.setStyleSheet(
            f"font-size: 10px; color: {_C['fg2']}; font-style: italic;"
        )
        self._btn_scope_clear.setVisible(False)
        self._status("Scope file cleared.")

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def _export_html(self) -> None:
        if not self._report:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save HTML Report", "creep_report.html", "HTML files (*.html)"
        )
        if path:
            saved = self._report.save_html(path)
            self._status(f"HTML report saved: {saved}")
            webbrowser.open(str(saved))

    def _export_json(self) -> None:
        if not self._report:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save JSON Report", "creep_report.json", "JSON files (*.json)"
        )
        if path:
            saved = self._report.save_json(path)
            self._status(f"JSON report saved: {saved}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName("Leon Priest")

    try:
        app.setStyle("Fusion")
    except Exception:
        pass

    app.setPalette(_build_palette())
    app.setStyleSheet(STYLESHEET)

    window = CreepWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
