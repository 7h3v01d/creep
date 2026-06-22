"""
creep_report.py — Unified Report Generator
Part of Creep: Defensive Adversarial Security Scanner
Author: Leon Priest
License: Apache 2.0

Aggregates Finding objects from all Creep modules into:
  - An in-memory report object with statistics and deduplication
  - JSON export (machine-readable, CI-friendly)
  - Self-contained HTML report (dark theme, severity-coloured, filterable)

Usage:
    from creep_report import CReepReport
    report = CreepReport(target="myproject", scan_id="2024-01-15")
    report.add(static_findings)
    report.add(deps_findings)
    ...
    report.save_json("creep_report.json")
    report.save_html("creep_report.html")
    print(report.summary())
"""

from __future__ import annotations

import collections
import hashlib
import html
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from creep_static import Category, Finding, Severity

# ---------------------------------------------------------------------------
# Deduplication key
# ---------------------------------------------------------------------------

def _finding_key(f: Finding) -> str:
    """
    Stable dedup key — same vuln in the same location = same key.
    Ignores timestamp and evidence (which may vary slightly between runs).
    """
    raw = f"{f.severity.value}|{f.category.value}|{f.target}|{f.title}|{f.line or ''}"
    return hashlib.md5(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Report object
# ---------------------------------------------------------------------------

@dataclass
class CreepReport:
    target:    str
    scan_id:   str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    started:   str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished:  str = ""

    _findings:  list[Finding]     = field(default_factory=list, repr=False)
    _seen_keys: set[str]          = field(default_factory=set,  repr=False)

    # ------------------------------------------------------------------
    def add(self, findings: Sequence[Finding], *, deduplicate: bool = True) -> int:
        """
        Add findings to the report.
        Returns the number of findings actually added (after dedup).
        """
        added = 0
        for f in findings:
            key = _finding_key(f)
            if deduplicate and key in self._seen_keys:
                continue
            self._seen_keys.add(key)
            self._findings.append(f)
            added += 1
        return added

    # ------------------------------------------------------------------
    @property
    def findings(self) -> list[Finding]:
        return sorted(self._findings, key=lambda f: (f.severity.rank, f.module, f.target))

    # ------------------------------------------------------------------
    def counts(self) -> dict[str, int]:
        c: dict[str, int] = collections.Counter(f.severity.value for f in self._findings)
        return {
            "CRITICAL": c.get("CRITICAL", 0),
            "HIGH":     c.get("HIGH",     0),
            "MEDIUM":   c.get("MEDIUM",   0),
            "LOW":      c.get("LOW",      0),
            "INFO":     c.get("INFO",     0),
            "TOTAL":    len(self._findings),
        }

    def by_module(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = collections.defaultdict(list)
        for f in self._findings:
            result[f.module].append(f)
        return dict(result)

    def by_category(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = collections.defaultdict(list)
        for f in self._findings:
            result[f.category.value].append(f)
        return dict(result)

    # ------------------------------------------------------------------
    def risk_score(self) -> int:
        """
        Simple 0-100 risk score.
        CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1, INFO=0 — capped at 100.
        """
        c = self.counts()
        raw = (
            c["CRITICAL"] * 10 +
            c["HIGH"]     * 5  +
            c["MEDIUM"]   * 2  +
            c["LOW"]      * 1
        )
        return min(raw, 100)

    def risk_label(self) -> str:
        score = self.risk_score()
        if score >= 70: return "CRITICAL"
        if score >= 40: return "HIGH"
        if score >= 20: return "MEDIUM"
        if score >= 5:  return "LOW"
        return "INFO"

    # ------------------------------------------------------------------
    def summary(self) -> str:
        c = self.counts()
        lines = [
            f"{'─'*60}",
            f"  Creep Report — {self.target}",
            f"  Scan ID : {self.scan_id}",
            f"  Risk    : {self.risk_label()} (score {self.risk_score()}/100)",
            f"{'─'*60}",
            f"  CRITICAL : {c['CRITICAL']}",
            f"  HIGH     : {c['HIGH']}",
            f"  MEDIUM   : {c['MEDIUM']}",
            f"  LOW      : {c['LOW']}",
            f"  INFO     : {c['INFO']}",
            f"  TOTAL    : {c['TOTAL']}",
            f"{'─'*60}",
        ]
        mods = self.by_module()
        if mods:
            lines.append("  By module:")
            for mod, flist in sorted(mods.items()):
                crits = sum(1 for f in flist if f.severity == Severity.CRITICAL)
                highs = sum(1 for f in flist if f.severity == Severity.HIGH)
                lines.append(f"    {mod:<12} {len(flist):>3} finding(s)"
                             + (f"  [{crits}C {highs}H]" if crits or highs else ""))
        lines.append(f"{'─'*60}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        c = self.counts()
        return {
            "meta": {
                "target":     self.target,
                "scan_id":    self.scan_id,
                "started":    self.started,
                "finished":   self.finished or datetime.now(timezone.utc).isoformat(),
                "risk_score": self.risk_score(),
                "risk_label": self.risk_label(),
                "generator":  "creep/0.1.0",
            },
            "counts":   c,
            "findings": [f.to_dict() for f in self.findings],
        }

    def save_json(self, path: str | Path) -> Path:
        self.finished = datetime.now(timezone.utc).isoformat()
        p = Path(path)
        p.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return p

    # ------------------------------------------------------------------
    def save_html(self, path: str | Path) -> Path:
        self.finished = datetime.now(timezone.utc).isoformat()
        p = Path(path)
        p.write_text(_render_html(self), encoding="utf-8")
        return p


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------

_SEV_COLOUR = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#44aaff",
    "INFO":     "#888888",
}

_SEV_BG = {
    "CRITICAL": "#2d0000",
    "HIGH":     "#2d1500",
    "MEDIUM":   "#2d2200",
    "LOW":      "#001e2d",
    "INFO":     "#1a1a1a",
}

_MOD_ICON = {
    "static":  "🔍",
    "deps":    "📦",
    "surface": "🗺️",
    "network": "🌐",
    "fuzz":    "💥",
    "auth":    "🔐",
    "ai":      "🤖",
}


def _h(s: str) -> str:
    """HTML-escape a string."""
    return html.escape(str(s))


def _badge(sev: str) -> str:
    colour = _SEV_COLOUR.get(sev, "#888")
    return (
        f'<span style="background:{colour};color:#000;font-weight:700;'
        f'padding:2px 8px;border-radius:3px;font-size:0.75rem;'
        f'letter-spacing:0.05em;">{_h(sev)}</span>'
    )


def _render_html(report: CreepReport) -> str:
    c      = report.counts()
    score  = report.risk_score()
    label  = report.risk_label()
    colour = _SEV_COLOUR.get(label, "#888")
    flist  = report.findings

    # Pre-compute all values that would require backslashes or nested f-strings
    # inside expression blocks — forbidden in Python < 3.12.
    started_str  = _h(report.started[:19].replace("T", " "))
    finished_str = _h((report.finished or "\u2014")[:19].replace("T", " "))
    target_str   = _h(report.target)
    scan_id_str  = _h(report.scan_id)
    label_str    = _h(label)
    total_str    = str(c["TOTAL"])
    score_str    = str(score)

    # Findings rows — pure string concatenation, no f-strings
    rows_parts = []
    for f in flist:
        sev_col   = _SEV_COLOUR.get(f.severity.value, "#888")
        sev_bg    = _SEV_BG.get(f.severity.value, "#111")
        icon      = _MOD_ICON.get(f.module, "\u2022")
        loc       = _h(f.target) + (":" + str(f.line) if f.line else "")
        sev_h     = _h(f.severity.value)
        mod_h     = _h(f.module)
        cat_h     = _h(f.category.value)
        title_h   = _h(f.title)
        detail_h  = _h(f.detail)
        ts        = _h(f.timestamp[:19].replace("T", " "))
        evid_html = (
            "<div style='font-family:monospace;font-size:0.78rem;"
            "color:#888;margin-top:4px;'>Evidence: " + _h(f.evidence) + "</div>"
        ) if f.evidence else ""

        rows_parts.append(
            "<tr class='finding-row'"
            " data-sev='" + sev_h + "' data-mod='" + mod_h + "'"
            " style='border-left:3px solid " + sev_col + ";background:" + sev_bg + ";'"
            " onclick='toggleDetail(this)'>"
            "<td style='padding:8px 12px;white-space:nowrap;'>" + _badge(f.severity.value) + "</td>"
            "<td style='padding:8px 12px;color:#aaa;font-size:0.8rem;'>" + icon + " " + mod_h + "</td>"
            "<td style='padding:8px 12px;color:#ccc;font-size:0.8rem;font-family:monospace;'>" + loc + "</td>"
            "<td style='padding:8px 12px;color:#eee;'>" + title_h + "</td>"
            "</tr>"
            "<tr class='detail-row' style='display:none;'>"
            "<td colspan='4' style='padding:0 12px 12px 28px;background:" + sev_bg + ";'>"
            "<div style='color:#bbb;font-size:0.85rem;margin-bottom:4px;'>" + detail_h + "</div>"
            + evid_html +
            "<div style='font-size:0.75rem;color:#555;margin-top:4px;'>"
            "Module: " + mod_h + " | Category: " + cat_h + " | " + ts + " UTC"
            "</div></td></tr>"
        )
    rows_html = "\n".join(rows_parts)

    # Module breakdown — pure string concatenation
    mods_parts = []
    for mod, mfindings in sorted(report.by_module().items()):
        crits  = sum(1 for f in mfindings if f.severity == Severity.CRITICAL)
        highs  = sum(1 for f in mfindings if f.severity == Severity.HIGH)
        icon   = _MOD_ICON.get(mod, "\u2022")
        accent = "#ff4444" if crits else "#ff8800" if highs else "#555"
        cb = ("&nbsp;\u00b7&nbsp;<span style='color:#ff4444'>" + str(crits) + "C</span>") if crits else ""
        hb = ("&nbsp;\u00b7&nbsp;<span style='color:#ff8800'>" + str(highs) + "H</span>") if highs else ""
        mods_parts.append(
            "<div style='background:#1a1a1a;border:1px solid #2a2a2a;"
            "border-left:3px solid " + accent + ";padding:10px 14px;border-radius:4px;'>"
            "<div style='color:#ccc;font-weight:600;'>" + icon + " " + _h(mod) + "</div>"
            "<div style='color:#888;font-size:0.82rem;margin-top:2px;'>"
            + str(len(mfindings)) + " finding(s)" + cb + hb + "</div></div>"
        )
    mods_html = "\n".join(mods_parts)

    # Severity bars — pure string concatenation
    bars_parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n   = c[sev]
        pct = round(n / max(c["TOTAL"], 1) * 100)
        col = _SEV_COLOUR[sev]
        bars_parts.append(
            "<div style='margin-bottom:10px;'>"
            "<div style='display:flex;justify-content:space-between;margin-bottom:3px;'>"
            "<span style='color:" + col + ";font-size:0.8rem;font-weight:600;'>" + sev + "</span>"
            "<span style='color:#888;font-size:0.8rem;'>" + str(n) + "</span>"
            "</div><div style='background:#2a2a2a;border-radius:2px;height:6px;'>"
            "<div style='background:" + col + ";width:" + str(pct) + "%;height:6px;border-radius:2px;'>"
            "</div></div></div>"
        )
    stat_bars = "\n".join(bars_parts)

    # Filter buttons — pure string concatenation
    sev_btns = "".join(
        "<span class='filter-btn' onclick='filterSev(\""
        + s + "\")'><span style='color:" + _SEV_COLOUR[s] + ";'>" + s + "</span> "
        + str(c[s]) + "</span>"
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )
    mod_btns = "".join(
        "<span class='filter-btn' onclick='filterMod(\"" + m + "\")'>"
        + _MOD_ICON.get(m, "\u2022") + " " + m + "</span>"
        for m in sorted(report.by_module().keys())
    )

    findings_content = (
        "<div class='empty'>No findings.</div>" if not flist
        else "<table id='findings-table'>" + rows_html + "</table>"
    )

    return (
        "<!DOCTYPE html>\n<html lang='en'>\n<head>\n"
        "<meta charset='UTF-8'>\n"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>\n"
        "<title>Creep Report \u2014 " + target_str + "</title>\n"
        "<style>\n"
        "  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }\n"
        "  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;"
        " background: #0d0d0d; color: #ddd; min-height: 100vh; }\n"
        "  .header { background: #111; border-bottom: 1px solid #222;"
        " padding: 24px 32px; display: flex; align-items: center; gap: 20px; }\n"
        "  .logo { font-family: monospace; font-size: 1.6rem; font-weight: 900;"
        " color: " + colour + "; letter-spacing: 0.15em; }\n"
        "  .meta { color: #666; font-size: 0.82rem; margin-top: 4px; }\n"
        "  .risk-badge { margin-left: auto; background: " + colour + "22;"
        " border: 1px solid " + colour + "; color: " + colour + ";"
        " padding: 8px 20px; border-radius: 6px; font-weight: 700;"
        " font-size: 1.1rem; letter-spacing: 0.1em; text-align: center; }\n"
        "  .risk-score { font-size: 0.75rem; color: " + colour + "99; }\n"
        "  .layout { display: grid; grid-template-columns: 280px 1fr;"
        " gap: 24px; padding: 24px 32px; max-width: 1400px; margin: 0 auto; }\n"
        "  .sidebar { display: flex; flex-direction: column; gap: 16px; }\n"
        "  .card { background: #111; border: 1px solid #222; border-radius: 6px; padding: 16px; }\n"
        "  .card-title { font-size: 0.75rem; font-weight: 700; text-transform: uppercase;"
        " letter-spacing: 0.1em; color: #666; margin-bottom: 12px; }\n"
        "  .filter-btn { display: inline-block; padding: 4px 10px; border-radius: 3px;"
        " border: 1px solid #333; background: #1a1a1a; color: #aaa;"
        " cursor: pointer; font-size: 0.78rem; margin: 2px; transition: all 0.15s; }\n"
        "  .filter-btn:hover, .filter-btn.active { border-color: #666; color: #eee; background: #2a2a2a; }\n"
        "  .main { min-width: 0; }\n"
        "  .section-title { font-size: 0.75rem; font-weight: 700; text-transform: uppercase;"
        " letter-spacing: 0.1em; color: #555; margin-bottom: 12px; }\n"
        "  table { width: 100%; border-collapse: collapse; }\n"
        "  .finding-row { cursor: pointer; transition: filter 0.1s; }\n"
        "  .finding-row:hover { filter: brightness(1.3); }\n"
        "  td { vertical-align: top; }\n"
        "  .empty { color: #444; text-align: center; padding: 48px; font-size: 0.9rem; }\n"
        "  .search { width: 100%; background: #1a1a1a; border: 1px solid #333;"
        " color: #ddd; padding: 8px 12px; border-radius: 4px; font-size: 0.88rem;"
        " margin-bottom: 12px; outline: none; }\n"
        "  .search:focus { border-color: #555; }\n"
        "</style>\n</head>\n<body>\n\n"
        "<div class='header'>\n  <div>\n"
        "    <div class='logo'>CREEP</div>\n"
        "    <div style='color:#aaa;font-size:0.95rem;margin-top:2px;'>"
        "Adversarial Security Report \u2014 <strong style='color:#ddd'>" + target_str + "</strong></div>\n"
        "    <div class='meta'>Scan ID: " + scan_id_str + " &nbsp;\u00b7&nbsp; "
        + started_str + " UTC &nbsp;\u00b7&nbsp; " + total_str + " finding(s)"
        " &nbsp;\u00b7&nbsp; creep/0.1.0</div>\n  </div>\n"
        "  <div class='risk-badge'>" + label_str
        + "<div class='risk-score'>score " + score_str + "/100</div></div>\n</div>\n\n"
        "<div class='layout'>\n  <div class='sidebar'>\n"
        "    <div class='card'><div class='card-title'>Severity</div>\n" + stat_bars + "\n    </div>\n"
        "    <div class='card'><div class='card-title'>Filter by Severity</div>\n      <div>"
        "<span class='filter-btn active' onclick='filterSev(\"ALL\")'>All</span>"
        + sev_btns + "</div>\n    </div>\n"
        "    <div class='card'><div class='card-title'>Filter by Module</div>\n      <div>"
        "<span class='filter-btn active' onclick='filterMod(\"ALL\")'>All</span>"
        + mod_btns + "</div>\n    </div>\n"
        "    <div class='card'><div class='card-title'>Modules Scanned</div>\n"
        "      <div style='display:flex;flex-direction:column;gap:8px;'>\n"
        + mods_html + "\n      </div>\n    </div>\n"
        "    <div class='card'><div class='card-title'>Scan Info</div>\n"
        "      <div style='font-size:0.8rem;color:#666;line-height:1.8;'>\n"
        "        <div>Target: <span style='color:#aaa'>" + target_str + "</span></div>\n"
        "        <div>Started: <span style='color:#aaa'>" + started_str + "</span></div>\n"
        "        <div>Finished: <span style='color:#aaa'>" + finished_str + "</span></div>\n"
        "        <div>Risk score: <span style='color:" + colour + "'>"
        + score_str + "/100 (" + label_str + ")</span></div>\n"
        "      </div>\n    </div>\n  </div>\n\n"
        "  <div class='main'>\n"
        "    <div class='section-title'>Findings (" + total_str + ")</div>\n"
        "    <input class='search' type='text' placeholder='Search findings\u2026'"
        " oninput='filterSearch(this.value)'>\n"
        "    <div id='findings-wrap'>\n      " + findings_content + "\n    </div>\n  </div>\n</div>\n\n"
        "<script>\n"
        "  let activeSev = 'ALL';\n"
        "  let activeMod = 'ALL';\n"
        "  let searchTxt = '';\n\n"
        "  function applyFilters() {\n"
        "    const rows  = document.querySelectorAll('.finding-row');\n"
        "    const drows = document.querySelectorAll('.detail-row');\n"
        "    drows.forEach(r => r.style.display = 'none');\n"
        "    rows.forEach(r => {\n"
        "      const sev   = r.dataset.sev;\n"
        "      const mod   = r.dataset.mod;\n"
        "      const title = r.innerText.toLowerCase();\n"
        "      const show  =\n"
        "        (activeSev === 'ALL' || sev === activeSev) &&\n"
        "        (activeMod === 'ALL' || mod === activeMod) &&\n"
        "        (searchTxt === '' || title.includes(searchTxt));\n"
        "      r.style.display = show ? '' : 'none';\n"
        "    });\n  }\n\n"
        "  function filterSev(s) {\n"
        "    activeSev = s;\n"
        "    document.querySelectorAll('.filter-btn').forEach(b => {\n"
        "      if (b.onclick && b.onclick.toString().includes('filterSev'))\n"
        "        b.classList.toggle('active', b.innerText.trim().startsWith(s) || s === 'ALL');\n"
        "    });\n"
        "    applyFilters();\n  }\n\n"
        "  function filterMod(m) { activeMod = m; applyFilters(); }\n\n"
        "  function filterSearch(v) { searchTxt = v.toLowerCase(); applyFilters(); }\n\n"
        "  function toggleDetail(row) {\n"
        "    const next = row.nextElementSibling;\n"
        "    if (next && next.classList.contains('detail-row')) {\n"
        "      next.style.display = next.style.display === 'none' ? '' : 'none';\n"
        "    }\n  }\n"
        "</script>\n</body>\n</html>"
    )


# ---------------------------------------------------------------------------
# Convenience runner — combine all module outputs into one report
# ---------------------------------------------------------------------------

def build_report(
    target:       str,
    *finding_lists,
    scan_id:      str | None = None,
) -> CreepReport:
    """
    Build a CreepReport from any number of finding lists.

    Usage:
        report = build_report(
            "myproject",
            static_findings,
            deps_findings,
            surface_findings,
            network_findings,
            fuzz_findings,
            auth_findings,
            ai_findings,
        )
    """
    r = CreepReport(
        target=target,
        scan_id=scan_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
    )
    for flist in finding_lists:
        r.add(flist)
    r.finished = datetime.now(timezone.utc).isoformat()
    return r


# ---------------------------------------------------------------------------
# CLI entry point — load a JSON findings file and re-render
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python creep_report.py <findings.json> [output_html]")
        print("       Reads a creep JSON report and re-renders to HTML.")
        sys.exit(1)

    src  = Path(sys.argv[1])
    dest = Path(sys.argv[2]) if len(sys.argv) > 2 else src.with_suffix(".html")

    data = json.loads(src.read_text(encoding="utf-8"))
    meta = data.get("meta", {})

    report = CreepReport(
        target=meta.get("target", src.stem),
        scan_id=meta.get("scan_id", ""),
        started=meta.get("started", ""),
        finished=meta.get("finished", ""),
    )

    for fd in data.get("findings", []):
        report._findings.append(Finding(
            severity=Severity(fd["severity"]),
            category=Category(fd["category"]),
            target=fd.get("target", ""),
            title=fd.get("title", ""),
            detail=fd.get("detail", ""),
            evidence=fd.get("evidence", ""),
            line=fd.get("line"),
            module=fd.get("module", ""),
            timestamp=fd.get("timestamp", ""),
        ))

    html_path = report.save_html(dest)
    print(report.summary())
    print(f"\n  HTML report saved: {html_path}")
