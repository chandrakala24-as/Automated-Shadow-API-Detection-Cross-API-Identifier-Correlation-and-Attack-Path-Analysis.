"""Self-contained HTML report. All dynamic values are escaped."""
from __future__ import annotations

import json
from html import escape

from .db import Scan

STYLE = """
body{font:14px/1.55 system-ui,Segoe UI,sans-serif;color:#172033;max-width:920px;margin:32px auto;padding:0 20px}
h1{margin-bottom:4px}h2{margin-top:36px;border-bottom:2px solid #e3e8f0;padding-bottom:6px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #e3e8f0;vertical-align:top}
code,pre{font-family:Consolas,monospace;font-size:12px}pre{background:#f4f6fa;padding:10px;border-radius:6px;white-space:pre-wrap;word-break:break-word}
.badge{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11px;font-weight:700;text-transform:uppercase;color:#fff}
.critical{background:#b4232a}.high{background:#c2570c}.medium{background:#8a6400}.low{background:#47617f}
.card{border:1px solid #e3e8f0;border-radius:10px;padding:14px 18px;margin:12px 0;break-inside:avoid}
.muted{color:#5b6779}.hint{background:#eef4ff;padding:10px 14px;border-radius:8px}
@media print{.hint{display:none}body{margin:0}}
"""


def _badge(severity: str) -> str:
    return f'<span class="badge {escape(severity)}">{escape(severity)}</span>'


def build_report(scan: Scan) -> str:
    findings = sorted((f for f in scan.findings if f.triage != "false_positive"),
                      key=lambda f: -f.score)
    excluded = len(scan.findings) - len(findings)
    counts = {s: sum(f.severity == s for f in findings)
              for s in ("critical", "high", "medium", "low")}
    stats = scan.stats
    out = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        f"<title>ShadowAPI report - {escape(scan.project.name)}</title><style>{STYLE}</style></head><body>",
        "<p class='hint'>To save this report as a PDF, press Ctrl+P and choose “Save as PDF”.</p>",
        f"<h1>API security report</h1><p class='muted'>{escape(scan.project.name)} · "
        f"{escape(scan.project.base_url)} · scan #{scan.id} · "
        f"{scan.created_at:%Y-%m-%d %H:%M} UTC</p>",
        "<h2>Summary</h2><table><tr><th>Live APIs</th><th>Shadow</th><th>Zombie</th>"
        "<th>Findings</th><th>Attack paths</th><th>Requests</th></tr><tr>",
        "".join(f"<td>{int(stats.get(k, 0))}</td>" for k in
                ("live", "shadow", "zombie", "findings", "paths", "requests")),
        "</tr></table><p>" + " ".join(f"{_badge(k)} {v}" for k, v in counts.items()) + "</p>",
    ]
    if excluded:
        out.append(f"<p class='muted'>{excluded} finding(s) marked as false positive are excluded.</p>")
    if scan.warnings:
        out.append("<h2>Scan limitations</h2><ul>" + "".join(
            f"<li>{escape(w)}</li>" for w in scan.warnings) + "</ul>")

    out.append("<h2>Attack paths</h2>")
    if not scan.paths:
        out.append("<p>No multi-step attack path was verified.</p>")
    for row in scan.paths:
        path = row.data
        out.append(f"<div class='card'>{_badge(path['severity'])} <b>{escape(path['title'])}</b> "
                   f"<span class='muted'>risk {path['score']}/100 · attacker: "
                   f"{escape(path['attacker'])}</span><ol>")
        for step in path["steps"]:
            uses = ", ".join(f"{u['field']} from step {u['from_step']}" for u in step["uses"])
            out.append(f"<li><code>{escape(step['request'])}</code> → {step['status']}"
                       + (f"<br><span class='muted'>uses {escape(uses)}</span>" if uses else "")
                       + "</li>")
        out.append("</ol></div>")

    out.append("<h2>Findings</h2>")
    for row in findings:
        f = row.data
        out.append(
            f"<div class='card'>{_badge(row.severity)} <b>{escape(f['title'])}</b><br>"
            f"<code>{escape(row.endpoint)}</code> <span class='muted'>· risk {row.score}/100 · "
            f"{escape(f['owasp'])} · {escape(f['confidence'])} · status: "
            f"{escape(row.triage.replace('_', ' '))}</span>"
            f"<p>{escape(f['description'])}</p><p><b>Fix:</b> {escape(f['remediation'])}</p>")
        for item in f["evidence"]:
            out.append(f"<p class='muted'>{escape(item['note'])}: <code>{escape(item['request'])}"
                       f"</code> → {item['status']}</p><pre>"
                       f"{escape(json.dumps(item['response'], indent=2))}</pre>")
        out.append("</div>")

    out.append("<h2>API inventory</h2><table><tr><th>Method</th><th>Path</th><th>Class</th>"
               "<th>Found by</th></tr>")
    for e in scan.endpoints:
        out.append(f"<tr><td>{escape(e.method)}</td><td><code>{escape(e.path)}</code></td>"
                   f"<td>{escape(e.classification)}</td>"
                   f"<td>{escape(', '.join(e.data['sources']))}</td></tr>")
    out.append("</table><p class='muted'>Only read-only (GET) requests were sent. An absence of "
               "findings does not prove that an API is secure.</p></body></html>")
    return "".join(out)
