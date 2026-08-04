"""Standalone HTML report with per-finding proof."""

from __future__ import annotations

from html import escape
from typing import Iterable

from authdiff.core.models import Finding

_SEV_COLOR = {"critical": "#b3123c", "high": "#d94f00", "medium": "#c79000",
              "low": "#2a7", "info": "#567"}


def build_html(findings: Iterable[Finding]) -> str:
    findings = list(findings)
    rows = []
    for f in findings:
        color = _SEV_COLOR.get(f.severity.value, "#567")
        proof = "<br>".join(escape(p) for p in f.proof)
        rows.append(f"""
        <div class="finding">
          <span class="sev" style="background:{color}">{f.severity.value.upper()}</span>
          <span class="conf">{f.confidence.value}</span>
          <code class="id">{f.id}</code>
          <h3>{escape(f.kind)}</h3>
          <p><b>{escape(f.actor)}</b> accessed data of <b>{escape(f.victim_owner)}</b></p>
          <p class="req">{escape(f.method)} {escape(f.url)} &rarr; HTTP {f.status_code}
             {f'· CVSS {f.cvss}' if f.cvss else ''}</p>
          <pre class="proof">{proof}</pre>
        </div>""")
    body = "\n".join(rows) or "<p>No findings.</p>"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>AuthDiff Report</title>
<style>
 body{{font-family:system-ui,Segoe UI,Roboto,sans-serif;max-width:960px;margin:2rem auto;
      padding:0 1.5rem;color:#1a1a1a;background:#fafafa}}
 h1{{font-size:1.6rem}} .finding{{background:#fff;border:1px solid #e5e5e5;border-radius:10px;
      padding:1rem 1.25rem;margin:1rem 0;box-shadow:0 1px 3px rgba(0,0,0,.05)}}
 .sev{{color:#fff;padding:.15rem .5rem;border-radius:6px;font-size:.75rem;font-weight:700}}
 .conf{{margin-left:.5rem;font-size:.75rem;color:#666;text-transform:uppercase}}
 .id{{float:right;color:#888;font-size:.8rem}}
 h3{{margin:.6rem 0 .3rem}} .req{{color:#444;font-family:ui-monospace,monospace;font-size:.85rem}}
 .proof{{background:#0f1420;color:#d6e2f0;padding:.75rem;border-radius:8px;overflow:auto;font-size:.8rem}}
</style></head><body>
<h1>AuthDiff — Authorization Findings</h1>
<p>{len(findings)} finding(s). Every <em>proven</em> finding carries a cryptographic canary witness.</p>
{body}
</body></html>"""


def write_html(findings: Iterable[Finding], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(build_html(findings))
