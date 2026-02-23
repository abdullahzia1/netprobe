"""
NetProbe v2 — HTML Report Generator

Reads a RunResult JSON file (produced by --json flag or save_json()) and
renders a self-contained, shareable HTML page suitable for non-technical
readers.

Usage:
    python generate_report.py <input.json> <output.html>
    
The __main__.py also calls build_html() directly when --html is passed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


# ── severity helpers ──────────────────────────────────────────────────────────

SEV_CLEAN    = 0
SEV_INFO     = 10
SEV_LOW      = 25
SEV_MEDIUM   = 50
SEV_HIGH     = 75
SEV_CRITICAL = 100


def _sev_colour(score: int) -> str:
    if score >= SEV_CRITICAL: return "#7f1d1d"
    if score >= SEV_HIGH:     return "#991b1b"
    if score >= SEV_MEDIUM:   return "#92400e"
    if score >= SEV_LOW:      return "#854d0e"
    return "#166534"


def _sev_bg(score: int) -> str:
    if score >= SEV_CRITICAL: return "#fee2e2"
    if score >= SEV_HIGH:     return "#fee2e2"
    if score >= SEV_MEDIUM:   return "#fef3c7"
    if score >= SEV_LOW:      return "#fefce8"
    return "#dcfce7"


def _sev_int(f: dict) -> int:
    """Extract severity as int regardless of whether it was serialized as
    an int (IntEnum → asdict) or as a {"value": N} dict (custom serializer)."""
    raw = f.get("severity", 0)
    if isinstance(raw, dict):
        return raw.get("value", 0)
    return int(raw)


def _badge(score: int, ok_text="✓ Clear", bad_text="✗ Issue") -> str:
    if score <= SEV_INFO:
        return f'<span class="badge ok">{ok_text}</span>'
    if score >= SEV_HIGH:
        return f'<span class="badge crit">{bad_text}</span>'
    return f'<span class="badge warn">{bad_text}</span>'


def _severity_label(score: int) -> str:
    if score >= SEV_CRITICAL: return "Critical"
    if score >= SEV_HIGH:     return "High"
    if score >= SEV_MEDIUM:   return "Medium"
    if score >= SEV_LOW:      return "Low"
    if score >= SEV_INFO:     return "Info"
    return "Clean"


def _bar(score: int) -> str:
    pct = min(score, 100)
    c   = "#22c55e" if pct < 25 else "#f97316" if pct < 75 else "#ef4444"
    return (f'<div class="bar-wrap">'
            f'<div class="bar" style="width:{pct}%;background:{c}"></div>'
            f'<span class="bar-lbl">{_severity_label(score)}</span>'
            f'</div>')


# ── building blocks ───────────────────────────────────────────────────────────

def _module_card(mod: dict) -> str:
    name        = mod.get("module_name", "")
    description = mod.get("module_description", "")
    summary     = mod.get("summary", "")
    score       = mod.get("score", 0)
    dur         = mod.get("duration_ms", 0)
    error       = mod.get("error", "")

    flagged = [f for f in mod.get("findings", [])
               if _sev_int(f) > SEV_INFO
               and f.get("category", "") != "THROTTLE_SAMPLE"]

    colour = _sev_colour(score)
    bg     = _sev_bg(score)

    rows = ""
    for f in flagged:
        sev_val = _sev_int(f)
        rows += f"""
        <tr class="{'row-crit' if sev_val >= SEV_HIGH else 'row-warn'}">
          <td><strong>{f.get('title','')}</strong></td>
          <td>{_badge(sev_val, bad_text=_severity_label(sev_val))}</td>
          <td>{f.get('detail','')}</td>
          <td><small>{f.get('domain','') or f.get('ip','')}</small></td>
          <td><small>{f.get('timestamp','')}</small></td>
        </tr>"""

    if not rows:
        rows = '<tr><td colspan="5" style="color:#166534;padding:16px 14px">✅ No issues detected in this module.</td></tr>'

    if error:
        rows = f'<tr><td colspan="5" style="color:#92400e;padding:16px 14px">⚠️ Module error: {error}</td></tr>'

    return f"""
    <div class="section">
      <div class="section-header" style="border-left:5px solid {colour}">
        <div>
          <h2>{name}</h2>
          <p style="color:#64748b;font-size:0.88rem;margin-top:4px">{description}</p>
        </div>
        <div style="text-align:right;min-width:160px">
          {_bar(score)}
          <small style="color:#94a3b8">{dur:.0f} ms · {len(flagged)} finding(s)</small>
        </div>
      </div>
      <div class="section-desc">{summary}</div>
      <table>
        <thead>
          <tr>
            <th>Finding</th><th>Severity</th>
            <th>Detail</th><th>Domain / IP</th><th>Time</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </div>"""


def _speed_table(modules: list[dict]) -> str:
    """Pull THROTTLE_SAMPLE findings and render a speed summary."""
    samples = []
    for mod in modules:
        if mod.get("module_name") != "Throttling":
            continue
        for f in mod.get("findings", []):
            if f.get("category") == "THROTTLE_SAMPLE":
                raw = f.get("raw", {})
                samples.append(raw)

    if not samples:
        return ""

    rows = ""
    for s in samples:
        kbps  = s.get("kbps", 0)
        label = s.get("label", "")
        bts   = s.get("bytes", 0)
        secs  = s.get("secs", 0)
        speed_str = (f"{kbps/1000:.1f} Mbps" if kbps >= 1000
                     else f"{kbps:.0f} Kbps")
        rows += (f"<tr><td>{label}</td>"
                 f"<td><strong>{speed_str}</strong></td>"
                 f"<td>{bts:,} B</td><td>{secs}s</td></tr>")

    return f"""
    <div class="section">
      <div class="section-header" style="border-left:5px solid #6366f1">
        <div><h2>Speed Test Raw Data</h2></div>
      </div>
      <table>
        <thead><tr><th>Traffic type</th><th>Speed</th><th>Bytes</th><th>Duration</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>"""


# ── main builder ──────────────────────────────────────────────────────────────

def build_html(data: dict) -> str:
    ts       = data.get("timestamp", "Unknown")
    dur      = data.get("duration_ms", 0)
    modules  = data.get("modules", [])

    # Compute overall score & flagged count from the nested structure
    all_findings = [f for m in modules for f in m.get("findings", [])
                    if f.get("category", "") != "THROTTLE_SAMPLE"]
    flagged      = [f for f in all_findings if _sev_int(f) > SEV_INFO]
    overall      = max((_sev_int(f) for f in flagged), default=0)

    # Verdict
    if overall == 0:
        v_icon, v_bg, v_col = "✅", "#dcfce7", "#166534"
        v_text = "No evidence of censorship or monitoring detected."
        v_sub  = "All checks passed. Your connection appears clean."
    elif overall < SEV_HIGH:
        v_icon, v_bg, v_col = "⚠️", "#fef3c7", "#92400e"
        v_text = f"{len(flagged)} finding(s) — worth investigating."
        v_sub  = "Some checks raised flags. May be geo-routing or real interference."
    else:
        v_icon, v_bg, v_col = "🚨", "#fee2e2", "#7f1d1d"
        v_text = f"{len(flagged)} suspicious finding(s) — strong signs of interference."
        v_sub  = ("Multiple independent tests flagged problems. Your connection "
                  "is likely being filtered or monitored.")

    module_cards = "\n".join(_module_card(m) for m in modules)
    speed_table  = _speed_table(modules)

    # Score tiles per module
    tiles = ""
    for m in modules:
        sc = m.get("score", 0)
        col = "#22c55e" if sc == 0 else "#f97316" if sc < SEV_HIGH else "#ef4444"
        tiles += f"""
        <div class="tile">
          <div class="num" style="color:{col}">{sc}</div>
          <strong>{m.get('module_name','')}</strong>
          <small>{len([f for f in m.get('findings',[]) if _sev_int(f) > SEV_INFO])} finding(s)</small>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetProbe — Internet Freedom Report</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                 Helvetica, Arial, sans-serif;
    background: #f8fafc; color: #1e293b; line-height: 1.6;
  }}
  .header {{
    background: linear-gradient(135deg,#1e1b4b,#312e81 60%,#4338ca);
    color:#fff; padding:48px 32px 40px; text-align:center;
  }}
  .header h1 {{ font-size:2.2rem; font-weight:800; }}
  .header p  {{ opacity:.8; margin-top:8px; }}
  .header .meta {{ margin-top:16px; font-size:.82rem; opacity:.6; }}
  .container {{ max-width:980px; margin:0 auto; padding:32px 16px 64px; }}
  .verdict {{
    border-radius:12px; padding:28px 32px; margin-bottom:36px;
    background:{v_bg}; border-left:6px solid {v_col};
  }}
  .verdict .icon {{ font-size:2rem; }}
  .verdict h2 {{ font-size:1.4rem; color:{v_col}; margin:8px 0 4px; }}
  .verdict p  {{ color:{v_col}; opacity:.85; }}
  .tiles {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:36px; }}
  .tile {{
    flex:1; min-width:150px; background:#fff;
    border-radius:10px; padding:20px 24px;
    box-shadow:0 1px 3px rgba(0,0,0,.08); text-align:center;
  }}
  .tile .num {{ font-size:2.4rem; font-weight:800; }}
  .tile small {{ color:#64748b; font-size:.82rem; display:block; margin-top:4px; }}
  .section {{
    background:#fff; border-radius:12px;
    box-shadow:0 1px 3px rgba(0,0,0,.08);
    margin-bottom:28px; overflow:hidden;
  }}
  .section-header {{
    padding:20px 24px; border-bottom:1px solid #e2e8f0;
    display:flex; align-items:flex-start; justify-content:space-between; gap:16px;
  }}
  .section-header h2 {{ font-size:1.1rem; font-weight:700; }}
  .section-desc {{
    padding:12px 24px 16px; color:#64748b;
    font-size:.88rem; border-bottom:1px solid #f1f5f9;
  }}
  table {{ width:100%; border-collapse:collapse; font-size:.86rem; }}
  th {{
    background:#f8fafc; text-align:left; padding:10px 14px;
    font-weight:600; color:#475569; border-bottom:1px solid #e2e8f0;
    font-size:.78rem; text-transform:uppercase; letter-spacing:.04em;
  }}
  td {{ padding:11px 14px; border-bottom:1px solid #f1f5f9; vertical-align:top; }}
  tr:last-child td {{ border-bottom:none; }}
  .row-warn td {{ background:#fff7ed; }}
  .row-crit td {{ background:#fff1f2; }}
  .badge {{
    display:inline-block; padding:3px 10px; border-radius:999px;
    font-size:.76rem; font-weight:600;
  }}
  .badge.ok   {{ background:#dcfce7; color:#166534; }}
  .badge.warn {{ background:#fef3c7; color:#92400e; }}
  .badge.crit {{ background:#fee2e2; color:#991b1b; }}
  .bar-wrap {{ display:flex; align-items:center; gap:8px; margin-bottom:4px; }}
  .bar {{ height:8px; border-radius:4px; min-width:4px; max-width:160px; }}
  .bar-lbl {{ font-size:.78rem; color:#64748b; }}
  .footer {{
    text-align:center; padding:32px;
    font-size:.8rem; color:#94a3b8;
  }}
  @media(max-width:600px) {{
    .header h1 {{ font-size:1.5rem; }}
    .tiles {{ flex-direction:column; }}
  }}
</style>
</head>
<body>

<div class="header">
  <h1>🌐 Internet Freedom Report</h1>
  <p>Independent technical audit of your internet connection — NetProbe v2</p>
  <div class="meta">Generated: {ts} &nbsp;·&nbsp; Scan duration: {dur:.0f} ms</div>
</div>

<div class="container">

  <div class="verdict">
    <div class="icon">{v_icon}</div>
    <h2>{v_text}</h2>
    <p>{v_sub}</p>
  </div>

  <div class="tiles">{tiles}</div>

  {module_cards}

  {speed_table}

  <div class="section">
    <div class="section-header" style="border-left:5px solid #3b82f6">
      <div><h2>🛡️ What Can You Do?</h2></div>
    </div>
    <table>
      <thead><tr><th>Finding type</th><th>Recommended action</th></tr></thead>
      <tbody>
        <tr><td><strong>DNS tampering</strong></td>
            <td>Switch to DNS-over-HTTPS in your browser (Firefox: Settings → Privacy → DNS over HTTPS). Or manually set DNS to 1.1.1.1 or 8.8.8.8.</td></tr>
        <tr><td><strong>TLS interception / MitM</strong></td>
            <td>Use a VPN with certificate pinning. Verify certificates manually using browser developer tools. Report to your country's data protection authority.</td></tr>
        <tr><td><strong>SNI filtering</strong></td>
            <td>Enable Encrypted Client Hello (ECH) in your browser. Use Cloudflare's 1.1.1.1 app or WARP. Or use Tor Browser which hides SNI by default.</td></tr>
        <tr><td><strong>Traffic throttling</strong></td>
            <td>A VPN hides traffic type from the ISP. Document evidence with timestamps and report to your national telecom regulator.</td></tr>
        <tr><td><strong>Port blocking</strong></td>
            <td>Use VPNs that support port 443 (looks like HTTPS). Tor Browser with bridges bypasses most port blocks. Shadowsocks and V2Ray are also effective.</td></tr>
      </tbody>
    </table>
  </div>

</div>

<div class="footer">
  Generated by <strong>NetProbe v2</strong> — open-source internet censorship detection &nbsp;·&nbsp;
  <a href="https://github.com/abdullahzia1/netprobe">github.com/abdullahzia1/netprobe</a>
</div>

</body>
</html>
"""


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: python generate_report.py <input.json> <output.html>")
        sys.exit(1)
    data = json.loads(Path(sys.argv[1]).read_text())
    html = build_html(data)
    out  = Path(sys.argv[2])
    out.write_text(html, encoding="utf-8")
    print(f"Report written to {out.resolve()}")


if __name__ == "__main__":
    main()
