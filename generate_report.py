"""
Generates a self-contained HTML report from a NetProbe JSON result file.
Usage: python generate_report.py <input.json> <output.html>
"""

import json
import sys
from pathlib import Path


def load(path: str) -> dict:
    return json.loads(Path(path).read_text())


def badge(ok: bool, ok_text="Clear", bad_text="Suspicious") -> str:
    if ok:
        return f'<span class="badge ok">{ok_text}</span>'
    return f'<span class="badge warn">{bad_text}</span>'


def severity_bar(ratio: float) -> str:
    """Visual 0-100% severity bar."""
    pct = min(int(ratio * 100), 100)
    colour = "#22c55e" if pct < 40 else "#f97316" if pct < 70 else "#ef4444"
    return (
        f'<div class="bar-wrap">'
        f'<div class="bar" style="width:{pct}%;background:{colour}"></div>'
        f'<span class="bar-label">{pct}%</span>'
        f'</div>'
    )


def fmt_kbps(kbps: float) -> str:
    if kbps >= 1000:
        return f"{kbps/1000:.1f} Mbps"
    return f"{kbps:.0f} Kbps"


def build_html(data: dict) -> str:
    generated = data.get("generated", "Unknown")
    dns_data = data.get("dns", [])
    proxy_data = data.get("proxy", {})
    throttle_data = data.get("throttle", {})

    # ── counts ──────────────────────────────────────────────────────────────
    dns_flagged = [d for d in dns_data if d.get("mismatch")]
    proxy_suspicious = [i for i in proxy_data.get("indicators", [])
                        if i.get("suspicious")]
    throttle_suspicious = [i for i in throttle_data.get("indicators", [])
                           if i.get("suspicious")]
    total_issues = (len(dns_flagged) + len(proxy_suspicious)
                    + len(throttle_suspicious))
    overall_ok = total_issues == 0

    # ── overall verdict ──────────────────────────────────────────────────────
    if total_issues == 0:
        verdict_colour = "#166534"
        verdict_bg = "#dcfce7"
        verdict_icon = "✅"
        verdict_text = "No evidence of censorship or monitoring detected."
        verdict_sub = ("All DNS lookups matched, no proxy was found, and "
                       "internet speeds look normal.")
    elif total_issues <= 3:
        verdict_colour = "#92400e"
        verdict_bg = "#fef3c7"
        verdict_icon = "⚠️"
        verdict_text = f"{total_issues} suspicious finding(s) — worth investigating."
        verdict_sub = ("Some checks raised flags. This could be innocent "
                       "(e.g. geo-routing) or real interference.")
    else:
        verdict_colour = "#7f1d1d"
        verdict_bg = "#fee2e2"
        verdict_icon = "🚨"
        verdict_text = f"{total_issues} suspicious findings — strong signs of interference."
        verdict_sub = ("Multiple independent tests flagged problems. "
                       "Your internet connection is likely being filtered "
                       "or monitored.")

    # ── DNS rows ─────────────────────────────────────────────────────────────
    dns_rows = ""
    for d in dns_data:
        domain = d["domain"]
        mismatch = d.get("mismatch", False)
        local_ips = (d.get("local_result") or {}).get("ips") or []
        local_err = (d.get("local_result") or {}).get("error", "")
        local_str = ", ".join(local_ips) if local_ips else (
            "<em>Resolution failed</em>" if local_err else "—")

        pub_cells = ""
        for pr in d.get("public_results", []):
            pub_ips = ", ".join(pr.get("ips", [])) or pr.get("error", "—")
            pub_cells += f"<td>{pub_ips}</td>"

        if mismatch:
            detail = d.get("mismatch_details", "")
            # plain-English rewrite
            if "failed" in detail.lower():
                plain = ("Your ISP could not resolve this domain at all, "
                         "but Google and Cloudflare found it fine. "
                         "This is a classic sign of DNS-level blocking.")
            else:
                plain = ("Your ISP returned a different server address "
                         "than Google and Cloudflare did. This can mean "
                         "the ISP is redirecting your traffic to a "
                         "different destination without telling you.")
        else:
            plain = ""

        row_class = "row-warn" if mismatch else ""
        dns_rows += f"""
        <tr class="{row_class}">
          <td><strong>{domain}</strong></td>
          <td>{local_str}</td>
          {pub_cells}
          <td>{badge(not mismatch, "✓ Matching", "✗ Mismatch")}</td>
        </tr>
        {"" if not mismatch else f'<tr class="row-detail"><td colspan="5"><div class="detail-box">💬 {plain}</div></td></tr>'}
        """

    # ── proxy section ─────────────────────────────────────────────────────────
    proxy_rows = ""
    proxy_label_map = {
        "Proxy Header Injection":
            ("Header Inspection",
             "We sent a web request and checked if extra hidden headers appeared — "
             "a common sign of a proxy reading your traffic."),
        "Double Host Header":
            ("Double Destination Test",
             "We sent a deliberately malformed request. Normal servers reject it; "
             "transparent proxies silently fix and forward it."),
        "HTTP vs HTTPS Body Comparison":
            ("Content Tampering Check",
             "We fetched the same webpage over encrypted (HTTPS) and unencrypted "
             "(HTTP) channels and compared the results. Differences can reveal "
             "content injection."),
        "TTL Hop-Count Analysis":
            ("Network Route Analysis",
             "We measured how many network hops separate you from a server on "
             "encrypted vs unencrypted ports. A mismatch suggests an extra device "
             "sits in your unencrypted traffic path."),
    }
    for ind in proxy_data.get("indicators", []):
        name = ind.get("test_name", "")
        susp = ind.get("suspicious", False)
        details = ind.get("details", "")
        ts = ind.get("timestamp", "")
        friendly_name, description = proxy_label_map.get(
            name, (name, details))
        row_class = "row-warn" if susp else ""

        # make the raw details human-readable if test was okay
        if "could not complete" in details.lower():
            human_detail = "This specific test could not run on your system — result excluded from verdict."
        elif susp:
            human_detail = (
                "This test raised a flag. On its own this is not conclusive, "
                "but combined with other results it suggests something is "
                "intercepting your traffic.")
        else:
            human_detail = "This test passed — no sign of interception."

        proxy_rows += f"""
        <tr class="{row_class}">
          <td><strong>{friendly_name}</strong><br>
              <small style="color:#6b7280">{description}</small></td>
          <td>{badge(not susp, "✓ Passed", "✗ Flagged")}</td>
          <td>{human_detail}</td>
          <td><small>{ts}</small></td>
        </tr>
        """

    proxy_verdict = proxy_data.get("summary", "")
    proxy_ok = not proxy_data.get("proxy_likely", False)

    # ── throttling section ────────────────────────────────────────────────────
    # Build speed comparison table
    def avg_speed(samples, label_prefix):
        speeds = [s["speed_kbps"] for s in samples
                  if s["label"].startswith(label_prefix) and s["speed_kbps"] > 0]
        return sum(speeds) / len(speeds) if speeds else 0

    dl = throttle_data.get("download_samples", [])
    ul = throttle_data.get("upload_samples", [])

    speeds = {
        "small_https": avg_speed(dl, "small_https"),
        "small_http":  avg_speed(dl, "small_http"),
        "large_https": avg_speed(dl, "large_https"),
        "large_http":  avg_speed(dl, "large_http"),
        "upload_small": avg_speed(ul, "upload_small"),
        "upload_large": avg_speed(ul, "upload_large"),
    }

    speed_rows = ""
    speed_label_map = {
        "small_https": ("Small file — Encrypted (HTTPS)", "download"),
        "small_http":  ("Small file — Unencrypted (HTTP)", "download"),
        "large_https": ("Large file — Encrypted (HTTPS)", "download"),
        "large_http":  ("Large file — Unencrypted (HTTP)", "download"),
        "upload_small": ("Small file — Upload", "upload"),
        "upload_large": ("Large file — Upload", "upload"),
    }
    for key, (label, direction) in speed_label_map.items():
        sp = speeds[key]
        speed_rows += f"""
        <tr>
          <td>{label}</td>
          <td>{"⬇ Download" if direction == "download" else "⬆ Upload"}</td>
          <td><strong>{fmt_kbps(sp)}</strong></td>
        </tr>
        """

    throttle_indicator_rows = ""
    indicator_label_map = {
        "small_http vs small_https":
            "Small encrypted vs unencrypted downloads",
        "large_http vs large_https":
            "Large encrypted vs unencrypted downloads",
        "large_https vs small_https":
            "Large vs small encrypted downloads",
        "small_https jitter":
            "Consistency of small encrypted downloads",
        "small_http jitter":
            "Consistency of small unencrypted downloads",
        "large_https jitter":
            "Consistency of large encrypted downloads",
        "large_http jitter":
            "Consistency of large unencrypted downloads",
        "upload_small vs upload_large":
            "Small vs large uploads",
    }

    for ind in throttle_data.get("indicators", []):
        comp = ind.get("comparison", "")
        susp = ind.get("suspicious", False)
        ratio = ind.get("ratio")
        label = indicator_label_map.get(comp, comp)
        row_class = "row-warn" if susp else ""

        if "jitter" in comp:
            what = (
                "High variability — your speed swings wildly for this type of "
                "traffic, which can indicate the ISP is applying burst controls."
                if susp else
                "Speed is consistent for this traffic type."
            )
        else:
            what = (
                "One channel is significantly slower than the other — "
                "a classic sign of selective speed throttling."
                if susp else
                "Speed is similar across both channels."
            )

        ratio_display = severity_bar(ratio) if ratio is not None else "—"

        throttle_indicator_rows += f"""
        <tr class="{row_class}">
          <td><strong>{label}</strong></td>
          <td>{badge(not susp, "✓ Normal", "✗ Anomaly")}</td>
          <td>{ratio_display}</td>
          <td>{what}</td>
        </tr>
        """

    throttle_verdict = throttle_data.get("summary", "")
    throttle_issues = len(throttle_suspicious)

    # ── assemble HTML ─────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
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
    background: #f8fafc;
    color: #1e293b;
    line-height: 1.6;
  }}
  a {{ color: #3b82f6; }}

  /* ── header ── */
  .header {{
    background: linear-gradient(135deg, #1e1b4b 0%, #312e81 60%, #4338ca 100%);
    color: #fff;
    padding: 48px 32px 40px;
    text-align: center;
  }}
  .header h1 {{ font-size: 2.2rem; font-weight: 800; letter-spacing: -0.5px; }}
  .header p  {{ margin-top: 8px; opacity: 0.8; font-size: 1rem; }}
  .header .meta {{ margin-top: 16px; font-size: 0.85rem; opacity: 0.6; }}

  /* ── layout ── */
  .container {{ max-width: 960px; margin: 0 auto; padding: 32px 16px 64px; }}

  /* ── verdict card ── */
  .verdict {{
    border-radius: 12px;
    padding: 28px 32px;
    margin-bottom: 36px;
    background: {verdict_bg};
    border-left: 6px solid {verdict_colour};
  }}
  .verdict .icon {{ font-size: 2rem; }}
  .verdict h2 {{
    font-size: 1.4rem; color: {verdict_colour};
    margin: 8px 0 4px;
  }}
  .verdict p {{ color: {verdict_colour}; opacity: 0.85; }}

  /* ── score tiles ── */
  .tiles {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 36px; }}
  .tile {{
    flex: 1; min-width: 180px;
    background: #fff;
    border-radius: 10px;
    padding: 20px 24px;
    box-shadow: 0 1px 3px rgba(0,0,0,.08);
    text-align: center;
  }}
  .tile .num {{ font-size: 2.4rem; font-weight: 800; }}
  .tile .num.red  {{ color: #ef4444; }}
  .tile .num.amber {{ color: #f97316; }}
  .tile .num.green {{ color: #22c55e; }}
  .tile small {{ color: #64748b; font-size: 0.82rem; display: block; margin-top: 4px; }}

  /* ── section ── */
  .section {{
    background: #fff;
    border-radius: 12px;
    box-shadow: 0 1px 3px rgba(0,0,0,.08);
    margin-bottom: 32px;
    overflow: hidden;
  }}
  .section-header {{
    padding: 20px 28px;
    border-bottom: 1px solid #e2e8f0;
    display: flex;
    align-items: center;
    gap: 12px;
  }}
  .section-header h2 {{ font-size: 1.15rem; font-weight: 700; }}
  .section-icon {{ font-size: 1.4rem; }}
  .section-desc {{
    padding: 12px 28px 20px;
    color: #64748b;
    font-size: 0.9rem;
    border-bottom: 1px solid #f1f5f9;
  }}

  /* ── tables ── */
  table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
  th {{
    background: #f8fafc;
    text-align: left;
    padding: 11px 14px;
    font-weight: 600;
    color: #475569;
    border-bottom: 1px solid #e2e8f0;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }}
  td {{
    padding: 12px 14px;
    border-bottom: 1px solid #f1f5f9;
    vertical-align: top;
  }}
  tr:last-child td {{ border-bottom: none; }}
  .row-warn td {{ background: #fff7ed; }}
  .row-detail td {{ background: #fff7ed; }}

  /* ── badges ── */
  .badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 999px;
    font-size: 0.78rem;
    font-weight: 600;
  }}
  .badge.ok   {{ background: #dcfce7; color: #166534; }}
  .badge.warn {{ background: #fee2e2; color: #991b1b; }}

  /* ── detail box ── */
  .detail-box {{
    background: #fff7ed;
    border-left: 3px solid #f97316;
    border-radius: 6px;
    padding: 10px 14px;
    font-size: 0.85rem;
    color: #78350f;
  }}

  /* ── bar ── */
  .bar-wrap {{
    display: flex; align-items: center; gap: 8px;
    min-width: 140px;
  }}
  .bar {{
    height: 8px; border-radius: 4px;
    transition: width .3s;
  }}
  .bar-label {{ font-size: 0.78rem; color: #64748b; min-width: 32px; }}

  /* ── verdict footer ── */
  .verdict-pill {{
    display: inline-block;
    padding: 6px 16px;
    border-radius: 999px;
    font-size: 0.85rem;
    font-weight: 600;
    margin-top: 12px;
  }}
  .pill-ok   {{ background: #dcfce7; color: #166534; }}
  .pill-warn {{ background: #fee2e2; color: #991b1b; }}
  .pill-amber{{ background: #fef3c7; color: #92400e; }}

  /* ── explainer callout ── */
  .callout {{
    background: #eff6ff;
    border-left: 4px solid #3b82f6;
    border-radius: 6px;
    padding: 14px 18px;
    font-size: 0.88rem;
    color: #1e40af;
    margin: 16px 28px 20px;
  }}

  /* ── footer ── */
  .footer {{
    text-align: center;
    padding: 32px;
    font-size: 0.8rem;
    color: #94a3b8;
  }}

  @media(max-width: 600px) {{
    .header h1 {{ font-size: 1.5rem; }}
    .tiles {{ flex-direction: column; }}
    td, th {{ padding: 8px 10px; }}
  }}
</style>
</head>
<body>

<div class="header">
  <h1>🌐 Internet Freedom Report</h1>
  <p>An independent technical audit of your internet connection</p>
  <div class="meta">Generated by NetProbe &nbsp;·&nbsp; {generated}</div>
</div>

<div class="container">

  <!-- VERDICT -->
  <div class="verdict">
    <div class="icon">{verdict_icon}</div>
    <h2>{verdict_text}</h2>
    <p>{verdict_sub}</p>
  </div>

  <!-- SCORE TILES -->
  <div class="tiles">
    <div class="tile">
      <div class="num {'red' if dns_flagged else 'green'}">{len(dns_flagged)}</div>
      <strong>Blocked / Tampered Domains</strong>
      <small>out of {len(dns_data)} tested</small>
    </div>
    <div class="tile">
      <div class="num {'amber' if proxy_suspicious else 'green'}">{len(proxy_suspicious)}</div>
      <strong>Proxy Warning Signals</strong>
      <small>out of 4 proxy tests</small>
    </div>
    <div class="tile">
      <div class="num {'red' if throttle_issues >= 3 else 'amber' if throttle_issues else 'green'}">{throttle_issues}</div>
      <strong>Speed Anomalies</strong>
      <small>out of {len(throttle_data.get('indicators', []))} comparisons</small>
    </div>
  </div>

  <!-- DNS SECTION -->
  <div class="section">
    <div class="section-header">
      <span class="section-icon">🔍</span>
      <div>
        <h2>Domain Name Lookup (DNS) Test</h2>
        <span class="{'pill-warn' if dns_flagged else 'pill-ok'} verdict-pill">
          {len(dns_flagged)} mismatch(es) found
        </span>
      </div>
    </div>
    <div class="section-desc">
      <strong>What this tests:</strong> When you type a website address, your
      computer first asks your internet provider (ISP) for directions to that
      site's server. This test compares those directions to what two trusted,
      independent sources say — Google and Cloudflare. If they disagree, your
      ISP may be redirecting or blocking you.
    </div>
    <table>
      <thead>
        <tr>
          <th>Website</th>
          <th>Your ISP's Answer</th>
          <th>Google's Answer</th>
          <th>Cloudflare's Answer</th>
          <th>Result</th>
        </tr>
      </thead>
      <tbody>
        {dns_rows}
      </tbody>
    </table>
  </div>

  <!-- PROXY SECTION -->
  <div class="section">
    <div class="section-header">
      <span class="section-icon">🕵️</span>
      <div>
        <h2>Transparent Proxy Detection</h2>
        <span class="{'pill-warn' if proxy_suspicious else 'pill-ok'} verdict-pill">
          {len(proxy_suspicious)} warning(s) — {proxy_verdict.split("—")[-1].strip() if "—" in proxy_verdict else proxy_verdict}
        </span>
      </div>
    </div>
    <div class="section-desc">
      <strong>What this tests:</strong> A "transparent proxy" is a hidden
      middleman that secretly reads your unencrypted internet traffic —
      without your knowledge or consent. These are sometimes used by ISPs or
      governments for filtering, surveillance, or logging. Four different
      techniques were used to detect one.
    </div>
    <table>
      <thead>
        <tr>
          <th>Test</th>
          <th>Result</th>
          <th>What it means</th>
          <th>Time</th>
        </tr>
      </thead>
      <tbody>
        {proxy_rows}
      </tbody>
    </table>
  </div>

  <!-- THROTTLING SECTION -->
  <div class="section">
    <div class="section-header">
      <span class="section-icon">🐢</span>
      <div>
        <h2>Speed & Throttling Test</h2>
        <span class="{'pill-warn' if throttle_issues >= 2 else 'pill-amber' if throttle_issues else 'pill-ok'} verdict-pill">
          {throttle_verdict}
        </span>
      </div>
    </div>
    <div class="section-desc">
      <strong>What this tests:</strong> ISPs sometimes deliberately slow down
      certain types of traffic — such as encrypted connections, streaming, or
      video calls — while leaving others at full speed. This is called
      "traffic shaping" or "throttling." We ran {3} rounds of speed tests
      across different traffic types and compared the results.
    </div>

    <div class="callout">
      💡 <strong>How to read this:</strong> If encrypted (HTTPS) traffic is
      consistently much slower than unencrypted (HTTP) traffic to the same
      server, that strongly suggests your ISP is artificially slowing down
      your private/secure connections.
    </div>

    <div style="padding: 0 28px 20px;">
      <h3 style="margin-bottom: 12px; font-size: 0.9rem; color: #475569; text-transform: uppercase; letter-spacing: 0.05em;">
        Average Speeds Measured
      </h3>
      <table>
        <thead>
          <tr>
            <th>Traffic Type</th>
            <th>Direction</th>
            <th>Average Speed</th>
          </tr>
        </thead>
        <tbody>{speed_rows}</tbody>
      </table>
    </div>

    <div style="padding: 0 28px 28px;">
      <h3 style="margin-bottom: 12px; font-size: 0.9rem; color: #475569; text-transform: uppercase; letter-spacing: 0.05em;">
        Anomaly Analysis
      </h3>
      <table>
        <thead>
          <tr>
            <th>Comparison</th>
            <th>Result</th>
            <th>Severity</th>
            <th>Plain-English Meaning</th>
          </tr>
        </thead>
        <tbody>{throttle_indicator_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- WHAT TO DO -->
  <div class="section">
    <div class="section-header">
      <span class="section-icon">🛡️</span>
      <div><h2>What Can You Do?</h2></div>
    </div>
    <div style="padding: 20px 28px 28px;">
      <p style="margin-bottom: 16px; color: #475569;">
        If this report found issues, here are practical steps you can take:
      </p>
      <table>
        <thead>
          <tr><th>Finding</th><th>Suggested Action</th></tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>DNS Tampering</strong></td>
            <td>Change your DNS settings to use Cloudflare (1.1.1.1) or
            Google (8.8.8.8) directly, or enable DNS-over-HTTPS in your
            browser settings. This bypasses ISP DNS interference.</td>
          </tr>
          <tr>
            <td><strong>Transparent Proxy</strong></td>
            <td>Use a VPN or ensure you only access sites via HTTPS (look for
            the padlock 🔒 in your browser). Encrypted traffic cannot be read
            by a proxy.</td>
          </tr>
          <tr>
            <td><strong>Throttling</strong></td>
            <td>A VPN encrypts your traffic so your ISP can't see what type
            it is, often restoring full speeds. Document and report throttling
            to your national telecom regulator.</td>
          </tr>
          <tr>
            <td><strong>All of the above</strong></td>
            <td>Consider switching to a different ISP, or use the Tor Browser
            for maximum anonymity. Share this report with digital rights
            organizations in your region.</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- METHODOLOGY -->
  <div class="section">
    <div class="section-header">
      <span class="section-icon">📋</span>
      <div><h2>Methodology & Limitations</h2></div>
    </div>
    <div style="padding: 20px 28px 28px; font-size: 0.88rem; color: #475569;">
      <ul style="padding-left: 20px; line-height: 2;">
        <li>DNS comparisons were made against Google (8.8.8.8) and Cloudflare
            (1.1.1.1) as trusted baselines.</li>
        <li>Speed tests used Cloudflare's public speed test endpoint and
            Google's infrastructure. Results may vary with network congestion.</li>
        <li>All tests were conducted from the same device on the same network
            at the time shown in each result.</li>
        <li><strong>Limitations:</strong> Some DNS mismatches can be caused
            by normal geo-routing (CDNs serving users from nearby data
            centres). Speed differences can also reflect temporary congestion
            rather than deliberate throttling. This tool provides evidence,
            not legal proof.</li>
      </ul>
    </div>
  </div>

</div>

<div class="footer">
  Generated by <strong>NetProbe</strong> — open-source internet censorship detection
  &nbsp;·&nbsp; {generated}
</div>

</body>
</html>
"""
    return html


def main():
    if len(sys.argv) < 3:
        print("Usage: python generate_report.py <input.json> <output.html>")
        sys.exit(1)
    data = load(sys.argv[1])
    html = build_html(data)
    out = Path(sys.argv[2])
    out.write_text(html, encoding="utf-8")
    print(f"Report written to {out.resolve()}")


if __name__ == "__main__":
    main()
