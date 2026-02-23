# NetProbe — Internet Censorship & Monitoring Detection Toolkit

A modular Python 3 tool that detects DNS censorship, transparent proxies, and selective traffic throttling by ISPs or governments.

## Features

| Module | What it does |
|---|---|
| **DNS Censorship** | Compares local DNS results against Google (8.8.8.8) and Cloudflare (1.1.1.1); flags mismatches and optionally tests HTTP/HTTPS reachability. |
| **Proxy Detection** | Detects transparent proxies via header injection analysis, double-Host tricks, HTTP-vs-HTTPS body comparison, and TTL hop-count divergence. |
| **Throttling Detection** | Measures download/upload speeds across HTTP vs HTTPS and small vs large payloads; flags statistical anomalies that suggest traffic shaping. |
| **Reporting** | Produces a clear terminal report and optional JSON export with timestamps and IPs. |

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run all checks
python -m netprobe

# 3. Run specific modules
python -m netprobe --dns-only
python -m netprobe --proxy-only
python -m netprobe --throttle-only

# 4. Include HTTP/HTTPS reachability tests
python -m netprobe --dns-only --reachability

# 5. Custom domain list
python -m netprobe --domains domains.txt

# 6. Save JSON report
python -m netprobe --json report.json
```

## CLI Options

```
usage: netprobe [-h] [--domains FILE] [--reachability] [--rounds N]
                [--json FILE] [--dns-only] [--proxy-only] [--throttle-only]

options:
  --domains FILE     Text file with one domain per line.
  --reachability     Also test HTTP/HTTPS reachability for each domain.
  --rounds N         Number of speed-test rounds per target (default: 3).
  --json FILE        Save results as JSON to FILE.
  --dns-only         Run only DNS censorship checks.
  --proxy-only       Run only transparent proxy detection.
  --throttle-only    Run only throttling detection.
```

## Domain List Format

One domain per line. Lines starting with `#` are ignored:

```
google.com
twitter.com
# this is a comment
wikipedia.org
```

## Project Structure

```
netprobe/
├── __init__.py
├── __main__.py          # CLI entry point
└── modules/
    ├── __init__.py
    ├── dns_censorship.py    # DNS comparison & reachability
    ├── proxy_detection.py   # Transparent proxy tests
    ├── throttle_detection.py# Speed & throttle analysis
    └── report.py            # Terminal & JSON reporting
```

## Requirements

- Python 3.10+
- `requests` — HTTP client
- `dnspython` — DNS resolution against specific servers

## Platform Support

Tested on Linux, macOS, and Windows. Some TTL-based tests may have reduced accuracy on Windows due to socket option differences.
