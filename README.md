# NetProbe — Network Analysis & Educational Toolkit

A modular Python 3 tool for exploring how your internet connection behaves, including DNS responses, transparent proxies, and traffic speed characteristics.

## Features

| Module                     | What it does                                                                                                                                       |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **DNS Analysis**           | Compares local DNS results against Google (8.8.8.8) and Cloudflare (1.1.1.1); highlights differences and optionally tests HTTP/HTTPS reachability. |
| **Proxy Detection**        | Detects potential transparent proxies using header analysis, double-Host tests, HTTP-vs-HTTPS body comparison, and TTL hop-count divergence.       |
| **Traffic Speed Analysis** | Measures download/upload speeds across HTTP vs HTTPS and small vs large payloads; flags statistical anomalies in performance.                      |
| **Reporting**              | Produces a clear terminal report and optional JSON export with timestamps and observed IPs.                                                        |

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

# 5. Use a custom domain list
python -m netprobe --domains domains.txt

# 6. Save JSON report
python -m netprobe --json report.json
```

## CLI Options

```bash
usage: netprobe [-h] [--domains FILE] [--reachability] [--rounds N]
                [--json FILE] [--dns-only] [--proxy-only] [--throttle-only]

options:
  --domains FILE     Text file with one domain per line.
  --reachability     Also test HTTP/HTTPS reachability for each domain.
  --rounds N         Number of speed-test rounds per target (default: 3).
  --json FILE        Save results as JSON to FILE.
  --dns-only         Run only DNS analysis.
  --proxy-only       Run only proxy detection tests.
  --throttle-only    Run only traffic speed analysis.
```

## Domain List Format

One domain per line. Lines starting with `#` are ignored:

```text
google.com
twitter.com
# this is a comment
wikipedia.org
```

## Project Structure

```text
netprobe/
├── __init__.py
├── __main__.py          # CLI entry point
└── modules/
    ├── __init__.py
    ├── dns_analysis.py      # DNS comparison & optional reachability
    ├── proxy_detection.py   # Proxy detection tests
    ├── traffic_analysis.py  # Speed & performance analysis
    └── report.py            # Terminal & JSON reporting
```

## Requirements

* Python 3.10+
* `requests` — HTTP client
* `dnspython` — DNS resolution against specific servers

## Platform Support

Tested on Linux, macOS, and Windows. Some TTL-based tests may have reduced accuracy on Windows due to socket option differences.

## Disclaimer

NetProbe is intended for **educational purposes** and **personal exploration** of your own network.
Do **not** attempt to run tests on networks, servers, or systems you do not own or have permission to test.
