# Lightweight Web Vulnerability Scanner

A small, read-only command-line scanner for authorised localhost security labs. It crawls same-origin pages, reviews response headers and cookies, checks a short list of common exposed paths, and writes a JSON report with evidence and remediation guidance.

## Features

- Consent gate and loopback-only target validation
- Same-origin crawling with a configurable page limit
- Link, form, and query-parameter inventory
- GET-only passive checks and narrowly scoped benign probes
- Console summary and structured JSON output
- Request delay, timeout, and identifiable User-Agent
- Unit tests for core detection and safety behavior

## Safety and scope

Use this tool only against your own localhost applications or labs for which you have explicit authorization. The scanner refuses to run without `--i-have-permission` and accepts literal loopback IP addresses only (`127.0.0.1` or `::1`). Use the loopback IP in the URL; the hostname `localhost` is not accepted.

The scanner sends GET requests only, does not submit forms, does not follow redirects, and does not attempt authentication or exploit payloads. It uses a unique harmless text marker and a single quote for limited input checks. Exposed-file checks require content signatures rather than relying on an HTTP 200 response.

Defaults are a 250 ms delay between requests, an 8-second timeout, and a 30-page crawl limit. A report marked `incomplete` is not a clean scan; review `request_errors` and rerun after the lab is reachable.

## Requirements

- Python 3.9 or newer
- No third-party packages; the scanner uses the Python standard library

## Run a scan

Start an authorised lab and keep it bound to loopback. Then run:

```powershell
python scanner.py http://127.0.0.1:5000 --i-have-permission -o reports/scan.json
```

To adjust pacing, page limit, or timeout:

```powershell
python scanner.py http://127.0.0.1:18080 --i-have-permission --delay 0.4 --max-pages 50 --timeout 10 -o reports/scan-2.json
```

## Detection coverage

| Checks | OWASP mapping |
| --- | --- |
| HTTP transport, HSTS, Secure cookie flag, mixed content | A02 Cryptographic Failures |
| Database error signature after a quote probe; reflected harmless marker | A03 Injection |
| CSP, frame and content-type headers; directory listing; `.env`, `.git/HEAD`, and phpinfo signatures | A05 Security Misconfiguration |
| Server version banner disclosure | A06 Vulnerable and Outdated Components (inventory signal only) |
| HttpOnly and SameSite cookie flags | A07 Identification and Authentication Failures |
| External scripts without SRI | A08 Software and Data Integrity Failures |
| Permissive CORS and a passive CSRF form heuristic | A01 Broken Access Control |

Findings are indicators for manual review, not proof of exploitability. The scanner does not assess A09 or A10. It cannot reliably test authenticated routes, authorization, business logic, stored or DOM XSS, blind injection, SSRF, race conditions, or dependency CVEs from response banners.

## Tests

```powershell
python -m unittest discover -s tests -v
```

## Project files

- `scanner.py` — command-line interface, crawler, checks, and JSON reporting
- `tests/` — unit tests for safety and detections
- `reports/secureshop-flask.json` — sample scan of the local Flask lab
- `reports/secureshop-node.json` — sample scan of the local Node/Express lab
- `reports/project-report.pdf` — assignment report with architecture, coverage, findings, limitations, and remediation advice
- `build_report.py` — rebuilds the project report PDF

The included sample reports are completed unauthenticated scans of vulnerable local lab profiles. Flask SecureShop was scanned at `127.0.0.1:5000` (8 pages, 5 findings); Node SecureShop was scanned at `127.0.0.1:18080` (13 pages, 5 findings) because its default port was occupied during the scan. Review each finding and evidence before using the results in an assessment.

