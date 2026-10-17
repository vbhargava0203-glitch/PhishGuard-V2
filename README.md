# PhishGuard V2

PhishGuard V2 is an evidence-backed, privacy-first heuristic phishing and risk analyzer. It provides local structural inspection of URLs, SMS/email message text, and QR code payloads without navigating to untrusted targets or relying on fabricated telemetry claims.

## Key Upgrades in V2

1. **Elimination of Fictional Claims:** Removed all fake global threat counters, simulated live tickers, and unverified SSL/WHOIS verification claims.
2. **Robust Local Parser:** Uses reliable URL parsing to examine protocols, hosts, userinfo credentials, IP hostnames, and subdomain nesting separately without false keyword penalties.
3. **Multi-Mode Scanning:** Includes dedicated modes for **URL Inspection**, **Message / SMS Pressure Analysis**, and **QR Code Payload Decoding**.
4. **Local Privacy-First History:** Stores up to 20 recent scans in browser `localStorage` with query token redaction and search/filtering capabilities.
5. **Evidence Export & Printing:** Instant JSON report generation and clean print-to-PDF audit reports.

## Quick Start

1. Extract all files (`index.html`, `style.css`, `script.js`) into a local directory.
2. Open `index.html` in any modern web browser.
3. Enter a URL, paste a suspicious SMS message, or upload a QR image to run the local heuristic evaluation.

## Optional Threat Intelligence Integration

PhishGuard V2 runs fully client-side out of the box in local-only mode. To connect real external reputation providers (such as Google Safe Browsing or PhishTank), implement a secured serverless proxy endpoint to protect API secrets from client-side exposure.