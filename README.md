# Clickjacking Finder (CJF)

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey)]()
[![Security Audit](https://img.shields.io/badge/security-automated%20audit-red)]()

A fast, multi-threaded security auditing utility designed to detect **Clickjacking** vectors and misconfigured HTTP security headers across target domains. Generates interactive HTML Proof-of-Concepts (PoC) and structured vulnerability assessment reports for security research and bug bounty workflows.

---

## 📌 Overview

**CJF** automates the inspection of framing protections and modern HTTP response security headers. It evaluates target response metadata to determine whether an application can be maliciously embedded within third-party frames (`<iframe>`), while concurrently auditing transport, content, and origin safeguards.

---

## ⚡ Key Capabilities

* **Clickjacking Assessment**: Evaluates `X-Frame-Options` and `Content-Security-Policy` (`frame-ancestors`) directives against framing exploitation standards.
* **Multi-Threaded Engine**: Built-in concurrent worker threads for rapid scanning of target lists without external dependencies.
* **Comprehensive Header Checks**:
  * Clickjacking Framing Protection (`X-Frame-Options`, CSP `frame-ancestors`)
  * HTTP Strict Transport Security (HSTS) validation & max-age evaluation
  * Content Security Policy (CSP) presence & unsafe directive flags
  * Insecure Cookie Analysis (`Secure`, `HttpOnly`, `SameSite` flags)
  * Cross-Origin Resource Sharing (CORS) wildcard & origin reflection analysis
  * MIME Sniffing Safeguards (`X-Content-Type-Options`)
  * Data Leakage Controls (`Referrer-Policy`, `Permissions-Policy`)
  * Plain HTTP to HTTPS redirect verification
* **Dynamic PoC Generation**: Outputs interactive HTML proof-of-concept files featuring a simulated UI redressing overlay with draggable transparency controls.
* **Standardized Bug Reports**: Generates submission-ready vulnerability templates containing CVSS 3.1 severity metrics and technical evidence.

---

## 📥 Installation

CJF is lightweight and utilizes standard Python libraries without third-party dependencies.

```bash
git clone https://github.com/AVII-VERSE/CJF.git
cd CJF
```

---

## 🚀 Usage

### Scan Single or Multiple Targets
Place domain names or URLs in a target text file (one target per line):

```bash
python Clickjacking_Finder.py targets.txt
```

### High-Concurrency Scanning
Specify worker thread count for faster bulk execution:

```bash
python Clickjacking_Finder.py targets.txt 10
```

### Input File Format (`targets.txt`):
```text
example.com
subdomain.target.org
https://api.domain.net
```

---

## 📊 Sample Output

```text
============================================================
  [1/1] TARGET: example.com
============================================================
  Overall: CRITICAL | Score: 16 | HIGH:4 MED:1 LOW:2 | Issues: 7

  [1] [HIGH] Clickjacking
       Evidence   : X-Frame-Options: NOT PRESENT | CSP frame-ancestors: NOT SET
       Root Cause : Server sends no framing policy. Site can be framed without restriction.
       Impact     : Allows transparent UI Redressing overlays on third-party pages.
       CVSS       : CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | Score: 6.1

  [>] Report : example.com_cjf_report.html
```

---

## 📑 Generated HTML Report Features

Each identified target generates an interactive offline HTML assessment report containing:
- **Executive Summary**: Vulnerability count, overall risk grade, and CVSS score.
- **Detailed Findings Table**: Root cause analysis, exact HTTP header evidence, and CVSS vectors.
- **Header Audit Matrix**: Full breakdown of present vs. missing security headers.
- **Interactive UI Redressing PoC**: Functional visual simulation demonstrating iframe layering with real-time opacity controls.
- **Clipboard-Ready Bug Report**: Structured markdown template formatted for bug bounty platforms.

---

## ⚖️ Legal Disclaimer

This tool is strictly intended for **authorized penetration testing, defensive security audits, and educational research**. Usage of this software against unauthorized targets is strictly prohibited. The maintainers assume no liability for misuse or damage caused by this software.

---

## 📄 License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
