# Clickjacking Finder (CJF)

Fast, multi-threaded Clickjacking and web security header vulnerability scanner with interactive HTML PoC generator.

---

## Features

- **Clickjacking Detection**: Checks `X-Frame-Options` and CSP `frame-ancestors`.
- **Security Headers Audit**: HSTS, CSP, CORS, Cookies, and MIME protections.
- **Multi-Threaded**: Concurrent scanning for bulk targets.
- **Interactive PoC**: Generates HTML exploit simulations with UI redressing slider.
- **Bug Bounty Ready**: Auto-generates markdown reports with CVSS metrics.

---

## Installation

```bash
git clone https://github.com/AVII-VERSE/CJF.git
cd CJF
```

---

## Usage

```bash
# Basic scan
python Clickjacking_Finder.py targets.txt

# Multi-threaded fast scan (e.g. 10 threads)
python Clickjacking_Finder.py targets.txt 10
```

### targets.txt format:
```text
example.com
google.com
target.org
```

---

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
