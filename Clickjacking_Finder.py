# Author: AVII-VERSE
# CJF - Clickjacking Finder & Web Security Scanner v1.0
# High-Performance Multi-Threaded Vulnerability Auditor

import os
import sys
import ssl
import socket
import json
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from sys import argv, exit

if os.name == 'nt':
    os.system('')

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

__author__  = 'AVII-VERSE'
__version__ = '1.0'

# ── ANSI COLORS ─────────────────────────────────────
C   = '\033[96m'   # Cyan
G   = '\033[92m'   # Green
Y   = '\033[93m'   # Yellow
R   = '\033[91m'   # Red
M   = '\033[95m'   # Magenta
B   = '\033[94m'   # Blue
W   = '\033[97m'   # Bright White
BO  = '\033[1m'    # Bold
DM  = '\033[2m'    # Dim
RS  = '\033[0m'    # Reset

RISK_C = {'CRITICAL': R, 'HIGH': R, 'MEDIUM': Y, 'LOW': C, 'INFO': B}
RISK_S = {'CRITICAL': 5, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}

BANNER = rf"""{C}{BO}
  ____     _   _____ 
 / ___|   | | |  ___|
| |    _  | | | |_   
| |___| |_| | |  _|  
 \____|\___/  |_|    
{M}+====================================================+
|  {Y}CLICKJACKING FINDER (CJF) v1.0{M}                    |
|  {B}[*] Author  : {G}AVII-VERSE{M}                            |
|  {B}[*] Mode    : {G}Full-Spectrum Vulnerability Auditor{M}    |
|  {B}[*] Engine  : {G}Multi-Threaded Security Scanner{M}        |
+====================================================+{RS}
"""

THREADS = 5
TIMEOUT = 8
UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 CJF/1.0'

# ═══════════════════════════════════════════════════
#  SECURITY AUDIT FUNCTIONS
# ═══════════════════════════════════════════════════

def get_target_ip(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return "Unknown"

def chk_clickjacking(hdrs, full_url):
    xfo = hdrs.get('X-Frame-Options')
    csp = hdrs.get('Content-Security-Policy', '')
    fa  = 'frame-ancestors' in csp.lower() if csp else False
    if xfo is None and not fa:
        return {
            'id':       'CLICKJACKING',
            'risk':     'HIGH',
            'name':     'Clickjacking (Missing Framing Protections)',
            'location': 'HTTP Response Headers -> X-Frame-Options & Content-Security-Policy',
            'evidence': 'X-Frame-Options: NOT PRESENT | CSP frame-ancestors: NOT SET',
            'root':     'The server omits framing protection directives. Web browsers allow any external domain to render this webpage inside an <iframe> context.',
            'impact':   'Attackers can embed this application transparently beneath a decoy user interface on an external website, coercing victims into unknowingly executing state-changing operations (account modification, transaction authorization, data deletion).',
            'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | Score: 6.1',
            'fix':      "Add the following header to server configuration:\n"
                        "Nginx:   add_header Content-Security-Policy \"frame-ancestors 'none';\" always;\n"
                        "Apache:  Header always set Content-Security-Policy \"frame-ancestors 'none';\"\n"
                        "Express: app.use(helmet.frameguard({ action: 'deny' }));",
            'ref':      'https://owasp.org/www-community/attacks/Clickjacking',
            'poc':      True,
        }
    return None

def chk_cors_wildcard(hdrs):
    acao = hdrs.get('Access-Control-Allow-Origin', '')
    acac = hdrs.get('Access-Control-Allow-Credentials', '')
    if acao == '*':
        sev = 'HIGH' if 'true' in acac.lower() else 'MEDIUM'
        return {
            'id':       'CORS_WILDCARD',
            'risk':     sev,
            'name':     'Insecure CORS Wildcard Header',
            'location': 'HTTP Response Headers -> Access-Control-Allow-Origin',
            'evidence': f'Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: {acac or "Not Set"}',
            'root':     'The web application implements a blanket wildcard (*) Access-Control-Allow-Origin header instead of validating requested origins.',
            'impact':   'Arbitrary websites can initiate cross-origin XMLHttpRequests/fetch calls and inspect private application responses if sensitive information is returned on non-credentialed routes.',
            'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N | Score: 7.2',
            'fix':      "Remove the wildcard origin. Validate origin headers against a strict server-side whitelist:\n"
                        "Nginx:   if ($http_origin ~* (https://trusted\\.domain\\.com)) { add_header Access-Control-Allow-Origin $http_origin; }\n"
                        "Express: app.use(cors({ origin: ['https://trusted.domain.com'], credentials: true }));",
            'ref':      'https://portswigger.net/web-security/cors',
            'poc':      False,
        }
    return None

def chk_cors_reflection(base_url):
    try:
        test_origin = 'https://attacker-controlled-context.com'
        req = Request(base_url, headers={'User-Agent': UA, 'Origin': test_origin})
        resp = urlopen(req, timeout=TIMEOUT)
        acao = resp.info().get('Access-Control-Allow-Origin', '')
        acac = resp.info().get('Access-Control-Allow-Credentials', '')
        if test_origin in acao:
            sev = 'CRITICAL' if 'true' in acac.lower() else 'HIGH'
            return {
                'id':       'CORS_REFLECT',
                'risk':     sev,
                'name':     'Arbitrary CORS Origin Reflection',
                'location': 'Server Origin Validation Logic -> Access-Control-Allow-Origin',
                'evidence': f'Sent Origin: {test_origin} | Reflected ACAO: {acao} | Allow-Credentials: {acac or "false"}',
                'root':     'The server dynamically mirrors the incoming request Origin header directly into Access-Control-Allow-Origin without whitelist validation.',
                'impact':   'Enables complete Same-Origin Policy (SOP) bypass. A malicious domain visited by an authenticated user can read sensitive session data, profile details, and API responses.',
                'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N | Score: 9.3',
                'fix':      "Never reflect arbitrary request Origin headers. Enforce an immutable whitelist:\n"
                        "Nginx:   map $http_origin $cors_allowed { default \"\"; \"https://trusted.com\" \"$http_origin\"; }\n"
                        "Node.js: cors({ origin: function(origin, callback) { if(whitelist.indexOf(origin) !== -1) callback(null, true); } })",
                'ref':      'https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack',
                'poc':      False,
            }
    except Exception:
        pass
    return None

def chk_cookies(hdrs):
    raw = hdrs.get_all('Set-Cookie') if hasattr(hdrs, 'get_all') else [hdrs.get('Set-Cookie')]
    if not raw or raw == [None]:
        return None
    issues = []
    for ck in raw:
        if not ck: continue
        ck_lower = ck.lower()
        cookie_name = ck.split('=')[0].strip()
        if 'secure' not in ck_lower:
            issues.append(f"'{cookie_name}' missing Secure flag (transmitted over cleartext HTTP)")
        if 'httponly' not in ck_lower:
            issues.append(f"'{cookie_name}' missing HttpOnly flag (accessible via document.cookie XSS)")
        if 'samesite' not in ck_lower:
            issues.append(f"'{cookie_name}' missing SameSite flag (susceptible to CSRF vectors)")
    if issues:
        return {
            'id':       'INSECURE_COOKIE',
            'risk':     'HIGH',
            'name':     'Insecure Cookie Attributes Missing',
            'location': 'HTTP Response Headers -> Set-Cookie',
            'evidence': ' | '.join(issues[:3]),
            'root':     'Session tokens or persistent application state cookies are instantiated without defensive security attributes (Secure, HttpOnly, SameSite).',
            'impact':   'Missing HttpOnly permits script-driven cookie theft during Cross-Site Scripting (XSS). Missing Secure permits cookie interception over cleartext networks. Missing SameSite facilitates Cross-Site Request Forgery (CSRF).',
            'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N | Score: 7.1',
            'fix':      "Configure all authentication and session cookies with security flags:\n"
                        "Set-Cookie: session_id=<token>; Secure; HttpOnly; SameSite=Strict; Path=/;\n"
                        "Express: res.cookie('session', token, { secure: true, httpOnly: true, sameSite: 'strict' });",
            'ref':      'https://owasp.org/www-community/controls/SecureCookieAttribute',
            'poc':      False,
        }
    return None

def chk_hsts(hdrs, url):
    hsts = hdrs.get('Strict-Transport-Security')
    if url.startswith('https://') and hsts is None:
        return {
            'id':       'MISSING_HSTS',
            'risk':     'HIGH',
            'name':     'Missing HTTP Strict Transport Security (HSTS)',
            'location': 'HTTP Response Headers -> Strict-Transport-Security',
            'evidence': 'Strict-Transport-Security: NOT PRESENT on HTTPS endpoint',
            'root':     'The server serves content securely via HTTPS but does not mandate modern browsers to strictly enforce HTTPS connections on future requests.',
            'impact':   'Leaves end users susceptible to SSL Stripping and active Man-in-the-Middle (MITM) downgrade attacks over unsecured public networks.',
            'cvss':     'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N | Score: 6.8',
            'fix':      "Enable HSTS with a minimum max-age duration of one year (31536000 seconds):\n"
                        "Nginx:   add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n"
                        "Apache:  Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
            'ref':      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
            'poc':      False,
        }
    elif hsts:
        try:
            parts = [p.strip().lower() for p in hsts.split(';')]
            max_age_part = [p for p in parts if p.startswith('max-age=')]
            if max_age_part:
                age = int(max_age_part[0].split('=')[1])
                if age < 15552000: # Less than 180 days
                    return {
                        'id':       'WEAK_HSTS',
                        'risk':     'MEDIUM',
                        'name':     'Weak HSTS max-age Duration',
                        'location': 'HTTP Response Headers -> Strict-Transport-Security',
                        'evidence': f'Strict-Transport-Security: {hsts} (max-age is {age}s, recommended >= 31536000s)',
                        'root':     'The configured max-age parameter is too short to provide persistent HTTPS enforcement.',
                        'impact':   'Reduces protection window against protocol downgrade and SSL stripping attacks.',
                        'cvss':     'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N | Score: 4.2',
                        'fix':      'Increase HSTS duration to at least 31536000 seconds (1 year) and includeSubDomains.',
                        'ref':      'https://hstspreload.org/',
                        'poc':      False,
                    }
        except Exception:
            pass
    return None

def chk_csp(hdrs):
    csp = hdrs.get('Content-Security-Policy')
    if csp is None:
        return {
            'id':       'MISSING_CSP',
            'risk':     'HIGH',
            'name':     'Missing Content Security Policy (CSP)',
            'location': 'HTTP Response Headers -> Content-Security-Policy',
            'evidence': 'Content-Security-Policy: NOT PRESENT',
            'root':     'The web server does not deliver a Content Security Policy header to restrict executable resource sources.',
            'impact':   'Eliminates second-line browser defenses against Cross-Site Scripting (XSS), malicious script injection, and clickjacking attacks.',
            'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N | Score: 8.8',
            'fix':      "Deploy a restrictive CSP header specifying trusted origins:\n"
                        "Nginx: add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\" always;\n"
                        "Apache: Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\"",
            'ref':      'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
            'poc':      False,
        }
    issues = []
    csp_l = csp.lower()
    if "'unsafe-inline'" in csp_l:
        issues.append("'unsafe-inline' directive permits arbitrary inline JavaScript execution")
    if "'unsafe-eval'" in csp_l:
        issues.append("'unsafe-eval' directive permits dynamic string-to-code execution")
    if 'data:' in csp_l:
        issues.append("'data:' URI scheme allows arbitrary base64 payload injection")
    if issues:
        return {
            'id':       'WEAK_CSP',
            'risk':     'MEDIUM',
            'name':     'Permissive Content Security Policy Directives',
            'location': 'HTTP Response Headers -> Content-Security-Policy',
            'evidence': ' | '.join(issues),
            'root':     f'Configured CSP contains insecure exceptions allowing unverified code execution: {csp[:90]}...',
            'impact':   'Allows script injection payloads to bypass CSP filters if an injection point exists in the application.',
            'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:M/I:M/A:N | Score: 6.1',
            'fix':      "Remove 'unsafe-inline' and 'unsafe-eval'. Migrate to cryptographic nonces or hashes (e.g., 'nonce-random123').",
            'ref':      'https://csp-evaluator.withgoogle.com/',
            'poc':      False,
        }
    return None

def chk_http_methods(base_url):
    try:
        req = Request(base_url, headers={'User-Agent': UA}, method='OPTIONS')
        resp = urlopen(req, timeout=TIMEOUT)
        allow = resp.info().get('Allow', '') or resp.info().get('Public', '')
        if allow:
            methods = [m.strip().upper() for m in allow.split(',')]
            dangerous = [m for m in methods if m in ['TRACE', 'TRACK', 'PUT', 'DELETE']]
            if 'TRACE' in dangerous or 'TRACK' in dangerous:
                return {
                    'id':       'HTTP_TRACE',
                    'risk':     'HIGH',
                    'name':     'Cross-Site Tracing (HTTP TRACE Method Enabled)',
                    'location': f'Web Server Method Dispatcher -> {allow}',
                    'evidence': f'Allow / Public Header: {allow}',
                    'root':     'The web server enables HTTP TRACE / TRACK methods, which reflect request headers back in the response body.',
                    'impact':   'Enables Cross-Site Tracing (XST) attacks. An attacker executing XSS can bypass HttpOnly cookie defenses by issuing a TRACE request and reading the reflected cookie string.',
                    'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N | Score: 6.5',
                    'fix':      "Disable TRACE and TRACK methods on the web server:\n"
                                "Apache: TraceEnable off\n"
                                "Nginx:  if ($request_method ~ ^(TRACE|TRACK)$) { return 405; }",
                    'ref':      'https://owasp.org/www-community/attacks/Cross_Site_Tracing',
                    'poc':      False,
                }
            elif dangerous:
                return {
                    'id':       'DANGEROUS_METHODS',
                    'risk':     'MEDIUM',
                    'name':     'Potentially Dangerous HTTP Methods Enabled',
                    'location': f'Web Server Method Dispatcher -> {allow}',
                    'evidence': f'Enabled Methods: {", ".join(dangerous)}',
                    'root':     'The web server allows state-modifying HTTP verbs (PUT, DELETE) on root endpoints.',
                    'impact':   'If permissions or authentication barriers fail, unauthorized users might attempt arbitrary resource modification or deletion.',
                    'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L | Score: 5.3',
                    'fix':      "Restrict HTTP methods to GET, POST, HEAD unless explicitly required:\n"
                                "Nginx: if ($request_method !~ ^(GET|POST|HEAD)$) { return 405; }",
                    'ref':      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods',
                    'poc':      False,
                }
    except Exception:
        pass
    return None

def chk_sensitive_files(base_url):
    findings = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    
    # 1. Check .env file
    try:
        req = Request(f"{origin}/.env", headers={'User-Agent': UA})
        resp = urlopen(req, timeout=TIMEOUT)
        if resp.status == 200:
            content = resp.read(512).decode('utf-8', errors='ignore')
            if '=' in content and any(k in content.upper() for k in ['DB_', 'SECRET', 'PASSWORD', 'API_KEY', 'APP_KEY']):
                findings.append({
                    'id':       'EXPOSED_ENV',
                    'risk':     'CRITICAL',
                    'name':     'Exposed Environment Configuration File (.env)',
                    'location': f'{origin}/.env',
                    'evidence': f'HTTP 200 OK | File contains sensitive environment assignments: {content[:80]}...',
                    'root':     'The .env file is stored directly within the public web document root without server-level access restrictions.',
                    'impact':   'Complete infrastructure compromise. Attackers can read database credentials, private API keys, cryptographic secrets, and internal endpoints.',
                    'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | Score: 10.0',
                    'fix':      "Move .env outside public webroot. Deny access via server config:\n"
                                "Nginx: location ~ /\\.env { deny all; return 404; }\n"
                                "Apache: <Files \".env\"> Require all denied </Files>",
                    'ref':      'https://cwe.mitre.org/data/definitions/552.html',
                    'poc':      False,
                })
    except Exception:
        pass

    # 2. Check .git/HEAD
    try:
        req = Request(f"{origin}/.git/HEAD", headers={'User-Agent': UA})
        resp = urlopen(req, timeout=TIMEOUT)
        if resp.status == 200:
            content = resp.read(128).decode('utf-8', errors='ignore').strip()
            if content.startswith('ref: refs/') or len(content) == 40:
                findings.append({
                    'id':       'EXPOSED_GIT',
                    'risk':     'CRITICAL',
                    'name':     'Exposed Git Repository Root (.git/HEAD)',
                    'location': f'{origin}/.git/HEAD',
                    'evidence': f'HTTP 200 OK | Content: {content}',
                    'root':     'The .git version control repository was deployed to production and remains accessible over HTTP.',
                    'impact':   'Attackers can extract the entire source code repository, commit history, hardcoded credentials, and architectural secrets using tools like git-dumper.',
                    'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | Score: 8.6',
                    'fix':      "Block all requests targeting hidden dotfiles:\n"
                                "Nginx: location ~ /\\.git { deny all; return 404; }\n"
                                "Apache: <DirectoryMatch \"/\\.git\"> Require all denied </DirectoryMatch>",
                    'ref':      'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure',
                    'poc':      False,
                })
    except Exception:
        pass

    # 3. Check robots.txt for sensitive endpoints
    try:
        req = Request(f"{origin}/robots.txt", headers={'User-Agent': UA})
        resp = urlopen(req, timeout=TIMEOUT)
        if resp.status == 200:
            txt = resp.read(2048).decode('utf-8', errors='ignore')
            disallowed = []
            for line in txt.splitlines():
                if line.lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if any(s in path.lower() for s in ['admin', 'api', 'backup', 'secret', 'dashboard', 'internal', 'staging', 'portal']):
                        disallowed.append(path)
            if disallowed:
                findings.append({
                    'id':       'ROBOTS_DISCLOSURE',
                    'risk':     'LOW',
                    'name':     'Sensitive Internal Paths Disclosed in robots.txt',
                    'location': f'{origin}/robots.txt',
                    'evidence': f'Disclosed Paths: {", ".join(disallowed[:5])}',
                    'root':     'Web administrators listed private administration or internal API endpoints inside public robots.txt files.',
                    'impact':   'Facilitates target reconnaissance. Attackers identify hidden admin panels, staging servers, and internal entry points without brute-forcing.',
                    'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | Score: 3.7',
                    'fix':      "Do not rely on robots.txt for security. Protect private endpoints with server-level authentication and network firewall ACLs.",
                    'ref':      'https://developer.mozilla.org/en-US/docs/Glossary/Robots.txt',
                    'poc':      False,
                })
    except Exception:
        pass

    return findings

def chk_mime_sniffing(hdrs):
    xcto = hdrs.get('X-Content-Type-Options', '')
    if 'nosniff' not in xcto.lower():
        return {
            'id':       'MIME_SNIFFING',
            'risk':     'MEDIUM',
            'name':     'Missing X-Content-Type-Options (MIME Sniffing)',
            'location': 'HTTP Response Headers -> X-Content-Type-Options',
            'evidence': f'X-Content-Type-Options: {xcto or "NOT PRESENT"}',
            'root':     'The server fails to instruct user agents to honor the declared Content-Type header without sniffing.',
            'impact':   'Permits MIME-confusion attacks. Browsers may execute benign text or user-uploaded media files as HTML/JavaScript if script elements are detected.',
            'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:M/I:M/A:N | Score: 6.1',
            'fix':      "Add nosniff header across all responses:\n"
                        "Nginx:  add_header X-Content-Type-Options \"nosniff\" always;\n"
                        "Apache: Header always set X-Content-Type-Options \"nosniff\"",
            'ref':      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
            'poc':      False,
        }
    return None

def chk_referrer_policy(hdrs):
    rp = hdrs.get('Referrer-Policy')
    if rp is None:
        return {
            'id':       'MISSING_REFERRER',
            'risk':     'LOW',
            'name':     'Missing Referrer-Policy',
            'location': 'HTTP Response Headers -> Referrer-Policy',
            'evidence': 'Referrer-Policy: NOT PRESENT',
            'root':     'The application does not declare how much referrer information should be transmitted on outbound requests.',
            'impact':   'Full target URLs (which may contain sensitive query tokens, IDs, or reset keys) may leak to external third-party CDN or analytics servers.',
            'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N | Score: 4.3',
            'fix':      "Enforce strict-origin-when-cross-origin:\n"
                        "Nginx:  add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
                        "Apache: Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
            'ref':      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
            'poc':      False,
        }
    return None

def chk_permissions_policy(hdrs):
    pp = hdrs.get('Permissions-Policy') or hdrs.get('Feature-Policy')
    if pp is None:
        return {
            'id':       'MISSING_PERMISSIONS',
            'risk':     'LOW',
            'name':     'Missing Permissions-Policy',
            'location': 'HTTP Response Headers -> Permissions-Policy',
            'evidence': 'Permissions-Policy: NOT PRESENT',
            'root':     'No browser hardware feature controls (camera, microphone, geolocation) are defined for iframe contexts.',
            'impact':   'Embedded third-party scripts or frames can access sensitive browser hardware APIs within the origin context.',
            'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N | Score: 4.7',
            'fix':      "Define a restrictive Permissions-Policy header:\n"
                        "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;",
            'ref':      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy',
            'poc':      False,
        }
    return None

def chk_server_disclosure(hdrs):
    disclosed = []
    srv = hdrs.get('Server', '')
    if srv and any(c.isdigit() for c in srv):
        disclosed.append(f"Server: {srv}")
    xpb = hdrs.get('X-Powered-By', '')
    if xpb:
        disclosed.append(f"X-Powered-By: {xpb}")
    if disclosed:
        return {
            'id':       'SERVER_DISCLOSURE',
            'risk':     'LOW',
            'name':     'Web Server & Technology Banner Disclosure',
            'location': 'HTTP Response Headers -> Server / X-Powered-By',
            'evidence': ' | '.join(disclosed),
            'root':     'The web server broadcasts granular software names and version numbers in HTTP responses.',
            'impact':   'Aids threat actors during technology profiling. Specific software releases can be mapped to public CVE databases for targeted exploit execution.',
            'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | Score: 5.3',
            'fix':      "Disable banner emission in web server configs:\n"
                        "Nginx:  server_tokens off;\n"
                        "Apache: ServerTokens Prod; ServerSignature Off;\n"
                        "Express: app.disable('x-powered-by');",
            'ref':      'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server',
            'poc':      False,
        }
    return None

def chk_ssl_certificate(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get('notAfter')
                if not_after:
                    exp_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                    now_utc = datetime.now(timezone.utc)
                    days_left = (exp_date - now_utc).days
                    if days_left < 14:
                        sev = 'CRITICAL' if days_left <= 0 else 'HIGH'
                        return {
                            'id':       'SSL_EXPIRING',
                            'risk':     sev,
                            'name':     'SSL/TLS Certificate Expired or Expiring Soon',
                            'location': f'{host}:443 (TLS Handshake)',
                            'evidence': f'Certificate Expiry: {not_after} ({days_left} days remaining)',
                            'root':     'The SSL/TLS certificate is either expired or within the critical 14-day renewal threshold.',
                            'impact':   'Expired certificates trigger browser security warnings, breaking encrypted communications and undermining client trust.',
                            'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N | Score: 7.5',
                            'fix':      'Renew SSL/TLS certificate immediately through Certbot or your Certificate Authority.',
                            'ref':      'https://letsencrypt.org/',
                            'poc':      False,
                        }
    except ssl.SSLCertVerificationError as e:
        return {
            'id':       'SSL_INVALID',
            'risk':     'HIGH',
            'name':     'Invalid or Self-Signed SSL/TLS Certificate',
            'location': f'{host}:443 (TLS Handshake)',
            'evidence': f'SSL Verification Error: {str(e)}',
            'root':     'The TLS certificate chain cannot be verified by trusted root authorities.',
            'impact':   'Users receive invalid certificate warnings; active adversaries on public Wi-Fi can easily intercept traffic using forged certificates.',
            'cvss':     'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N | Score: 7.4',
            'fix':      'Install a valid certificate issued by a recognized Certificate Authority (e.g., Let\'s Encrypt).',
            'ref':      'https://letsencrypt.org/',
            'poc':      False,
        }
    except Exception:
        pass
    return None

# ═══════════════════════════════════════════════════
#  SCAN ENGINE WORKER
# ═══════════════════════════════════════════════════

def scan_target(raw_url):
    url = raw_url.strip()
    if not url.startswith('http'):
        url = 'https://' + url

    parsed = urlparse(url)
    host = parsed.netloc.split(':')[0]
    target_ip = get_target_ip(host)
    
    findings = []
    t_start = datetime.now()

    try:
        req = Request(url, headers={'User-Agent': UA})
        resp = urlopen(req, timeout=TIMEOUT)
        hdrs = resp.info()
        status_code = resp.status
        final_url = resp.geturl()
    except HTTPError as e:
        hdrs = e.headers
        status_code = e.code
        final_url = url
    except Exception as e:
        return raw_url, url, target_ip, 0, 0, [], str(e), {}

    latency_ms = int((datetime.now() - t_start).total_seconds() * 1000)

    # 1. Header Assessments
    checks = [
        chk_clickjacking(hdrs, final_url),
        chk_cors_wildcard(hdrs),
        chk_cookies(hdrs),
        chk_hsts(hdrs, final_url),
        chk_csp(hdrs),
        chk_mime_sniffing(hdrs),
        chk_referrer_policy(hdrs),
        chk_permissions_policy(hdrs),
        chk_server_disclosure(hdrs)
    ]
    for c in checks:
        if c: findings.append(c)

    # 2. CORS Reflection
    c_ref = chk_cors_reflection(final_url)
    if c_ref: findings.append(c_ref)

    # 3. HTTP Methods
    c_meth = chk_http_methods(final_url)
    if c_meth: findings.append(c_meth)

    # 4. Sensitive Files
    c_files = chk_sensitive_files(final_url)
    findings.extend(c_files)

    # 5. SSL/TLS Certificate
    if final_url.startswith('https://'):
        c_ssl = chk_ssl_certificate(host)
        if c_ssl: findings.append(c_ssl)

    header_dict = dict(hdrs)
    return raw_url, final_url, target_ip, status_code, latency_ms, findings, None, header_dict

# ═══════════════════════════════════════════════════
#  SCORING UTILITIES
# ═══════════════════════════════════════════════════

def calc_score(findings):
    return sum(RISK_S.get(f['risk'], 0) for f in findings)

def get_overall_risk(score):
    if score >= 12: return 'CRITICAL', R
    if score >= 7:  return 'HIGH', R
    if score >= 3:  return 'MEDIUM', Y
    if score >= 1:  return 'LOW', C
    return 'SECURE', G

# ═══════════════════════════════════════════════════
#  TERMINAL PRINTER
# ═══════════════════════════════════════════════════

def print_banner():
    print(BANNER)

def print_target_result(idx, total, raw_url, final_url, ip, status, latency, findings, err):
    div = "=" * 62
    sub = "-" * 62
    print(f"\n{C}{BO}{div}{RS}")
    print(f"{W}{BO}[{idx}/{total}] TARGET:{RS} {C}{BO}{raw_url}{RS}")
    print(f"{C}{BO}{div}{RS}")
    
    if err:
        print(f"  {R}[ERROR]{RS} Unable to connect to host: {err}\n")
        return

    score = calc_score(findings)
    risk_label, risk_color = get_overall_risk(score)

    print(f"  {DM}Address :{RS} {W}{ip}{RS} | {DM}Status :{RS} {G}{status} OK{RS} | {DM}Latency :{RS} {latency}ms")
    print(f"  {DM}Endpoint:{RS} {final_url}")
    print(f"  {DM}Posture :{RS} {risk_color}{BO}{risk_label}{RS} (Score: {score}) | {W}{len(findings)} Total Finding(s){RS}")
    print(f"{DM}{sub}{RS}")

    if not findings:
        print(f"  {G}{BO}[PASS]{RS} No critical misconfigurations detected on checked endpoints.\n")
        return

    for i, f in enumerate(findings, 1):
        rc = RISK_C.get(f['risk'], C)
        print(f"  {BO}#{i} {rc}[{f['risk']}]{RS} {W}{BO}{f['name']}{RS}")
        print(f"     {DM}Location   :{RS} {f['location']}")
        print(f"     {DM}Evidence   :{RS} {f['evidence']}")
        print(f"     {DM}Root Cause :{RS} {f['root'][:100]}...")
        print(f"     {DM}Remediation:{RS} {G}{f['fix'].splitlines()[0]}{RS}")
        print()

# ═══════════════════════════════════════════════════
#  INTERACTIVE HTML POC GENERATOR
# ═══════════════════════════════════════════════════

def generate_poc_report(raw_url, final_url, ip, status, latency, findings, headers):
    safe_name = raw_url.replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_')
    report_file = f"{safe_name}_cjf_report.html"

    score = calc_score(findings)
    risk_label, _ = get_overall_risk(score)
    theme_color = {'CRITICAL': '#e53e3e', 'HIGH': '#dd6b20', 'MEDIUM': '#d69e2e', 'LOW': '#3182ce', 'SECURE': '#38a169'}.get(risk_label, '#718096')

    # Build Finding Accordions
    findings_html = ""
    for i, f in enumerate(findings, 1):
        badge_color = {'CRITICAL': '#e53e3e', 'HIGH': '#dd6b20', 'MEDIUM': '#d69e2e', 'LOW': '#3182ce'}.get(f['risk'], '#718096')
        fix_code = f['fix'].replace('\n', '<br>')
        findings_html += f"""
        <div class="card mb-4">
            <div class="card-header" style="border-left: 5px solid {badge_color};" onclick="toggleCard({i})">
                <span class="badge" style="background: {badge_color};">{f['risk']}</span>
                <strong class="title">#{i} {f['name']}</strong>
                <span class="location-tag">{f['location'][:45]}...</span>
            </div>
            <div class="card-body" id="card-{i}">
                <div class="row"><div class="label">Component Location</div><div class="value code">{f['location']}</div></div>
                <div class="row"><div class="label">Observed Evidence</div><div class="value code-evidence">{f['evidence']}</div></div>
                <div class="row"><div class="label">Root Cause</div><div class="value">{f['root']}</div></div>
                <div class="row"><div class="label">Real-World Impact</div><div class="value alert-impact">{f['impact']}</div></div>
                <div class="row"><div class="label">CVSS 3.1 Rating</div><div class="value cvss-pill">{f['cvss']}</div></div>
                <div class="row"><div class="label">Remediation Guidelines</div><div class="value code-fix">{fix_code}</div></div>
                <div class="row"><div class="label">Technical Reference</div><div class="value"><a href="{f['ref']}" target="_blank">{f['ref']}</a></div></div>
            </div>
        </div>
        """

    # Build Header Matrix
    header_rows = ""
    audited = ['X-Frame-Options', 'Content-Security-Policy', 'Strict-Transport-Security', 'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy', 'Access-Control-Allow-Origin', 'Set-Cookie', 'Server', 'X-Powered-By']
    for h in audited:
        val = headers.get(h)
        if val:
            header_rows += f"<tr><td><strong>{h}</strong></td><td class='present'>{val}</td><td class='badge-pass'>PASS</td></tr>"
        else:
            header_rows += f"<tr><td><strong>{h}</strong></td><td class='missing'>NOT PRESENT</td><td class='badge-fail'>MISSING</td></tr>"

    # Clickjacking PoC Tab
    cj_vuln = any(f['id'] == 'CLICKJACKING' for f in findings)
    cj_tab_btn = '<button class="tab-btn" onclick="openTab(\'tab-poc\')">Live Clickjacking PoC</button>' if cj_vuln else ''
    
    cj_tab_content = f"""
    <div id="tab-poc" class="tab-content">
        <div class="poc-container">
            <div class="poc-header">
                <h3>Live Clickjacking (UI Redressing) Simulator</h3>
                <p>This proof-of-concept tests whether <strong>{final_url}</strong> permits cross-origin framing and simulates an active UI redressing attack vector.</p>
                <div class="server-notice">
                    <strong>💡 Browser Sandbox Notice:</strong> If modern browsers refuse to load this page when opened as a local file (<code>file:///</code>), 
                    run <code>python Clickjacking_Finder.py --serve</code> in this directory to load with a standard HTTP origin.
                </div>
            </div>

            <div class="poc-controls">
                <button class="btn" onclick="reloadIframe()">Reload Frame</button>
                <button class="btn" onclick="window.open('{final_url}', '_blank')">Open Target In New Tab</button>
                <div class="slider-box">
                    <span>Overlay Opacity:</span>
                    <input type="range" id="opacitySlider" min="0" max="100" value="25" oninput="adjustOpacity(this.value)">
                    <span id="opacityVal">25%</span>
                </div>
            </div>

            <div class="simulator-stage">
                <!-- Target Layer (Underneath) -->
                <iframe id="targetFrame" src="{final_url}" class="target-iframe"></iframe>

                <!-- Attacker Decoy Layer (Overlay) -->
                <div id="decoyOverlay" class="decoy-overlay">
                    <div class="decoy-card">
                        <h2>🎁 Verification Required</h2>
                        <p>Click below to verify identity and claim administrative gift token.</p>
                        <button class="decoy-button" onclick="recordClick()">Verify & Claim Prize</button>
                        <div class="decoy-note">(Decoy Button Positioned Over Target Coordinates)</div>
                    </div>
                </div>
            </div>

            <div id="clickAlert" class="click-alert">
                <strong>⚡ Click Registered!</strong> In a real-world scenario, your click would penetrate the transparent layer and trigger the underlying action on <strong>{final_url}</strong> without your consent.
            </div>
        </div>
    </div>
    """ if cj_vuln else '<div id="tab-poc" class="tab-content"><p>Target is not vulnerable to clickjacking.</p></div>'

    # Build Markdown Bug Report
    md_report = f"# Vulnerability Assessment Report - {final_url}\n\n"
    md_report += f"- Target Host: {final_url}\n"
    md_report += f"- IP Address : {ip}\n"
    md_report += f"- Scan Time  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    md_report += f"- Overall Posture: {risk_label} (Score: {score})\n\n---\n\n"
    for f in findings:
        md_report += f"## [{f['risk']}] {f['name']}\n"
        md_report += f"- Location: {f['location']}\n"
        md_report += f"- Evidence: {f['evidence']}\n"
        md_report += f"- CVSS 3.1: {f['cvss']}\n"
        md_report += f"- Root Cause: {f['root']}\n"
        md_report += f"- Real-World Impact: {f['impact']}\n"
        md_report += f"- Remediation:\n```\n{f['fix']}\n```\n\n"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CJF Assessment Report | {raw_url}</title>
<style>
    :root {{
        --bg-primary: #f8fafc;
        --bg-surface: #ffffff;
        --border-color: #e2e8f0;
        --text-primary: #1a202c;
        --text-muted: #718096;
        --accent: #3182ce;
        --danger: #e53e3e;
        --warning: #dd6b20;
        --success: #38a169;
    }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
    body {{ background: var(--bg-primary); color: var(--text-primary); line-height: 1.6; padding: 24px; }}
    .container {{ max-width: 1100px; margin: 0 auto; }}

    /* Header */
    .header-bar {{ background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 8px; padding: 24px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
    .header-title {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }}
    .header-title h1 {{ font-size: 20px; font-weight: 700; color: #2d3748; }}
    .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-top: 16px; }}
    .meta-item {{ background: #f7fafc; padding: 12px; border-radius: 6px; border: 1px solid #edf2f7; }}
    .meta-item .label {{ font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; }}
    .meta-item .val {{ font-size: 15px; font-weight: 700; margin-top: 4px; }}

    /* Tabs */
    .tab-nav {{ display: flex; gap: 8px; margin-bottom: 20px; border-bottom: 2px solid var(--border-color); }}
    .tab-btn {{ background: none; border: none; padding: 12px 20px; font-size: 14px; font-weight: 600; color: var(--text-muted); cursor: pointer; border-bottom: 2px solid transparent; margin-bottom: -2px; }}
    .tab-btn.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
    .tab-content {{ display: none; }}
    .tab-content.active {{ display: block; }}

    /* Findings Cards */
    .card {{ background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 8px; margin-bottom: 16px; overflow: hidden; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }}
    .card-header {{ padding: 16px 20px; cursor: pointer; display: flex; align-items: center; gap: 12px; background: #ffffff; user-select: none; }}
    .card-header:hover {{ background: #f7fafc; }}
    .badge {{ color: white; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }}
    .location-tag {{ margin-left: auto; font-size: 12px; color: var(--text-muted); font-family: monospace; }}
    .card-body {{ padding: 20px; border-top: 1px solid var(--border-color); background: #fafafa; }}
    .row {{ margin-bottom: 12px; }}
    .row .label {{ font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700; margin-bottom: 4px; }}
    .row .value {{ font-size: 14px; }}
    .code {{ font-family: Consolas, monospace; background: #edf2f7; padding: 4px 8px; border-radius: 4px; font-size: 13px; display: inline-block; }}
    .code-evidence {{ font-family: Consolas, monospace; background: #fff5f5; color: #c53030; padding: 8px; border-radius: 4px; border: 1px solid #feb2b2; font-size: 13px; word-break: break-all; }}
    .code-fix {{ font-family: Consolas, monospace; background: #f0fff4; color: #22543d; padding: 10px; border-radius: 4px; border: 1px solid #9ae6b4; font-size: 13px; white-space: pre-wrap; }}
    .alert-impact {{ background: #fffaf0; border-left: 4px solid var(--warning); padding: 8px 12px; color: #744210; }}
    .cvss-pill {{ font-family: Consolas, monospace; font-size: 12px; color: #4a5568; }}

    /* Table */
    .table-container {{ background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden; }}
    table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; }}
    th {{ background: #f7fafc; padding: 12px 16px; border-bottom: 1px solid var(--border-color); font-weight: 700; color: #4a5568; }}
    td {{ padding: 12px 16px; border-bottom: 1px solid #edf2f7; }}
    td.present {{ color: var(--success); font-family: monospace; word-break: break-all; }}
    td.missing {{ color: var(--danger); font-style: italic; }}
    .badge-pass {{ color: var(--success); font-weight: 700; }}
    .badge-fail {{ color: var(--danger); font-weight: 700; }}

    /* PoC Simulator */
    .poc-container {{ background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 8px; padding: 24px; }}
    .server-notice {{ background: #ebf8ff; border: 1px solid #bee3f8; color: #2b6cb0; padding: 12px; border-radius: 6px; font-size: 13px; margin: 12px 0 20px 0; }}
    .poc-controls {{ display: flex; align-items: center; gap: 16px; margin-bottom: 16px; flex-wrap: wrap; }}
    .btn {{ background: var(--accent); color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer; }}
    .btn:hover {{ opacity: 0.9; }}
    .slider-box {{ display: flex; align-items: center; gap: 8px; margin-left: auto; font-size: 13px; }}
    .simulator-stage {{ position: relative; width: 100%; height: 500px; border: 2px solid #cbd5e0; border-radius: 8px; overflow: hidden; background: #ffffff; }}
    .target-iframe {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%; border: none; z-index: 1; }}
    .decoy-overlay {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%; background: rgba(240, 244, 248, 0.25); z-index: 2; display: flex; align-items: center; justify-content: center; }}
    .decoy-card {{ background: rgba(255, 255, 255, 0.95); border: 2px solid #cbd5e0; border-radius: 12px; padding: 24px 36px; text-align: center; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
    .decoy-button {{ background: #319795; color: white; border: none; padding: 12px 28px; font-size: 15px; font-weight: 700; border-radius: 6px; cursor: pointer; margin-top: 16px; }}
    .decoy-note {{ font-size: 11px; color: var(--text-muted); margin-top: 8px; }}
    .click-alert {{ display: none; margin-top: 16px; padding: 12px 16px; background: #feebc8; border-left: 4px solid var(--warning); color: #7b341e; border-radius: 4px; font-size: 13px; }}

    /* Markdown Export */
    .report-box {{ width: 100%; height: 400px; background: #1a202c; color: #e2e8f0; font-family: Consolas, monospace; font-size: 12px; padding: 16px; border-radius: 6px; border: none; resize: vertical; }}
</style>
</head>
<body>
<div class="container">
    <div class="header-bar">
        <div class="header-title">
            <h1>Web Security & Clickjacking Assessment</h1>
            <span class="badge" style="background: {theme_color}; font-size: 13px; padding: 6px 14px;">{risk_label} POSTURE</span>
        </div>
        <p style="color: var(--text-muted); font-size: 14px;">Target Audit: <strong>{final_url}</strong></p>
        <div class="meta-grid">
            <div class="meta-item"><div class="label">Host IP</div><div class="val">{ip}</div></div>
            <div class="meta-item"><div class="label">Risk Score</div><div class="val" style="color: {theme_color};">{score}</div></div>
            <div class="meta-item"><div class="label">Total Findings</div><div class="val">{len(findings)} Issue(s)</div></div>
            <div class="meta-item"><div class="label">Latency</div><div class="val">{latency} ms</div></div>
        </div>
    </div>

    <div class="tab-nav">
        <button class="tab-btn active" onclick="openTab('tab-findings')">Vulnerability Findings ({len(findings)})</button>
        <button class="tab-btn" onclick="openTab('tab-headers')">HTTP Headers Audit</button>
        {cj_tab_btn}
        <button class="tab-btn" onclick="openTab('tab-report')">Export Bug Bounty Report</button>
    </div>

    <!-- Findings Tab -->
    <div id="tab-findings" class="tab-content active">
        {findings_html if findings else '<div class="card"><div class="card-body">No vulnerabilities detected. All verified checks passed.</div></div>'}
    </div>

    <!-- Headers Tab -->
    <div id="tab-headers" class="tab-content">
        <div class="table-container">
            <table>
                <thead>
                    <tr><th>Header Name</th><th>Observed Value</th><th>Compliance</th></tr>
                </thead>
                <tbody>
                    {header_rows}
                </tbody>
            </table>
        </div>
    </div>

    <!-- PoC Tab -->
    {cj_tab_content}

    <!-- Report Tab -->
    <div id="tab-report" class="tab-content">
        <div style="margin-bottom: 12px;">
            <button class="btn" onclick="copyReport()">Copy Report to Clipboard</button>
        </div>
        <textarea id="rawReport" class="report-box" readonly>{md_report}</textarea>
    </div>
</div>

<script>
    function openTab(id) {{
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        event.target.classList.add('active');
        document.getElementById(id).classList.add('active');
    }}
    function toggleCard(id) {{
        const b = document.getElementById('card-' + id);
        b.style.display = b.style.display === 'none' ? 'block' : 'none';
    }}
    function adjustOpacity(val) {{
        document.getElementById('opacityVal').innerText = val + '%';
        document.getElementById('decoyOverlay').style.background = 'rgba(240, 244, 248, ' + (val/100) + ')';
    }}
    function recordClick() {{
        document.getElementById('clickAlert').style.display = 'block';
    }}
    function reloadIframe() {{
        const f = document.getElementById('targetFrame');
        if (f) f.src = f.src;
    }}
    function copyReport() {{
        const t = document.getElementById('rawReport');
        t.select();
        document.execCommand('copy');
        alert('Bug Bounty Report copied to clipboard!');
    }}
</script>
</body>
</html>
"""
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(html)
    return report_file

# ═══════════════════════════════════════════════════
#  BUILT-IN PREVIEW WEB SERVER
# ═══════════════════════════════════════════════════

def serve_preview(port=8080):
    print(f"\n{C}{BO}[*] Launching local HTTP preview server on port {port}...{RS}")
    print(f"{G}[*] Serving at http://127.0.0.1:{port}/{RS}")
    print(f"{DM}[*] Press Ctrl+C to terminate the local preview server.{RS}\n")
    try:
        webbrowser.open(f"http://127.0.0.1:{port}/")
        server = HTTPServer(('127.0.0.1', port), SimpleHTTPRequestHandler)
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{Y}[*] Preview server stopped.{RS}")
    except Exception as e:
        print(f"{R}[!] Unable to launch preview server: {e}{RS}")

# ═══════════════════════════════════════════════════
#  FILE READER & CLI ENTRY
# ═══════════════════════════════════════════════════

def read_target_list(path):
    with open(path, 'rb') as f:
        raw = f.read()
    if raw.startswith(b'\xff\xfe') or raw.startswith(b'\xfe\xff'):
        content = raw.decode('utf-16')
    elif raw.startswith(b'\xef\xbb\xbf'):
        content = raw.decode('utf-8-sig')
    else:
        content = raw.decode('utf-8', errors='ignore')
    return [l.strip().replace('\x00', '') for l in content.splitlines() if l.strip() and not l.strip().startswith('#')]

def main():
    print_banner()

    if len(argv) >= 2 and argv[1] == '--serve':
        port = int(argv[2]) if len(argv) > 2 else 8080
        serve_preview(port)
        exit(0)

    if len(argv) < 2:
        print(f"{Y}[*] Usage:{RS}")
        print(f"  Standard Audit : python Clickjacking_Finder.py <targets_file> [threads]")
        print(f"  Launch Preview : python Clickjacking_Finder.py --serve [port]\n")
        print(f"  Example: python Clickjacking_Finder.py targets.txt 10")
        print(f"  Example: python Clickjacking_Finder.py --serve 8080\n")
        exit(0)

    target_file = argv[1]
    threads = int(argv[2]) if len(argv) > 2 else THREADS

    try:
        targets = read_target_list(target_file)
    except Exception as e:
        print(f"{R}[!] Unable to read targets file: {e}{RS}\n")
        exit(0)

    total = len(targets)
    print(f"{C}[*]{RS} Loaded Targets: {BO}{total}{RS} | Worker Threads: {BO}{threads}{RS} | Timeout: {BO}{TIMEOUT}s{RS}")
    print(f"{C}[*]{RS} Assessment Scope: Clickjacking, CORS, Headers, Sensitive Files, SSL/TLS, Methods\n")

    results = {}
    completed = [0]
    lock = __import__('threading').Lock()

    def worker(t):
        res = scan_target(t)
        with lock:
            completed[0] += 1
            pct = int((completed[0] / total) * 20)
            bar = "#" * pct + "-" * (20 - pct)
            print(f"\r  [{bar}] {completed[0]}/{total} Completed", end='', flush=True)
        return res

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(worker, t): t for t in targets}
        for fut in as_completed(futures):
            raw, final, ip, status, lat, findings, err, hdrs = fut.result()
            results[raw] = (final, ip, status, lat, findings, err, hdrs)

    print("\n")

    # Render sorted results
    sorted_res = sorted(results.items(), key=lambda x: -calc_score(x[1][4]))
    summary_data = []

    for idx, (raw, (final, ip, status, lat, findings, err, hdrs)) in enumerate(sorted_res, 1):
        print_target_result(idx, total, raw, final, ip, status, lat, findings, err)
        if not err and findings:
            report_name = generate_poc_report(raw, final, ip, status, lat, findings, hdrs)
            print(f"  {Y}[>] Interactive PoC & Report Saved:{RS} {BO}{report_name}{RS}\n")
            summary_data.append((raw, len(findings), calc_score(findings)))
        elif not err:
            summary_data.append((raw, 0, 0))

    # ── FINAL AUDIT SUMMARY TABLE ──
    div = "=" * 62
    print(f"{C}{BO}{div}{RS}")
    print(f"{C}{BO}  FINAL AUDIT SUMMARY MATRIX{RS}")
    print(f"{C}{BO}{div}{RS}")
    print(f"  {'TARGET':<35} | {'ISSUES':<8} | {'RISK SCORE':<10}")
    print(f"  {'-'*35}-+-{'-'*8}-+-{'-'*10}")
    for target, count, score in summary_data:
        rl, rc = get_overall_risk(score)
        print(f"  {target:<35} | {count:<8} | {rc}{score} ({rl}){RS}")
    print(f"{C}{BO}{div}{RS}\n")
    print(f"{G}[*] Tip: Run `python Clickjacking_Finder.py --serve` to view interactive PoCs in your browser.{RS}\n")

if __name__ == '__main__':
    main()
