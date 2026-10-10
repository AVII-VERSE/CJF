# Author: AVII-VERSE
# CJF - Clickjacking Finder v1.0 | Advanced Multi-Threaded Security Scanner

import os, sys
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from sys import argv, exit

if os.name == 'nt':
    os.system('')

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

__author__  = 'AVII-VERSE'
__version__ = '1.0'

# ── COLORS ──────────────────────────────────────────
C  = '\033[96m'   # cyan
G  = '\033[92m'   # green
Y  = '\033[93m'   # yellow
R  = '\033[91m'   # red
M  = '\033[95m'   # magenta
B  = '\033[94m'   # blue
BO = '\033[1m'    # bold
DM = '\033[2m'    # dim
RS = '\033[0m'    # reset

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
|  {B}[*] Mode    : {G}Advanced Multi-Threaded Scanner{M}        |
|  {B}[*] Checks  : {G}12 Vulnerability Classes{M}               |
+====================================================+{RS}
"""

THREADS = 5
TIMEOUT = 10
UA = 'Mozilla/5.0 (CJF-Scanner/4.0; Security-Audit)'

# ═══════════════════════════════════════════════════
#  INDIVIDUAL CHECK FUNCTIONS
# ═══════════════════════════════════════════════════

def chk_clickjacking(hdrs):
    xfo = hdrs.get('X-Frame-Options')
    csp = hdrs.get('Content-Security-Policy', '')
    fa  = 'frame-ancestors' in csp.lower() if csp else False
    if xfo is None and not fa:
        return {
            'id':       'CLICKJACKING',
            'risk':     'HIGH',
            'name':     'Clickjacking',
            'evidence': f'X-Frame-Options: NOT PRESENT | CSP frame-ancestors: NOT SET',
            'root':     'The server sends no framing policy. Any website can embed this page inside an <iframe> tag without restriction.',
            'impact':   'Attacker embeds this site transparently behind a fake UI. Victim clicks what they think is a prize button but actually submits a form, deletes an account, or transfers funds on the real hidden site.',
            'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | Score: 6.1',
            'fix':      'Add: Content-Security-Policy: frame-ancestors \'none\'\n              OR: X-Frame-Options: DENY',
            'ref':      'https://owasp.org/www-community/attacks/Clickjacking',
            'poc':      True,
        }
    return None


def chk_cors(url, hdrs):
    # Send a request with attacker Origin and check ACAO response
    acao = hdrs.get('Access-Control-Allow-Origin', '')
    acac = hdrs.get('Access-Control-Allow-Credentials', '')
    if acao == '*':
        sev = 'HIGH' if 'true' in acac.lower() else 'MEDIUM'
        return {
            'id':       'CORS_WILDCARD',
            'risk':     sev,
            'name':     'CORS Wildcard Misconfiguration',
            'evidence': f'Access-Control-Allow-Origin: {acao} | Allow-Credentials: {acac or "not set"}',
            'root':     'Server reflects Access-Control-Allow-Origin: * allowing any origin to read responses. When combined with credentials=true this becomes critical.',
            'impact':   'Attacker can make cross-origin AJAX requests from evil.com and read authenticated API responses, stealing session data or private user information.',
            'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N | Score: 8.2',
            'fix':      'Whitelist specific origins: Access-Control-Allow-Origin: https://yourdomain.com\n              Never use * with Allow-Credentials: true',
            'ref':      'https://portswigger.net/web-security/cors',
            'poc':      False,
        }
    return None


def chk_cors_reflect(url):
    # Test if server reflects arbitrary Origin (more dangerous than wildcard)
    try:
        req = Request(url, headers={
            'User-Agent': UA,
            'Origin': 'https://evil-attacker.com'
        })
        resp   = urlopen(req, timeout=TIMEOUT)
        acao   = resp.info().get('Access-Control-Allow-Origin', '')
        acac   = resp.info().get('Access-Control-Allow-Credentials', '')
        if 'evil-attacker.com' in acao:
            return {
                'id':       'CORS_REFLECT',
                'risk':     'CRITICAL',
                'name':     'CORS Origin Reflection (Critical)',
                'evidence': f'Sent Origin: https://evil-attacker.com | Got back ACAO: {acao} | Credentials: {acac}',
                'root':     'Server reflects any Origin header back in Access-Control-Allow-Origin. Server trusts whatever origin the request claims.',
                'impact':   'Complete bypass of same-origin policy. Attacker can read any authenticated API response from the victim\'s session — account data, tokens, private messages.',
                'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N | Score: 9.3',
                'fix':      'Validate Origin against a strict allowlist. Never reflect arbitrary Origin values.',
                'ref':      'https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack',
                'poc':      False,
            }
    except Exception:
        pass
    return None


def chk_cookies(hdrs):
    raw = hdrs.get('Set-Cookie')
    if not raw:
        return None
    issues = []
    cookies = raw if isinstance(raw, list) else [raw]
    for ck in cookies:
        cku = ck.lower()
        name = ck.split('=')[0].strip()
        if 'secure' not in cku:
            issues.append(f'Cookie "{name}": missing Secure flag (sent over HTTP)')
        if 'httponly' not in cku:
            issues.append(f'Cookie "{name}": missing HttpOnly flag (readable by JS/XSS)')
        if 'samesite' not in cku:
            issues.append(f'Cookie "{name}": missing SameSite flag (CSRF risk)')
    if issues:
        return {
            'id':       'COOKIES',
            'risk':     'HIGH',
            'name':     'Insecure Cookie Configuration',
            'evidence': ' | '.join(issues[:3]),
            'root':     'Session/auth cookies are set without security flags, making them accessible to JavaScript (XSS), sent over plain HTTP, or usable in cross-site request forgery attacks.',
            'impact':   'Missing HttpOnly: XSS can steal session cookie via document.cookie. Missing Secure: cookie sent in HTTP MITM scenarios. Missing SameSite: CSRF attacks possible.',
            'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N | Score: 7.1',
            'fix':      'Set-Cookie: session=xyz; Secure; HttpOnly; SameSite=Strict',
            'ref':      'https://owasp.org/www-community/controls/SecureCookieAttribute',
            'poc':      False,
        }
    return None


def chk_hsts(hdrs, url):
    hsts = hdrs.get('Strict-Transport-Security')
    is_https = url.startswith('https://')
    if hsts is None and is_https:
        return {
            'id':       'HSTS_MISSING',
            'risk':     'HIGH',
            'name':     'Missing HSTS (HTTP Strict Transport Security)',
            'evidence': 'Strict-Transport-Security: NOT PRESENT on HTTPS site',
            'root':     'Site serves HTTPS but does not tell browsers to always use HTTPS. Users who visit via HTTP are never upgraded automatically.',
            'impact':   'SSL stripping attack: attacker intercepts HTTP request before redirect, downgrades to plain HTTP, reads/modifies traffic. Works on public WiFi.',
            'cvss':     'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N | Score: 6.8',
            'fix':      'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            'ref':      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
            'poc':      False,
        }
    elif hsts:
        # Check for weak max-age
        try:
            age = int([p for p in hsts.split(';') if 'max-age' in p][0].split('=')[1].strip())
            if age < 2592000:  # less than 30 days
                return {
                    'id':       'HSTS_WEAK',
                    'risk':     'MEDIUM',
                    'name':     'Weak HSTS Configuration',
                    'evidence': f'Strict-Transport-Security: {hsts} | max-age={age} (< 30 days)',
                    'root':     'HSTS max-age is too short. Browser will forget the HSTS rule quickly and may allow HTTP connections again.',
                    'impact':   'Short window where SSL stripping attacks are possible after HSTS expiry.',
                    'cvss':     'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:M/I:M/A:N | Score: 4.2',
                    'fix':      'Strict-Transport-Security: max-age=31536000; includeSubDomains',
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
            'id':       'CSP_MISSING',
            'risk':     'HIGH',
            'name':     'No Content Security Policy',
            'evidence': 'Content-Security-Policy: NOT PRESENT',
            'root':     'Without a CSP, browsers will execute any inline script and load resources from any origin. There is no defence against XSS injection.',
            'impact':   'If any input is reflected without encoding, attacker injects <script> tags. Browser executes them freely — cookie theft, keyloggers, crypto miners, page defacement.',
            'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N | Score: 8.8',
            'fix':      "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
            'ref':      'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
            'poc':      False,
        }
    issues = []
    csp_l = csp.lower()
    if "'unsafe-inline'" in csp_l:
        issues.append("'unsafe-inline' allows inline scripts (XSS risk)")
    if "'unsafe-eval'" in csp_l:
        issues.append("'unsafe-eval' allows eval() (code injection risk)")
    if 'data:' in csp_l:
        issues.append("'data:' URI scheme allows data: based XSS")
    if '*' in csp and 'report' not in csp_l:
        issues.append("Wildcard (*) in source allows loading from anywhere")
    if issues:
        return {
            'id':       'CSP_UNSAFE',
            'risk':     'MEDIUM',
            'name':     'Unsafe Content Security Policy',
            'evidence': ' | '.join(issues),
            'root':     f'CSP exists but contains unsafe directives. Full CSP: {csp[:120]}',
            'impact':   'Unsafe directives defeat the purpose of CSP. Attacker can still inject and run scripts if an XSS entry point exists.',
            'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:M/I:M/A:N | Score: 6.1',
            'fix':      "Remove 'unsafe-inline', 'unsafe-eval'. Use nonces or hashes instead.",
            'ref':      'https://csp-evaluator.withgoogle.com/',
            'poc':      False,
        }
    return None


def chk_info_disclosure(hdrs):
    findings = []
    srv = hdrs.get('Server', '')
    if srv and any(c.isdigit() for c in srv):
        findings.append(f'Server: {srv} (version exposed)')
    xpb = hdrs.get('X-Powered-By', '')
    if xpb:
        findings.append(f'X-Powered-By: {xpb} (tech stack exposed)')
    xav = hdrs.get('X-AspNet-Version') or hdrs.get('X-AspNetMvc-Version')
    if xav:
        findings.append(f'ASP.NET version: {xav}')
    xgen = hdrs.get('X-Generator')
    if xgen:
        findings.append(f'X-Generator: {xgen}')
    if findings:
        return {
            'id':       'INFO_DISCLOSURE',
            'risk':     'MEDIUM',
            'name':     'Technology/Version Disclosure',
            'evidence': ' | '.join(findings),
            'root':     'HTTP response headers reveal the server software, version, or framework. This is trivially readable by anyone with browser dev tools.',
            'impact':   'Attacker identifies exact software versions and searches for known CVEs. Targeted exploits for unpatched vulnerabilities become trivial.',
            'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | Score: 5.3',
            'fix':      'Apache: ServerTokens Prod | Nginx: server_tokens off | IIS: remove X-Powered-By',
            'ref':      'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server',
            'poc':      False,
        }
    return None


def chk_xcto(hdrs):
    xcto = hdrs.get('X-Content-Type-Options', '')
    if 'nosniff' not in xcto.lower():
        return {
            'id':       'XCTO',
            'risk':     'MEDIUM',
            'name':     'Missing X-Content-Type-Options',
            'evidence': f'X-Content-Type-Options: {xcto or "NOT PRESENT"}',
            'root':     'Browser will sniff (guess) the content type of responses. A response served as text/plain can be re-interpreted as text/html and executed.',
            'impact':   'MIME-confusion XSS: attacker uploads a file with embedded script. Browser ignores the text/plain content-type and executes it as HTML.',
            'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:M/I:M/A:N | Score: 6.1',
            'fix':      'X-Content-Type-Options: nosniff',
            'ref':      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
            'poc':      False,
        }
    return None


def chk_referrer(hdrs):
    rp = hdrs.get('Referrer-Policy')
    if rp is None:
        return {
            'id':       'REFERRER',
            'risk':     'LOW',
            'name':     'Missing Referrer-Policy',
            'evidence': 'Referrer-Policy: NOT PRESENT',
            'root':     'Browser sends full URL in Referer header to every external site. If URLs contain session IDs, tokens, or sensitive paths, they leak to third-party analytics/CDN servers.',
            'impact':   'Private URL parameters (password reset tokens, API keys in URLs) exposed in server logs of third-party sites.',
            'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N | Score: 4.3',
            'fix':      'Referrer-Policy: strict-origin-when-cross-origin',
            'ref':      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
            'poc':      False,
        }
    return None


def chk_permissions(hdrs):
    pp = hdrs.get('Permissions-Policy') or hdrs.get('Feature-Policy')
    if pp is None:
        return {
            'id':       'PERMISSIONS',
            'risk':     'LOW',
            'name':     'Missing Permissions-Policy',
            'evidence': 'Permissions-Policy: NOT PRESENT',
            'root':     'No restrictions on what browser features embedded iframes can access. Third-party scripts and iframes can request camera, microphone, geolocation.',
            'impact':   'Malicious third-party script or ad can request camera/microphone access through the site\'s trusted origin without user realising the request comes from an attacker.',
            'cvss':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N | Score: 4.7',
            'fix':      'Permissions-Policy: camera=(), microphone=(), geolocation=()',
            'ref':      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy',
            'poc':      False,
        }
    return None


def chk_http_redirect(site_url):
    # Check if HTTP redirects to HTTPS
    http_url = 'http://' + site_url.replace('https://','').replace('http://','')
    try:
        import urllib.request
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args): return None
        opener = urllib.request.build_opener(NoRedirect)
        opener.open(http_url, timeout=6)
        # If we get here, site served HTTP without redirect
        return {
            'id':       'NO_HTTPS_REDIRECT',
            'risk':     'HIGH',
            'name':     'HTTP Site — No HTTPS Redirect',
            'evidence': f'{http_url} served response without redirecting to HTTPS',
            'root':     'Site serves content over plain HTTP. All traffic including cookies and credentials is transmitted without encryption.',
            'impact':   'Full traffic interception. Attacker on same network can read passwords, session tokens, and all page content in plaintext.',
            'cvss':     'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N | Score: 7.4',
            'fix':      'Force HTTPS redirect on server. Obtain TLS certificate via Let\'s Encrypt (free).',
            'ref':      'https://letsencrypt.org/',
            'poc':      False,
        }
    except HTTPError as e:
        if e.code in (301, 302, 307, 308):
            loc = e.headers.get('Location', '')
            if 'https://' not in loc:
                return {
                    'id':       'HTTP_REDIRECT_HTTP',
                    'risk':     'MEDIUM',
                    'name':     'HTTP Redirects to HTTP (Not HTTPS)',
                    'evidence': f'HTTP 301/302 Location: {loc} (still HTTP)',
                    'root':     'Site redirects from HTTP but target is also HTTP. Encryption is never enforced.',
                    'impact':   'Same as no HTTPS — all traffic readable in plaintext.',
                    'cvss':     'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N | Score: 7.4',
                    'fix':      'Redirect HTTP to https:// URL.',
                    'ref':      'https://letsencrypt.org/',
                    'poc':      False,
                }
    except Exception:
        pass
    return None


# ═══════════════════════════════════════════════════
#  MAIN SCAN FUNCTION (one site)
# ═══════════════════════════════════════════════════
def scan_site(raw_url):
    url = raw_url.strip()
    if not url.startswith('http'):
        url = 'https://' + url

    findings = []

    try:
        req  = Request(url, headers={'User-Agent': UA})
        resp = urlopen(req, timeout=TIMEOUT)
        hdrs = resp.info()
        final_url = resp.geturl()
    except HTTPError as e:
        hdrs      = e.headers
        final_url = url
    except Exception as e:
        return raw_url, url, [], str(e), None

    # Run all header-based checks
    for fn in [
        lambda h: chk_clickjacking(h),
        lambda h: chk_cors(url, h),
        lambda h: chk_cookies(h),
        lambda h: chk_hsts(h, url),
        lambda h: chk_csp(h),
        lambda h: chk_info_disclosure(h),
        lambda h: chk_xcto(h),
        lambda h: chk_referrer(h),
        lambda h: chk_permissions(h),
    ]:
        r = fn(hdrs)
        if r:
            findings.append(r)

    # CORS reflect (separate request)
    cr = chk_cors_reflect(url)
    if cr:
        findings.append(cr)

    # HTTP redirect check
    hr = chk_http_redirect(raw_url)
    if hr:
        findings.append(hr)

    # Collect all headers for evidence
    header_dump = dict(hdrs)

    return raw_url, final_url, findings, None, header_dump


# ═══════════════════════════════════════════════════
#  SCORING
# ═══════════════════════════════════════════════════
def score_findings(findings):
    return sum(RISK_S.get(f['risk'], 0) for f in findings)

def overall_label(score, count):
    if score >= 10 or any(f == 'CRITICAL' for f in [x['risk'] for x in []]):
        return 'CRITICAL', R
    if score >= 6:  return 'HIGH',     R
    if score >= 3:  return 'MEDIUM',   Y
    if score >= 1:  return 'LOW',      C
    return 'SECURE', G

def overall_label_from_score(score):
    if score >= 10: return 'CRITICAL', R
    if score >= 6:  return 'HIGH',     R
    if score >= 3:  return 'MEDIUM',   Y
    if score >= 1:  return 'LOW',      C
    return 'SECURE', G


# ═══════════════════════════════════════════════════
#  TERMINAL PRINTER
# ═══════════════════════════════════════════════════
def print_banner():
    print(BANNER)

def print_finding(f, idx):
    rc = RISK_C.get(f['risk'], C)
    print(f"  {BO}[{idx}]{RS} {rc}{BO}[{f['risk']}]{RS} {BO}{f['name']}{RS}")
    print(f"       {DM}Evidence   :{RS} {f['evidence'][:90]}")
    print(f"       {DM}Root Cause :{RS} {f['root'][:90]}")
    print(f"       {DM}Impact     :{RS} {f['impact'][:90]}")
    print(f"       {DM}CVSS       :{RS} {DM}{f['cvss']}{RS}")
    print()

def print_site_header(idx, total, site):
    bar = '=' * 60
    print(f"\n{C}{BO}{bar}{RS}")
    print(f"{C}{BO}  [{idx}/{total}] TARGET: {site}{RS}")
    print(f"{C}{BO}{bar}{RS}")


# ═══════════════════════════════════════════════════
#  HTML REPORT GENERATOR
# ═══════════════════════════════════════════════════
def build_report(raw_url, final_url, findings, header_dump, scan_time):
    safe = raw_url.replace('https://','').replace('http://','').replace('/','_')
    fname = safe + '_cjf_report.html'

    score = score_findings(findings)
    lbl, _ = overall_label_from_score(score)

    oc = {'CRITICAL':'#ff2244','HIGH':'#ff4444','MEDIUM':'#ffcc00','LOW':'#00ccff','SECURE':'#00ff99'}.get(lbl,'#aaa')

    # Vuln table rows
    trows = ''
    for i, f in enumerate(findings, 1):
        rc = {'CRITICAL':'#ff2244','HIGH':'#ff4444','MEDIUM':'#ffcc00','LOW':'#00ccff'}.get(f['risk'],'#aaa')
        trows += (
            f'<tr onclick="showDetail({i-1})" style="cursor:pointer">'
            f'<td><span class="b" style="background:{rc};color:#000">{f["risk"]}</span></td>'
            f'<td><b>{f["name"]}</b></td>'
            f'<td class="ev">{f["evidence"][:80]}</td>'
            f'<td class="ev">{f["cvss"].split("|")[1].strip() if "|" in f["cvss"] else ""}</td>'
            f'</tr>'
        )

    # Detail panels
    dpanels = ''
    for i, f in enumerate(findings):
        rc = {'CRITICAL':'#ff2244','HIGH':'#ff4444','MEDIUM':'#ffcc00','LOW':'#00ccff'}.get(f['risk'],'#aaa')
        fix_html = f['fix'].replace('\n','<br>')
        dpanels += f'''
<div class="dp" id="dp{i}">
  <div class="dh" style="border-left:4px solid {rc}">
    <span class="b" style="background:{rc};color:#000">{f["risk"]}</span>
    <strong style="font-size:15px">{f["name"]}</strong>
    <span class="cvss-pill">{f["cvss"].split("|")[1].strip() if "|" in f["cvss"] else ""}</span>
  </div>
  <div class="db">
    <div class="dr"><span class="dk">Evidence</span>
      <code class="ev-code">{f["evidence"]}</code></div>
    <div class="dr"><span class="dk">Root Cause</span>
      <span class="dv">{f["root"]}</span></div>
    <div class="dr"><span class="dk">Real Impact</span>
      <span class="dv red">{f["impact"]}</span></div>
    <div class="dr"><span class="dk">CVSS</span>
      <span class="dv dim">{f["cvss"]}</span></div>
    <div class="dr"><span class="dk">Fix</span>
      <code class="fix-code">{fix_html}</code></div>
    <div class="dr"><span class="dk">Reference</span>
      <a href="{f["ref"]}" target="_blank" class="ref-link">{f["ref"]}</a></div>
  </div>
</div>'''

    # Headers evidence
    hdr_rows = ''
    security_headers = [
        'X-Frame-Options','Content-Security-Policy','Strict-Transport-Security',
        'X-Content-Type-Options','Referrer-Policy','Permissions-Policy',
        'Access-Control-Allow-Origin','Set-Cookie','Server','X-Powered-By',
        'X-XSS-Protection','X-Generator'
    ]
    for h in security_headers:
        val = header_dump.get(h)
        if val:
            hdr_rows += f'<tr><td class="hk">{h}</td><td class="hv present">{val[:120]}</td></tr>'
        else:
            hdr_rows += f'<tr><td class="hk">{h}</td><td class="hv missing">NOT PRESENT</td></tr>'

    # PoC section (clickjacking)
    cj = next((f for f in findings if f['id'] == 'CLICKJACKING'), None)
    poc_tab  = '<div class="tab" onclick="sw(3)">&#127917; PoC Demo</div>' if cj else ''
    poc_html = ''
    if cj:
        poc_html = f'''
<div class="panel" id="p3">
  <div class="poc-wrap">
    <div class="poc-banner">
      <span style="color:#ff4444;font-size:14px;font-weight:bold">LIVE CLICKJACKING PROOF OF CONCEPT</span>
      <span class="poc-sub">Drag the slider to reveal the hidden target site beneath the attacker UI</span>
    </div>
    <div class="poc-desc">
      <b style="color:#00ff99">Attack flow:</b><br>
      <span class="step">1.</span> Target site <b>{final_url}</b> is loaded in a transparent iframe (z-index below attacker UI).<br>
      <span class="step">2.</span> Attacker overlays a convincing fake UI on top — victim sees only the fake page.<br>
      <span class="step">3.</span> Victim clicks "Claim Prize" thinking it is on the attacker site — click hits the real hidden site button.<br>
      <span class="step">4.</span> Real action executes (form submit, account action, etc.) without victim's knowledge.<br><br>
      <b>Why this works:</b> The server sends no X-Frame-Options or CSP frame-ancestors header, so browsers allow any site to embed it in an iframe.
    </div>
    <div class="arena">
      <iframe id="rf" src="{final_url}" class="victim-frame"></iframe>
      <div class="atk-ui" id="aui">
        <div class="atk-card">
          <div style="font-size:28px">&#127881;</div>
          <h2 style="color:#fff;margin:8px 0">You Won!</h2>
          <p style="color:#aaa;font-size:13px;margin-bottom:20px">Special reward — limited time only!</p>
          <button class="atk-btn" onclick="triggerAtk()">Claim Prize Now &#128293;</button>
          <p style="font-size:10px;color:#1a3a2a;margin-top:12px">[ Attacker fake button ]</p>
        </div>
      </div>
    </div>
    <div class="slider-row">
      <span>Reveal hidden site:</span>
      <input type="range" min="0" max="100" value="8" id="sl"
        oninput="document.getElementById('rf').style.opacity=this.value/100;
                 document.getElementById('aui').style.opacity=Math.max(0,1-this.value/60)">
      <span id="slv">8%</span>
    </div>
    <div id="atk-result" class="atk-result">
      <b>&#128683; Attack Executed!</b><br>
      Victim just performed an action on <b>{final_url}</b> without knowing.
      Their click hit a real button hidden underneath this page.
      If this was a "Delete Account" or "Transfer Funds" button — the action would have completed.
    </div>
    <div class="poc-note">
      Note: Some browsers may show a blank iframe even when the site IS vulnerable to clickjacking.
      This is because the browser loads the page in a sandboxed context. The vulnerability still exists —
      a real attacker would host this on a proper server (not file://) and it would work fully.
      The vulnerability proof is in the missing HTTP headers above.
    </div>
  </div>
</div>'''

    # Bug report text
    rpt = f"""# Security Scan Report — CJF v4.0

Target  : {final_url}
Scanned : {scan_time}
Issues  : {len(findings)}
Score   : {score}
Level   : {lbl}

{'='*60}
"""
    for f in findings:
        rpt += f"""
## [{f['risk']}] {f['name']}

Evidence   : {f['evidence']}
Root Cause : {f['root']}
Impact     : {f['impact']}
CVSS       : {f['cvss']}
Fix        : {f['fix']}
Reference  : {f['ref']}

{'-'*60}"""
    rpt += f"\n\n*Generated by CJF v1.0 | Developed by AVII-VERSE | {scan_time}*"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CJF Report | {raw_url}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{font-family:'Courier New',monospace;background:#060810;color:#d0d0d0;font-size:13px;}}

/* TOP BAR */
.tb{{background:#0a0c14;border-bottom:2px solid {oc};padding:14px 24px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;}}
.tb h1{{font-size:14px;color:{oc};letter-spacing:2px;}}
.rlbl{{background:{oc};color:#000;padding:3px 12px;border-radius:3px;font-size:11px;font-weight:bold;}}
.turl{{color:#444;font-size:12px;margin-left:auto;word-break:break-all;max-width:40%;}}
.sc{{background:#111;border:1px solid #222;border-radius:4px;padding:5px 14px;
  font-size:12px;color:{oc};white-space:nowrap;}}

/* TABS */
.tabs{{display:flex;background:#0a0c14;border-bottom:1px solid #1a1a2a;overflow-x:auto;}}
.tab{{padding:11px 18px;cursor:pointer;font-size:12px;color:#444;
  border-bottom:2px solid transparent;white-space:nowrap;transition:.2s;}}
.tab.active{{color:#00ff99;border-bottom-color:#00ff99;}}
.tab:hover{{color:#ccc;}}
.panel{{display:none;}}.panel.active{{display:block;}}

/* OVERVIEW */
.og{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;padding:16px 20px;}}
.sc2{{background:#0a0c14;border:1px solid #1a1a2a;border-radius:6px;padding:14px;text-align:center;}}
.sc2 .n{{font-size:28px;font-weight:bold;}}
.sc2 .l{{font-size:10px;color:#444;text-transform:uppercase;letter-spacing:1px;margin-top:4px;}}
.vt{{margin:0 20px 20px;border-collapse:collapse;width:calc(100% - 40px);}}
.vt th{{background:#0a0c14;color:#333;padding:8px 12px;text-align:left;
  border-bottom:1px solid #1a1a2a;font-size:10px;text-transform:uppercase;letter-spacing:1px;}}
.vt td{{padding:9px 12px;border-bottom:1px solid #0f1020;vertical-align:middle;}}
.vt tr:hover td{{background:#0a0c18;}}
.b{{padding:2px 8px;border-radius:3px;font-size:10px;font-weight:bold;}}
.ev{{color:#444;font-size:11px;}}

/* DETAILS */
.dw{{padding:16px 20px;display:flex;flex-direction:column;gap:10px;}}
.dp{{background:#0a0c14;border:1px solid #1a1a2a;border-radius:6px;overflow:hidden;
  cursor:pointer;transition:.15s;}}
.dp:hover{{border-color:#2a2a4a;}}
.dh{{padding:11px 14px;display:flex;align-items:center;gap:10px;background:#0c0e18;}}
.cvss-pill{{margin-left:auto;font-size:10px;color:#555;}}
.db{{padding:14px;display:none;}}
.dp.open .db{{display:block;}}
.dr{{display:flex;gap:12px;margin-bottom:8px;flex-wrap:wrap;}}
.dk{{color:#333;min-width:90px;flex-shrink:0;font-size:11px;padding-top:2px;}}
.dv{{color:#aaa;flex:1;line-height:1.7;}}
.red{{color:#ff8888;}}
.dim{{color:#555;}}
.ev-code{{background:#060810;border:1px solid #1a1a2a;padding:4px 8px;border-radius:3px;
  color:#00ff99;font-size:11px;word-break:break-all;flex:1;}}
.fix-code{{background:#050e08;border:1px solid #0a2010;padding:6px 10px;border-radius:3px;
  color:#00cc66;font-size:12px;word-break:break-all;flex:1;line-height:1.8;}}
.ref-link{{color:#4499ff;font-size:12px;}}

/* HEADERS */
.hw{{padding:16px 20px;}}
.ht{{border-collapse:collapse;width:100%;}}
.ht td{{padding:8px 14px;border-bottom:1px solid #0f1020;font-size:12px;}}
.hk{{color:#555;width:260px;}}
.hv.present{{color:#00ff99;word-break:break-all;}}
.hv.missing{{color:#ff4444;font-style:italic;}}

/* POC */
.poc-wrap{{padding:16px 20px;}}
.poc-banner{{background:#0a0c14;border:1px solid #ff4444;border-radius:6px;
  padding:12px 18px;margin-bottom:12px;display:flex;flex-direction:column;gap:4px;}}
.poc-sub{{color:#555;font-size:11px;}}
.poc-desc{{background:#0a0c14;border:1px solid #1a1a2a;border-radius:6px;
  padding:14px;margin-bottom:12px;line-height:1.9;color:#888;font-size:12px;}}
.step{{color:#ffcc00;}}
.arena{{position:relative;width:100%;height:520px;border:2px solid #1a1a2a;
  border-radius:6px;overflow:hidden;background:#0a0c14;}}
.victim-frame{{position:absolute;top:0;left:0;width:100%;height:100%;
  opacity:.08;border:none;z-index:1;}}
.atk-ui{{position:absolute;top:0;left:0;width:100%;height:100%;
  background:linear-gradient(135deg,#0a1628,#0d2040,#102856);
  z-index:2;display:flex;align-items:center;justify-content:center;}}
.atk-card{{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);
  border-radius:12px;padding:32px 48px;text-align:center;backdrop-filter:blur(4px);}}
.atk-btn{{background:linear-gradient(135deg,#00cc55,#00aa44);color:#fff;border:none;
  padding:14px 40px;font-size:15px;border-radius:8px;cursor:pointer;font-weight:bold;
  box-shadow:0 0 24px rgba(0,204,85,.4);transition:transform .15s,box-shadow .15s;
  font-family:'Courier New',monospace;}}
.atk-btn:hover{{transform:translateY(-2px);box-shadow:0 0 32px rgba(0,204,85,.6);}}
.slider-row{{display:flex;align-items:center;gap:12px;padding:10px 0;
  font-size:12px;color:#555;}}
.slider-row input{{width:200px;cursor:pointer;accent-color:#00ff99;}}
.atk-result{{display:none;margin-top:10px;padding:14px 18px;
  background:#150000;border:1px solid #ff4444;border-radius:6px;
  color:#ff8888;font-size:13px;line-height:1.8;}}
.poc-note{{margin-top:10px;padding:10px 14px;background:#0d0d0d;border:1px solid #1a1a1a;
  border-radius:4px;color:#333;font-size:11px;line-height:1.7;}}

/* REPORT */
.rw{{padding:16px 20px;}}
.cb{{margin-bottom:10px;padding:7px 18px;background:#0a0c14;border:1px solid #1a1a2a;
  color:#00ff99;border-radius:4px;cursor:pointer;font-size:12px;}}
.cb:hover{{background:#111;}}
.rt{{background:#0a0c14;border:1px solid #1a1a2a;border-radius:6px;padding:16px;
  white-space:pre-wrap;font-size:11px;line-height:1.9;color:#888;
  max-height:600px;overflow-y:auto;}}

.footer{{text-align:center;padding:12px;font-size:10px;color:#1a1a2a;
  border-top:1px solid #0f1020;margin-top:8px;}}
</style>
</head>
<body>

<div class="tb">
  <h1>&#9888; CJF SECURITY REPORT</h1>
  <span class="rlbl">{lbl}</span>
  <span class="sc">Score: {score} | Issues: {len(findings)}</span>
  <span class="turl">{final_url}</span>
</div>

<div class="tabs">
  <div class="tab active" onclick="sw(0)">&#128202; Overview</div>
  <div class="tab" onclick="sw(1)">&#128269; Findings</div>
  <div class="tab" onclick="sw(2)">&#128200; HTTP Headers</div>
  {poc_tab}
  <div class="tab" onclick="sw(4)">&#128196; Bug Report</div>
</div>

<!-- OVERVIEW -->
<div class="panel active" id="p0">
  <div class="og">
    <div class="sc2"><div class="n" style="color:{oc}">{len(findings)}</div><div class="l">Total Issues</div></div>
    <div class="sc2"><div class="n" style="color:#ff4444">{sum(1 for f in findings if f['risk'] in ('HIGH','CRITICAL'))}</div><div class="l">High / Critical</div></div>
    <div class="sc2"><div class="n" style="color:#ffcc00">{sum(1 for f in findings if f['risk']=='MEDIUM')}</div><div class="l">Medium</div></div>
    <div class="sc2"><div class="n" style="color:#00ccff">{sum(1 for f in findings if f['risk']=='LOW')}</div><div class="l">Low</div></div>
  </div>
  <table class="vt">
    <thead><tr><th>Risk</th><th>Vulnerability</th><th>Evidence</th><th>CVSS</th></tr></thead>
    <tbody>{trows}</tbody>
  </table>
</div>

<!-- FINDINGS DETAIL -->
<div class="panel" id="p1">
  <div class="dw">{dpanels}</div>
</div>

<!-- HTTP HEADERS -->
<div class="panel" id="p2">
  <div class="hw">
    <p style="color:#444;font-size:11px;margin-bottom:12px">Security-relevant HTTP response headers from {final_url}</p>
    <table class="ht"><tbody>{hdr_rows}</tbody></table>
  </div>
</div>

{poc_html}

<!-- BUG REPORT -->
<div class="panel" id="p4">
  <div class="rw">
    <button class="cb" onclick="copyR()">&#128203; Copy Report</button>
    <div class="rt" id="rp">{rpt}</div>
  </div>
</div>

<div class="footer">CJF v1.0 | Developed by AVII-VERSE | {scan_time} | Authorized Security Testing Only</div>

<script>
var cur=0;
function sw(n){{
  document.querySelectorAll('.tab').forEach((t,i)=>t.classList.toggle('active',i===n));
  document.querySelectorAll('.panel').forEach((p,i)=>p.classList.toggle('active',i===n));
  cur=n;
}}
function showDetail(i){{
  document.querySelectorAll('.dp').forEach((d,j)=>{{
    if(j===i)d.classList.toggle('open');
    else d.classList.remove('open');
  }});
}}
function triggerAtk(){{document.getElementById('atk-result').style.display='block';}}
function copyR(){{
  navigator.clipboard.writeText(document.getElementById('rp').innerText)
    .then(()=>alert('Report copied!'));
}}
document.getElementById('sl') && document.getElementById('sl').addEventListener('input',function(){{
  document.getElementById('slv').textContent=this.value+'%';
}});
</script>
</body>
</html>"""

    with open(fname, 'w', encoding='utf-8') as f:
        f.write(html)
    return fname


# ═══════════════════════════════════════════════════
#  FILE READER
# ═══════════════════════════════════════════════════
def read_sites(path):
    with open(path, 'rb') as f:
        raw = f.read()
    if raw.startswith(b'\xff\xfe') or raw.startswith(b'\xfe\xff'):
        content = raw.decode('utf-16')
    elif raw.startswith(b'\xef\xbb\xbf'):
        content = raw.decode('utf-8-sig')
    else:
        content = raw.decode('utf-8', errors='ignore')
    lines = [l.strip().replace('\x00','') for l in content.splitlines()]
    return [l for l in lines if l and not l.startswith('#')]


# ═══════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════
def main():
    print_banner()

    if len(argv) < 2:
        print(f"{Y}[*] Usage:{RS} python Clickjacking_Finder.py <targets_file> [threads]\n")
        print(f"  Example: python Clickjacking_Finder.py sites.txt")
        print(f"  Example: python Clickjacking_Finder.py sites.txt 10\n")
        exit(0)

    try:
        sites = read_sites(argv[1])
    except Exception as e:
        print(f"{R}[!] Cannot read file: {e}{RS}"); exit(0)

    threads = int(argv[2]) if len(argv) > 2 else THREADS
    total   = len(sites)
    ts      = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    print(f"{C}[*]{RS} Targets: {BO}{total}{RS} | Threads: {BO}{threads}{RS} | Timeout: {BO}{TIMEOUT}s{RS}")
    print(f"{C}[*]{RS} Checks : Clickjacking, CORS, Cookies, HSTS, CSP, Info-Disclosure, XCTO, Referrer, Permissions\n")

    results = {}
    done    = [0]
    lock    = __import__('threading').Lock()

    def worker(site):
        r = scan_site(site)
        with lock:
            done[0] += 1
            pct = int(done[0] / total * 20)
            bar = '#' * pct + '-' * (20 - pct)
            print(f"\r  [{bar}] {done[0]}/{total} scanned", end='', flush=True)
        return r

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(worker, s): s for s in sites}
        for fut in as_completed(futs):
            raw, final, findings, err, hdrs = fut.result()
            results[raw] = (final, findings, err, hdrs)

    print('\n')

    vuln_sites  = []
    secure_sites = []
    error_sites  = []

    # Print results sorted by score (highest first)
    sorted_sites = sorted(
        results.items(),
        key=lambda x: -score_findings(x[1][1])
    )

    for idx, (raw, (final, findings, err, hdrs)) in enumerate(sorted_sites, 1):
        print_site_header(idx, total, raw)

        if err:
            print(f"  {M}[ERROR]{RS} {err}\n")
            error_sites.append(raw)
            continue

        score = score_findings(findings)
        lbl, lc = overall_label_from_score(score)

        if not findings:
            print(f"  {G}{BO}[SECURE]{RS} No issues detected.\n")
            secure_sites.append(raw)
            continue

        h = sum(1 for f in findings if f['risk'] in ('HIGH','CRITICAL'))
        m = sum(1 for f in findings if f['risk'] == 'MEDIUM')
        l = sum(1 for f in findings if f['risk'] == 'LOW')

        print(f"  {lc}{BO}Overall: {lbl}{RS} | Score: {score} | "
              f"{R}HIGH:{h}{RS} {Y}MED:{m}{RS} {C}LOW:{l}{RS} | "
              f"Issues: {len(findings)}\n")

        for i, f in enumerate(findings, 1):
            print_finding(f, i)

        report = build_report(raw, final, findings, hdrs or {}, ts)
        print(f"  {Y}{BO}[>] Report : {report}{RS}")
        print(f"  {Y}[>] Open in browser — Overview, Detail, PoC Demo, Bug Report tabs.{RS}\n")
        vuln_sites.append((raw, len(findings), score, lbl))

    # ── FINAL SUMMARY ─────────────────────
    bar = '=' * 60
    print(f"\n{C}{BO}{bar}{RS}")
    print(f"{C}{BO}  FINAL SCAN SUMMARY{RS}")
    print(f"{C}{BO}{bar}{RS}")
    print(f"  {G}Secure  : {len(secure_sites)}{RS}")
    print(f"  {R}Issues  : {len(vuln_sites)}{RS}")
    print(f"  {M}Errors  : {len(error_sites)}{RS}")

    if vuln_sites:
        print(f"\n  {R}{BO}Vulnerability Ranking (worst first):{RS}")
        for site, cnt, sc, lbl in sorted(vuln_sites, key=lambda x: -x[2]):
            lc = overall_label_from_score(sc)[1]
            print(f"    {lc}{BO}{lbl:10}{RS} score={sc:2}  issues={cnt}  {site}")

    print(f"{C}{BO}{bar}{RS}\n")


if __name__ == '__main__':
    main()
