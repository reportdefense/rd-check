#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import struct
import ssl
import sys
import threading
import time
import warnings
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import quote, unquote, urlencode, urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__version__ = "1.1.0"

LOG = logging.getLogger("rd-check")


class RateLimiter:

    def __init__(self, max_rps: float = 0.0):
        self.min_interval = 1.0 / max_rps if max_rps and max_rps > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self):
        if not self.min_interval:
            return
        with self._lock:
            now = time.monotonic()
            sleep_for = self._next - now
            if sleep_for > 0:
                time.sleep(sleep_for)
                now = time.monotonic()
            self._next = now + self.min_interval


_RATE = RateLimiter()

BANNER = r"""
           .___               .__                   __
_______  __| _/          ____ |  |__   ____   ____ |  | __
\_  __ \/ __ |  ______ _/ ___\|  |  \_/ __ \_/ ___\|  |/ /
 |  | \/ /_/ | /_____/ \  \___|   Y  \  ___/\  \___|    <
 |__|  \____ |          \___  >___|  /\___  >\___  >__|_ \
            \/              \/     \/     \/     \/     \/
"""


class C:
    enabled = (sys.stderr.isatty() and "NO_COLOR" not in os.environ
               and "--no-color" not in sys.argv)
    RESET = "\033[0m" if enabled else ""
    BOLD = "\033[1m" if enabled else ""
    DIM = "\033[2m" if enabled else ""
    RED = "\033[31m" if enabled else ""
    GREEN = "\033[32m" if enabled else ""
    YELLOW = "\033[33m" if enabled else ""
    CYAN = "\033[36m" if enabled else ""


def print_banner():
    sys.stderr.write(f"{C.CYAN}{BANNER}{C.RESET}")
    sys.stderr.write(f"  {C.DIM}v{__version__}  ·  Report Defense Team{C.RESET}\n\n")


_print_lock = threading.Lock()


def log(msg: str = "", quiet: bool = False):
    if not quiet:
        with _print_lock:
            print(msg, file=sys.stderr)


CAPTCHA_SIGNATURES = {
    "reCAPTCHA": [r"google\.com/recaptcha", r"g-recaptcha", r"grecaptcha", r"recaptcha\.net"],
    "hCaptcha": [r"hcaptcha\.com", r"h-captcha"],
    "Cloudflare Turnstile": [r"challenges\.cloudflare\.com/turnstile", r"cf-turnstile"],
    "Arkose / FunCaptcha": [r"arkoselabs\.com", r"funcaptcha"],
    "GeeTest": [r"geetest"],
    "FriendlyCaptcha": [r"friendlycaptcha", r"frc-captcha"],
    "MTCaptcha": [r"mtcaptcha"],
    "AWS WAF Captcha": [r"captcha\.awswaf\.com"],
}
GENERIC_CAPTCHA = re.compile(r"captcha", re.I)

BOT_JS_SIGNATURES = {
    "Cloudflare (challenge / bot management)": [r"/cdn-cgi/challenge-platform", r"__cf_chl",
                                                r"/cdn-cgi/bm/"],
    "Akamai Bot Manager": [r"/akam/\d+/", r"_abck"],
    "Imperva/Incapsula": [r"_Incapsula_Resource", r"incapsula"],
    "DataDome": [r"js\.datadome\.co", r"captcha-delivery\.com", r"datadome"],
    "PerimeterX/HUMAN": [r"client\.perimeterx\.net", r"px-cdn\.net", r"px-captcha"],
    "Kasada": [r"kpsdk", r"/149e9513-01fa-4fb0-aad4-566afd725d1b/"],
    "F5 Shape / Distributed Cloud": [r"shapesecurity", r"f5cdn"],
    "AWS WAF (token)": [r"token\.awswaf\.com", r"awswaf"],
    "Sucuri": [r"sucuri\.net"],
}

WAF_HEADER_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-mitigated"],
    "Akamai": ["x-akamai-transformed", "akamai-grn"],
    "Imperva/Incapsula": ["x-iinfo"],
    "AWS CloudFront / WAF": ["x-amzn-waf-action", "x-amz-cf-id"],
    "F5": ["x-wa-info"],
    "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
    "Azure Front Door": ["x-azure-ref"],
    "Fastly": ["x-fastly-request-id"],
    "Hostinger CDN": ["x-hcdn-request-id", "x-hcdn-cache-status"],
}
WAF_COOKIE_SIGNATURES = {
    "Cloudflare": ["__cf_bm", "cf_clearance", "__cflb"],
    "Akamai Bot Manager": ["_abck", "ak_bmsc", "bm_sz"],
    "Imperva/Incapsula": ["incap_ses", "visid_incap"],
    "AWS WAF": ["aws-waf-token"],
    "F5 BIG-IP": ["bigipserver", "ts0"],
    "DataDome": ["datadome"],
    "PerimeterX/HUMAN": ["_px"],
}
SERVER_HINTS = [("cloudflare", "Cloudflare"), ("akamaighost", "Akamai"),
                ("awselb", "AWS ELB"), ("bigip", "F5"), ("sucuri", "Sucuri"),
                ("cloudfront", "AWS CloudFront"), ("hcdn", "Hostinger CDN")]

SECURITY_HEADERS = [("strict-transport-security", "Strict-Transport-Security (HSTS)"),
                    ("content-security-policy", "Content-Security-Policy (CSP)"),
                    ("x-content-type-options", "X-Content-Type-Options"),
                    ("referrer-policy", "Referrer-Policy"),
                    ("permissions-policy", "Permissions-Policy"),
                    ("x-frame-options", "X-Frame-Options")]

OBSOLETE_HEADERS = [("x-xss-protection", "X-XSS-Protection"),
                    ("public-key-pins", "Public-Key-Pins (HPKP)"),
                    ("expect-ct", "Expect-CT")]

BANNER_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                  "x-generator", "x-powered-cms", "x-runtime", "x-version", "x-server",
                  "x-backend-server", "x-redirect-by", "x-turbo-charged-by", "x-owa-version",
                  "microsoftsharepointteamservices", "liferay-portal", "x-drupal-cache",
                  "x-varnish-version", "x-envoy-upstream-service-time"]
TECH_BANNER = {"x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator",
               "x-powered-cms", "x-redirect-by", "x-owa-version", "x-backend-server",
               "microsoftsharepointteamservices", "liferay-portal", "x-turbo-charged-by"}
VERSION_RE = re.compile(r"\d+\.\d+")
META_GENERATOR = re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", re.I)
ERROR_PAGE_BANNER = re.compile(
    r"\b(Apache|nginx|openresty|Microsoft-IIS|LiteSpeed|Tomcat|Jetty|Caddy|Express|"
    r"Werkzeug|gunicorn|Kestrel)/\d+(?:\.\d+)*(?:\s*\([^)<]{1,40}\))?", re.I)

PROXY_HEADERS = {
    "cf-ray": "Cloudflare", "x-amz-cf-id": "AWS CloudFront", "x-amz-cf-pop": "AWS CloudFront",
    "x-amzn-trace-id": "AWS ALB", "x-azure-ref": "Azure Front Door",
    "x-akamai-transformed": "Akamai", "akamai-grn": "Akamai", "x-iinfo": "Imperva/Incapsula",
    "x-sucuri-id": "Sucuri", "x-fastly-request-id": "Fastly", "x-served-by": "Fastly/Varnish",
    "x-varnish": "Varnish", "x-cache-lookup": "Squid", "x-squid-error": "Squid",
    "x-proxy-cache": "nginx (proxy_cache)", "x-litespeed-cache": "LiteSpeed Cache",
    "x-hcdn-request-id": "Hostinger CDN", "x-envoy-upstream-service-time": "Envoy",
    "x-kong-proxy-latency": "Kong", "x-kong-upstream-latency": "Kong",
    "fly-request-id": "Fly.io", "x-vercel-id": "Vercel", "x-nf-request-id": "Netlify",
    "x-github-request-id": "GitHub Pages", "x-cdn": "CDN", "x-edge-location": "CDN",
    "x-cache": "caché intermedia", "age": "caché intermedia", "x-backend-server": "balanceador",
}
PROXY_SERVERS = [("cloudflare", "Cloudflare"), ("akamaighost", "Akamai"), ("cloudfront", "AWS CloudFront"),
                 ("awselb", "AWS ELB"), ("envoy", "Envoy"), ("haproxy", "HAProxy"),
                 ("traefik", "Traefik"), ("varnish", "Varnish"), ("squid", "Squid"),
                 ("hcdn", "Hostinger CDN"), ("sucuri", "Sucuri"), ("bigip", "F5 BIG-IP"),
                 ("gws", "Google"), ("google frontend", "Google LB"), ("kong", "Kong"),
                 ("ats", "Apache Traffic Server"), ("openresty", "OpenResty")]

BLOCKER_HEADERS = {"cf-mitigated": "Cloudflare", "x-sucuri-block": "Sucuri",
                   "x-amzn-waf-action": "AWS WAF", "x-iinfo": "Imperva/Incapsula"}
BLOCKER_BODY = [
    (r"attention required|cloudflare ray id|cf-error-details", "Cloudflare"),
    (r"mod_security|modsecurity|not acceptable!", "ModSecurity"),
    (r"imunify360", "Imunify360"),
    (r"wordfence", "Wordfence"),
    (r"sucuri website firewall", "Sucuri"),
    (r"incapsula incident", "Imperva/Incapsula"),
    (r"reference\s*(&#32;)?#\s*\d+\.", "Akamai"),
    (r"the requested url was rejected", "F5 BIG-IP ASM"),
    (r"generated by cloudfront|request blocked\.", "AWS CloudFront / WAF"),
    (r"fortiweb|fortigate", "Fortinet"),
    (r"barracuda", "Barracuda"),
]
SERVER_BLOCKERS = [("cloudflare", "Cloudflare"), ("hcdn", "Hostinger CDN"),
                   ("litespeed", "LiteSpeed"), ("akamaighost", "Akamai"),
                   ("cloudfront", "AWS CloudFront"), ("nginx", "nginx"), ("apache", "Apache")]
BLOCK_CODES = (403, 406, 419, 429, 501, 503)

WAF_PROBES = [
    ("ctl", {"rdcheck": "hola123"}),
    ("xss", {"rdcheck": "<script>alert(1)</script>"}),
    ("sqli", {"id": "1' OR '1'='1' -- "}),
    ("lfi", {"file": "../../../../etc/passwd"}),
]

RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
    "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset", "ratelimit-policy",
    "retry-after", "x-rate-limit-limit", "x-rate-limit-remaining",
]

BLOCK_PAGE_SIGNS = re.compile(
    r"attention required|access denied|request blocked|request rejected|"
    r"the requested url was rejected|incapsula incident|mod_security|"
    r"not acceptable|web application firewall|forbidden by|sucuri website firewall|"
    r"direct ip access not allowed|error code: 100\d",
    re.I)
WAF_PROBE_PARAMS = {"rdcheck": "<script>alert(1)</script>", "id": "1' OR '1'='1"}

AUTH_RE = re.compile(
    r"log-?in|logon|sign-?in|sign-?up|auth|passw|otp|2fa|mfa|register|forgot|reset-?pass|"
    r"iniciar|sesion|sesión|ingres|acceso|acceder|mi-?cuenta|micuenta|registr|clave|"
    r"contrase|portal-?clientes|sucursal-?virtual|oficina-?virtual", re.I)

PASSWORD_INPUT = re.compile(r"<input[^>]+type=[\"']?password", re.I)
MFA_HINT = re.compile(
    r"\b(otp|2fa|two[-_ ]factor|mfa|verification[-_ ]code|one[-_ ]time[-_ ]code|"
    r"c[oó]digo de verificaci[oó]n)\b", re.I)
SCRIPT_STYLE = re.compile(r"<(script|style)\b.*?</\1\s*>", re.I | re.S)
STATIC_EXT = re.compile(
    r"\.(css|js|mjs|map|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|pdf|zip|mp4|mp3|"
    r"xml|json|txt|csv)$", re.I)
JS_PATH_RE = re.compile("[\"'`](/[A-Za-z0-9_\\-][A-Za-z0-9_\\-./~%]{0,119})[\"'`]")

UA = f"Mozilla/5.0 (compatible; rd-check/{__version__})"

SEV_HIGH, SEV_MED, SEV_LOW, SEV_OK = "ALTA", "MEDIA", "INFO", "OK"
SEV_ORDER = {SEV_HIGH: 0, SEV_MED: 1, SEV_LOW: 2, SEV_OK: 3}


class Ctx:

    def __init__(self, timeout, retries: int = 1, verify: bool = False):
        if isinstance(timeout, (tuple, list)):
            self.timeout = tuple(timeout)
            self.read_timeout = timeout[1]
        else:
            self.timeout = (min(timeout, 6), timeout)
            self.read_timeout = timeout
        self.verify = verify
        self.n = 0
        self.s = requests.Session()
        self.s.headers["User-Agent"] = UA
        adapter = requests.adapters.HTTPAdapter(
            max_retries=urllib3.Retry(total=retries, connect=retries, read=retries,
                                      backoff_factor=0.5,
                                      status_forcelist=(502, 503, 504),
                                      allowed_methods=frozenset(["GET", "HEAD", "OPTIONS"]),
                                      raise_on_status=False))
        self.s.mount("http://", adapter)
        self.s.mount("https://", adapter)
        self.seen = []

    @staticmethod
    def _multi(hd) -> list:
        out = []
        try:
            for k in hd.keys():
                for v in hd.getlist(k):
                    out.append((k.lower(), v))
        except AttributeError:
            out = [(k.lower(), v) for k, v in hd.items()]
        return out

    def get(self, url, tag="", **kw):
        _RATE.wait()
        self.n += 1
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("verify", self.verify)
        kw.setdefault("allow_redirects", True)
        LOG.debug("GET %s (tag=%s)", url, tag or "-")
        r = self.s.get(url, **kw)
        for i, resp in enumerate([*r.history, r]):
            final = i == len(r.history)
            self.seen.append((tag if final else tag + "-redirect", resp.status_code,
                              self._multi(resp.raw.headers if resp.raw else resp.headers),
                              resp.text[:20_000] if final else ""))
        return r

    def raw(self, connect_host, port, scheme, host_header, sni=None, path="/", extra=None,
            method="GET"):
        _RATE.wait()
        self.n += 1
        LOG.debug("%s %s (Host=%s, connect=%s)", method, path, host_header, connect_host)
        headers = {"Host": host_header, "User-Agent": UA, "Accept": "*/*", **(extra or {})}
        chost = f"[{connect_host}]" if ":" in connect_host and not connect_host.startswith("[") \
            else connect_host
        if isinstance(self.timeout, (tuple, list)):
            to = urllib3.Timeout(connect=self.timeout[0], read=self.timeout[1])
        else:
            to = self.timeout
        if scheme == "https":
            pool = urllib3.HTTPSConnectionPool(
                chost, port, cert_reqs="CERT_NONE", assert_hostname=False,
                server_hostname=sni, timeout=to, retries=False)
        else:
            pool = urllib3.HTTPConnectionPool(chost, port, timeout=to, retries=False)
        try:
            r = pool.request(method, path, headers=headers, redirect=False)
            body = r.data[:300_000].decode("utf-8", "replace")
            self.seen.append(("raw", r.status, self._multi(r.headers), body[:20_000]))
            return r.status, {k.lower(): v for k, v in r.headers.items()}, body
        finally:
            pool.close()


_local = threading.local()
_all_drivers = []
_drivers_lock = threading.Lock()


def make_driver(page_timeout: int):
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options

    opts = Options()
    for a in ("--headless=new", "--ignore-certificate-errors", "--no-sandbox", "--disable-gpu",
              "--disable-dev-shm-usage", "--window-size=1366,900",
              "--blink-settings=imagesEnabled=false", f"--user-agent={UA}"):
        opts.add_argument(a)
    opts.page_load_strategy = "eager"
    driver = webdriver.Chrome(options=opts)
    driver.set_page_load_timeout(page_timeout)
    return driver


def render_page(url: str, page_timeout: int, wait: float):
    d = getattr(_local, "driver", None)
    if d is None:
        d = make_driver(page_timeout)
        _local.driver = d
        with _drivers_lock:
            _all_drivers.append(d)
    try:
        d.get(url)
        time.sleep(wait)
        html = d.page_source
        cookies = [c["name"].lower() for c in d.get_cookies()]
        d.delete_all_cookies()
        return html, cookies
    except Exception:
        try:
            d.quit()
        except Exception:
            pass
        _local.driver = None
        raise


def snippet(text: str, m, ctx: int = 35) -> str:
    frag = unquote(text[max(0, m.start() - ctx): m.end() + ctx])
    return re.sub(r"\s+", " ", frag).strip()


def first_match(text: str, sigs: dict) -> dict:
    found = {}
    for name, pats in sigs.items():
        for p in pats:
            m = re.search(p, text, re.I)
            if m:
                found[name] = snippet(text, m)
                break
    return found


def detect_captchas(html: str) -> dict:
    found = first_match(html, CAPTCHA_SIGNATURES)
    if not found:
        m = GENERIC_CAPTCHA.search(html)
        if m:
            found[t("generic_captcha")] = snippet(html, m)
    return found


def detect_waf(headers: dict, cookies) -> dict:
    waf = {}
    for name, hs in WAF_HEADER_SIGNATURES.items():
        for h in hs:
            if h in headers:
                waf.setdefault(name, []).append(f"header {h}")
    for name, cs in WAF_COOKIE_SIGNATURES.items():
        for c in sorted(set(cookies)):
            if any(c.startswith(x) for x in cs):
                waf.setdefault(name, []).append(f"cookie {c}")
    server = headers.get("server", "")
    for key, name in SERVER_HINTS:
        if key in server.lower():
            waf.setdefault(name, []).append(f"Server: {server}")
    return waf


def headers_and_cookies(r: requests.Response, session: requests.Session):
    headers, cookies = {}, set(c.name.lower() for c in session.cookies)
    for resp in [*r.history, r]:
        for k, v in resp.headers.items():
            headers[k.lower()] = v
        try:
            for sc in resp.raw.headers.getlist("Set-Cookie"):
                name = sc.split("=", 1)[0].strip().lower()
                if name:
                    cookies.add(name)
        except AttributeError:
            pass
    return headers, cookies


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.scripts, self.forms = [], [], []
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("a", "area") and a.get("href"):
            self.links.append((a["href"], a.get("title", "") + " " + a.get("aria-label", "")))
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""),
                          "method": (a.get("method") or "GET").upper(), "password": False}
            self.forms.append(self._form)
        elif tag == "input" and a.get("type", "").lower() == "password" and self._form:
            self._form["password"] = True

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


def parse_html(html: str) -> LinkParser:
    p = LinkParser()
    try:
        p.feed(html)
        p.close()
    except Exception:
        pass
    return p


def mine_js(text: str) -> set:
    out = set()
    for m in JS_PATH_RE.finditer(text):
        path = m.group(1).split("?")[0].rstrip("/")
        if path and "//" not in path and ".." not in path and not STATIC_EXT.search(path):
            out.add(path)
    return out


def similar(a: int, b: int) -> bool:
    return abs(a - b) <= max(300, 0.1 * max(a, b))


def shq(s: str) -> str:
    """Comillas simples seguras para shell."""
    return "'" + s.replace("'", "'\\''") + "'"


def curl_fmt(url: str, *opts: str) -> str:
    return " ".join(["curl -sk -o /dev/null -w '%{http_code} %{size_download}\\n'",
                     *opts, shq(url)])


def _detect_lang() -> str:
    argv = sys.argv[1:]
    for i, a in enumerate(argv):
        if a.startswith("--lang="):
            return a.split("=", 1)[1].lower()[:2]
        if a == "--lang" and i + 1 < len(argv):
            return argv[i + 1].lower()[:2]
    return "es"


_lang = _detect_lang()
LANG = _lang if _lang in ("es", "en") else "es"

TEXTS = {
    "yes": ("SÍ", "YES"), "no": ("NO", "NO"), "partial": ("PARCIAL", "PARTIAL"),
    "ok": ("OK", "OK"), "vuln": ("VULNERABLE", "VULNERABLE"), "review": ("REVISAR", "REVIEW"),
    "exposed": ("EXPUESTO", "EXPOSED"), "protected": ("PROTEGIDO", "PROTECTED"),
    "na": ("-", "-"),
    "c_domain": ("Dominio", "Domain"), "c_rl": ("Rate limit", "Rate limit"),
    "c_captcha": ("Captcha", "Captcha"),
    "c_waf": ("WAF", "WAF"), "c_login": ("Login", "Login"),
    "c_host": ("Host header", "Host header"), "c_https": ("HTTPS", "HTTPS"),
    "c_tls": ("TLS / certificado", "TLS / certificate"),
    "d_tls_ok": ("válido ({p}, {iss})", "valid ({p}, {iss})"),
    "d_tls_exp": ("vence {date} ({d}d)", "expires {date} ({d}d)"),
    "d_tls_invalid": ("certificado NO válido: {why} ({p})", "certificate NOT valid: {why} ({p})"),
    "d_tls_expired": ("certificado caducado ({p})", "certificate expired ({p})"),
    "d_tls_weak": ("protocolo débil: {p}", "weak protocol: {p}"),
    "d_tls_soon": ("caduca en {d} días", "expires in {d} days"),
    "d_tls_error": ("no se pudo negociar TLS ({err})", "could not negotiate TLS ({err})"),
    "f_tls_invalid": ("Certificado TLS no válido: {why}", "Invalid TLS certificate: {why}"),
    "f_tls_weak": ("Protocolo TLS obsoleto: {p}", "Obsolete TLS protocol: {p}"),
    "f_tls_soon": ("El certificado TLS caduca pronto ({d} días)",
                   "TLS certificate expires soon ({d} days)"),
    "c_origin": ("Origen", "Origin"),
    "h_control": ("Control", "Control"), "h_result": ("Resultado", "Result"),
    "h_detail": ("Detalle", "Detail"), "h_test": ("Prueba de servidor", "Server test"),
    "h_sev": ("Severidad", "Severity"), "h_finding": ("Hallazgo", "Finding"),
    "h_repro": ("Comando para reproducir", "Command to reproduce"),
    "h_check": ("Comprobación", "Check"), "h_source": ("Origen", "Source"),
    "h_indicator": ("Indicador", "Indicator"), "h_evidence": ("Evidencia", "Evidence"),
    "h_page": ("Página", "Page"), "h_submit": ("Envío de credenciales", "Credentials sent to"),
    "h_requests": ("Peticiones", "Requests"),
    "d_rl_headers": ("cabeceras: {v}", "headers: {v}"),
    "d_rl_429": ("la página respondió HTTP 429", "page answered HTTP 429"),
    "d_rl_none": ("no hay cabeceras de rate limit; confirmar con --burst 30",
                  "no rate-limit headers; confirm with --burst 30"),
    "d_bot_js": ("script: {v}", "script: {v}"), "d_bot_cookie": ("cookie: {v}", "cookie: {v}"),
    "d_none": ("no detectado", "not detected"),
    "d_captcha_where": ("{v} ({where})", "{v} ({where})"),
    "w_home": ("inicio", "home"), "w_login": ("login", "login"),
    "manual": ("VERIFICAR MANUAL", "CHECK MANUALLY"),
    "d_waf_front": (" ({v} delante)", " ({v} in front)"),
    "d_waf_yes": ("{who} activo: filtra inyecciones ({classes}) y deja pasar la petición normal",
                  "{who} active: filters injections ({classes}) and lets the normal request pass"),
    "d_waf_yes_guess": ("filtra inyecciones ({classes}); probablemente {who} (sin confirmar)",
                        "filters injections ({classes}); probably {who} (unconfirmed)"),
    "d_waf_yes_unk": ("filtra inyecciones ({classes}); proveedor no identificado (WAF del "
                      "hosting, plugin o la propia aplicación)",
                      "filters injections ({classes}); provider not identified (hosting WAF, "
                      "plugin or the application itself)"),
    "d_waf_no_cdn": ("{v} delante (CDN/proxy), pero no filtra ninguna inyección de prueba",
                     "{v} in front (CDN/proxy), but filters none of the test injections"),
    "d_waf_no": ("no filtra ninguna inyección de prueba (XSS, SQLi, traversal)",
                 "filters none of the test injections (XSS, SQLi, traversal)"),
    "d_waf_ctl": ("bloquea hasta la petición normal (HTTP {ctl}): no se puede comparar, "
                  "verificar manualmente", "blocks even the normal request (HTTP {ctl}): "
                  "cannot compare, check manually"),
    "d_waf_base": ("la página base responde {st}: no se puede comparar, verificar manualmente",
                   "base page answers {st}: cannot compare, check manually"),
    "t_waf_ctl": ("WAF: control (?rdcheck=hola123)", "WAF: control (?rdcheck=hola123)"),
    "t_waf_xss": ("WAF: XSS", "WAF: XSS"), "t_waf_sqli": ("WAF: SQLi", "WAF: SQLi"),
    "t_waf_lfi": ("WAF: path traversal", "WAF: path traversal"),
    "t_method": ("Método {m}", "{m} method"),
    "v_trace_on": ("HTTP {st}: TRACE habilitado (Cross-Site Tracing)",
                   "HTTP {st}: TRACE enabled (Cross-Site Tracing)"),
    "v_method_ok": ("HTTP {st}: el método {m} no se rechaza", "HTTP {st}: {m} method not rejected"),
    "v_method_block": ("{m} rechazado (HTTP {st})", "{m} rejected (HTTP {st})"),
    "w_ctl_ok": ("HTTP {st}: pasa (petición de referencia, sin payload)",
                 "HTTP {st}: passes (reference request, no payload)"),
    "w_pass": ("HTTP {st}: no filtrada (este patrón no dispara el WAF; no es un bypass)",
               "HTTP {st}: not filtered (this pattern doesn't trigger the WAF; not a bypass)"),
    "w_blocked": ("HTTP {st}: filtrada{who}", "HTTP {st}: filtered{who}"),
    "w_cut": ("conexión cortada ({err}): bloqueada", "connection cut ({err}): blocked"),
    "h_field": ("Campo", "Field"), "h_value": ("Valor", "Value"),
    "c_sechead": ("Cabeceras HTTP", "Security headers"),
    "c_banner": ("Banner o Versiones", "Banner / Versions"),
    "c_proxy": ("Reverse proxy", "Reverse proxy"),
    "c_dns": ("DNS / infraestructura", "DNS / infrastructure"),
    "c_shared": ("IP compartida", "Shared IP"),
    "d_dns_error": ("no se pudo resolver DNS", "DNS resolution failed"),
    "d_shared_one": ("{ip} = sin otros dominios", "{ip} = no other domains"),
    "d_shared_many": ("{ip} = {n} dominios", "{ip} = {n} domains"),
    "d_shared_behindcdn": ("{ip} es la IP del CDN; el origen real es desconocido "
                           "(indica --origin IP para analizarlo)",
                           "{ip} is the CDN IP; the real origin is unknown "
                           "(pass --origin IP to analyse it)"),
    "d_shared_err": ("{ip}: no disponible ({e})", "{ip}: unavailable ({e})"),
    "r_dns": ("DNS e infraestructura", "DNS and infrastructure"),
    "dns_prov": ("Proveedor / rango", "Provider / range"),
    "dns_records": ("Registros", "Records"),
    "dns_verifs": ("Verificaciones", "Verifications"),
    "dns_reg": ("Registrado en", "Registered to"),
    "dns_prefix": ("Prefijo", "Prefix"),
    "dns_t_a": ("A", "A"), "dns_t_mx": ("MX Records", "MX Records"),
    "dns_t_ns": ("Nameservers", "Nameservers"), "dns_t_txt": ("TXT Records", "TXT Records"),
    "dns_t_shared": ("Dominios en la IP ({ip})", "Domains on IP ({ip})"),
    "dns_h_domain": ("Dominio", "Domain"), "dns_h_vendor": ("Vendor", "Vendor"),
    "r_exec": ("Resumen ejecutivo", "Executive summary"),
    "h_section": ("Sección", "Section"),
    "f_no_spf": ("Sin registro SPF (riesgo de suplantación de correo)",
                 "No SPF record (email spoofing risk)"),
    "f_no_dmarc": ("Sin registro DMARC", "No DMARC record"),
    "f_dmarc_none": ("DMARC con política p=none (no protege)",
                     "DMARC policy is p=none (no enforcement)"),
    "c_options": ("Métodos (OPTIONS)", "Methods (OPTIONS)"),
    "t_options": ("Método OPTIONS", "OPTIONS method"),
    "v_opt_none": ("HTTP {st}: no declara métodos (sin cabecera Allow)",
                   "HTTP {st}: no methods declared (no Allow header)"),
    "v_opt_ok": ("solo métodos seguros: {v}", "safe methods only: {v}"),
    "v_opt_risky": ("métodos permitidos: {v}; revisar: {r}",
                    "allowed methods: {v}; review: {r}"),
    "d_opt_none": ("no declara métodos", "no methods declared"),
    "f_options": ("OPTIONS expone métodos sensibles ({r}); confirma que están deshabilitados",
                  "OPTIONS exposes sensitive methods ({r}); confirm they are disabled"),
    "d_sec_none": ("ninguna", "none"),
    "d_sec_obsolete": ("obsoletas presentes: {v}", "obsolete present: {v}"),
    "banneronly": ("Solo Banner", "Banner only"),
    "bannerver": ("Banner + Version", "Banner + Version"),
    "nobanner": ("NO", "NO"),
    "d_banner_nover": ("{v} (sin versión)", "{v} (no version)"),
    "f_obsolete": ("Cabeceras obsoletas/deprecadas presentes: {v}",
                   "Obsolete/deprecated headers present: {v}"),
    "d_proxy_server_diff": ("Server distinto según la respuesta: {v}",
                            "different Server per response: {v}"),
    "d_proxy_via": ("Via: {v}", "Via: {v}"),
    "r_sechead": ("Cabeceras de seguridad", "Security headers"),
    "r_banner": ("Banner o versiones", "Banner / versions"),
    "r_proxy": ("Reverse proxy", "Reverse proxy"),
    "h_header": ("Cabecera", "Header"), "h_present": ("Presente", "Present"),
    "f_sechead": ("Faltan cabeceras de seguridad ({n}/6): {v}",
                  "Missing security headers ({n}/6): {v}"),
    "f_banner": ("Divulgación de versiones: {v}", "Version disclosure: {v}"),
    "i_final": ("URL final", "Final URL"), "i_cdn": ("Reverse proxy / CDN", "Reverse proxy / CDN"),
    "d_login": ("{url} → {submit}", "{url} → {submit}"),
    "d_login_none": ("no se encontró formulario de login", "no login form found"),
    "d_login_other": ("el login está en otro subdominio: {v}", "login is on another subdomain: {v}"),
    "d_host_ok": ("rechaza Host falso y no refleja X-Forwarded-Host",
                  "rejects fake Host and does not reflect X-Forwarded-Host"),
    "d_not_tested": ("no probado (--passive)", "not tested (--passive)"),
    "t_ref": ("Referencia (Host correcto)", "Baseline (correct Host)"),
    "t_host": ("Host falso", "Fake Host"), "t_xfh": ("X-Forwarded-Host", "X-Forwarded-Host"),
    "t_ip": ("IP directa ({ip})", "Direct IP ({ip})"), "t_http": ("HTTP → HTTPS", "HTTP → HTTPS"),
    "t_origin": ("Origen directo ({ip})", "Direct origin ({ip})"),
    "v_status": ("HTTP {st}", "HTTP {st}"), "v_error": ("error: {err}", "error: {err}"),
    "v_host_refused": ("conexión rechazada ({err}): no acepta hosts desconocidos",
                       "connection refused ({err}): unknown hosts not accepted"),
    "v_host_reflect_body": ("REFLEJA el Host falso en el HTML: la app confía en el Host "
                            "(Host header injection)",
                            "REFLECTS the fake Host in the HTML: the app trusts the Host "
                            "(Host header injection)"),
    "v_host_reflect_redirect": ("HTTP {st}: redirige al Host falso (redirect absoluto); riesgo "
                                "solo si se cachea o se usa en enlaces de reset",
                                "HTTP {st}: redirects to the fake Host (absolute redirect); risk "
                                "only if cached or used in reset links"),
    "v_host_reflect_other": ("devuelve el Host falso en Location: revisar cómo se usa el Host",
                             "returns the fake Host in Location: review how the Host is used"),
    "v_host_rejects": ("HTTP {st}: rechaza hosts desconocidos", "HTTP {st}: rejects unknown hosts"),
    "v_host_any": ("HTTP {st} con el mismo contenido: no valida el Host",
                   "HTTP {st} with the same content: Host is not validated"),
    "v_host_default": ("HTTP {st}, contenido distinto: vhost por defecto",
                       "HTTP {st}, different content: default vhost"),
    "v_xfh_reflect": ("REFLEJA X-Forwarded-Host: riesgo de cache poisoning / enlaces de reset "
                      "envenenados", "REFLECTS X-Forwarded-Host: cache poisoning / poisoned "
                      "reset links risk"),
    "v_xfh_ok": ("HTTP {st}: no se refleja", "HTTP {st}: not reflected"),
    "v_ip_tls": ("rechaza TLS sin nombre de dominio: no sirve el sitio por IP",
                 "rejects TLS without domain name: site not served by IP"),
    "v_ip_noresp": ("no responde por IP ({err})", "no response on IP ({err})"),
    "v_ip_blocked": ("HTTP {st}: no sirve el sitio por IP", "HTTP {st}: site not served by IP"),
    "v_ip_serves": ("HTTP {st}: sirve el sitio por IP directa", "HTTP {st}: site served by direct IP"),
    "v_ip_serves_nocdn": ("HTTP {st}: sirve el sitio por IP directa, sin CDN/WAF delante",
                          "HTTP {st}: site served by direct IP, no CDN/WAF in front"),
    "v_ip_default": ("HTTP {st}: responde un vhost por defecto", "HTTP {st}: default vhost answers"),
    "v_http_closed": ("puerto 80 cerrado ({err})", "port 80 closed ({err})"),
    "v_http_redirect": ("HTTP {st} → {loc}", "HTTP {st} → {loc}"),
    "v_http_plain": ("HTTP {st}: se sirve por HTTP sin redirigir a HTTPS",
                     "HTTP {st}: served over HTTP without redirecting to HTTPS"),
    "v_origin_noresp": ("el origen no responde a Internet ({err})",
                        "origin does not answer from the Internet ({err})"),
    "v_origin_bypass": ("el origen sirve el sitio directamente: el WAF/CDN se puede eludir",
                        "origin serves the site directly: WAF/CDN can be bypassed"),
    "v_origin_diff": ("HTTP {st}: el origen responde, pero no igual",
                      "HTTP {st}: origin answers, but differently"),
    "p_blocks": ("BLOQUEA", "BLOCKS"), "p_noblock": ("no bloquea", "does not block"),
    "p_inconclusive": ("no concluyente", "inconclusive"),
    "p_base_error": ("la página base ya responde {st}", "base page already answers {st}"),
    "p_cut": ("conexión cortada: {err}", "connection cut: {err}"),
    "b_enforced": ("aplicado", "enforced"), "b_not_observed": ("NO OBSERVADO", "NOT OBSERVED"),
    "b_inconclusive": ("no concluyente", "inconclusive"),
    "b_noresp": ("sin respuesta ({err})", "no response ({err})"),
    "b_429_first": ("HTTP 429 desde la 1ª petición (ya limitado)",
                    "HTTP 429 from the 1st request (already limited)"),
    "b_403_first": ("HTTP 403 desde la 1ª petición", "HTTP 403 from the 1st request"),
    "b_hit": ("{why} desde la petición ~{i}; {n} peticiones en {s:.1f}s; {summ}",
              "{why} from request ~{i}; {n} requests in {s:.1f}s; {summ}"),
    "b_cut": ("conexiones cortadas; {n} peticiones en {s:.1f}s; {summ}",
              "connections cut; {n} requests in {s:.1f}s; {summ}"),
    "b_none": ("{n} peticiones en {s:.1f}s sin bloqueo; {summ}",
               "{n} requests in {s:.1f}s without blocking; {summ}"),
    "f_no_waf": ("Sin WAF: ningún payload XSS/SQLi/traversal se bloquea",
                 "No WAF: no XSS/SQLi/traversal payload is blocked"),
    "f_waf_noblock": ("Hay {v} delante pero no bloquea payloads XSS/SQLi/traversal: no hay "
                      "reglas WAF activas", "{v} is in front but blocks no XSS/SQLi/traversal "
                      "payload: no active WAF rules"),
    "f_login_unprot": ("Login sin captcha ni cabeceras de rate limit: {url} ({submit})",
                       "Login without captcha or rate-limit headers: {url} ({submit})"),
    "f_confirm": (" — confirmar con --burst", " — confirm with --burst"),
    "f_burst": ("Ráfaga sin bloqueo en {url}: {d}", "Burst not blocked on {url}: {d}"),
    "f_no_rl": ("Sin cabeceras de rate limit (solo --burst confirma si existe)",
                "No rate-limit headers (only --burst confirms whether it exists)"),
    "f_other_host": ("El login enlaza a otro subdominio: {v} (analízalo también)",
                     "Login links to another subdomain: {v} (scan it too)"),
    "f_noresp": ("No responde ({err})", "No response ({err})"),
    "k_unreach": ("sin respuesta", "no response"),
    "r_title": ("Informe rd-check: Rate limit / Anti-bot / Captcha / WAF",
                "rd-check report: Rate limit / Anti-bot / Captcha / WAF"),
    "r_date": ("Fecha", "Date"), "r_input": ("Entrada", "Input"), "r_mode": ("Modo", "Mode"),
    "r_burst": ("Ráfaga", "Burst"), "r_off": ("desactivada", "disabled"),
    "r_nreq": ("{n} peticiones", "{n} requests"), "r_sent": ("Peticiones enviadas", "Requests sent"),
    "r_summary": ("Resumen", "Summary"), "r_priority": ("Prioridad", "Priority"),
    "r_verdict": ("Veredicto", "Verdict"), "r_code": ("Código y cabeceras", "Code and headers"),
    "r_server": ("Servidor (pruebas tipo curl)", "Server (curl-style tests)"),
    "r_waf_probe": ("WAF probe", "WAF probe"), "r_burst_sec": ("Ráfaga", "Burst"),
    "r_result": ("Resultado", "Result"), "r_repro": ("Reproducir", "Reproduce"),
    "r_conclusions": ("Conclusiones", "Conclusions"), "r_js": (
        "Rutas de autenticación en el JavaScript", "Authentication paths in the JavaScript"),
    "r_errors": ("Errores", "Errors"), "r_passive": ("pasivo", "passive"),
    "r_reqonly": ("solo requests", "requests only"),
    "r_notes": ("**Notas:** «NO» en rate limit sin `--burst` significa que no hay cabeceras "
                "visibles, no que esté confirmado. El límite que protege el login suele estar "
                "en el endpoint que recibe el POST de credenciales. Sin `--origin` no se puede "
                "saber si el servidor real es accesible saltándose el WAF/CDN.",
                "**Notes:** \"NO\" for rate limit without `--burst` means no visible headers, "
                "not a confirmed absence. The limit that protects login usually lives on the "
                "endpoint receiving the credentials POST. Without `--origin` it is unknown "
                "whether the real server can be reached bypassing the WAF/CDN."),
    "k_domains": ("{n} dominio(s)", "{n} domain(s)"),
    "k_header": ("HTTP {st} · {n} peticiones", "HTTP {st} · {n} requests"),
    "k_interrupted": ("Interrumpido; guardando resultados parciales...",
                      "Interrupted; saving partial results..."),
    "k_noresults": ("Sin resultados; no se genera informe.", "No results; no report written."),
    "k_no_selenium": ("Selenium no está instalado (pip install selenium). Sigo solo con requests.",
                      "Selenium is not installed (pip install selenium). Using requests only."),
    "k_no_chrome": ("No se pudo iniciar Chrome ({e}). Sigo solo con requests.",
                    "Could not start Chrome ({e}). Using requests only."),
    "k_all": ("Resumen de todos los dominios", "All domains summary"),
    "u_usage": ("uso: ", "usage: "), "u_examples": ("ejemplos:", "examples:"),
    "u_list": ("subdominios.txt", "subdomains.txt"),
    "e_both": ("usa un DOMINIO o -f FICHERO, no los dos a la vez",
               "use a DOMAIN or -f FILE, not both"),
    "e_none": ("indica un DOMINIO o una lista con -f FICHERO", "give a DOMAIN or a list with -f FILE"),
    "e_read": ("no se puede leer '{f}': {e}", "cannot read '{f}': {e}"),
    "e_empty": ("'{f}' no contiene dominios válidos", "'{f}' has no valid domains"),
    "e_range": ("--{n} debe estar entre {lo} y {hi}", "--{n} must be between {lo} and {hi}"),
    "e_origin": ("--origin debe ser una IPv4", "--origin must be an IPv4 address"),
    "e_all_private": ("todos los objetivos resuelven a IPs privadas (--deny-private)",
                      "all targets resolve to private IPs (--deny-private)"),
    "k_skip_private": ("omitido (IP privada): {h}", "skipped (private IP): {h}"),
    "k_changes": ("Cambios respecto a la línea base", "Changes vs baseline"),
    "k_nochange": ("Sin cambios respecto a la línea base", "No changes vs baseline"),
    "e_help": ("Usa -h para ver la ayuda.", "Use -h for help."),
    "generic_captcha": ("Captcha genérico (revisar)", "Generic captcha (review)"),
    "origin_tag": (" (origen)", " (origin)"),
    "api_limit": ("límite de la API", "API limit reached"),
    "no_data": ("sin datos", "no data"),
    "expired": ("caducado", "expired"),
    "d_tls_legacy": ("acepta {p} (obsoleto)", "accepts {p} (obsolete)"),
    "f_tls_legacy": ("El servidor acepta protocolos TLS obsoletos: {p}",
                     "Server accepts obsolete TLS protocols: {p}"),
}


SEV_LABEL = {"ALTA": ("ALTA", "HIGH"), "MEDIA": ("MEDIA", "MEDIUM"), "INFO": ("INFO", "INFO"),
             "OK": ("OK", "OK")}


def sev(s: str) -> str:
    return SEV_LABEL[s][0 if LANG == "es" else 1]


def t(key: str, **kw) -> str:
    s = TEXTS[key][0 if LANG == "es" else 1]
    return s.format(**kw) if kw else s


BOT_COOKIES = ["__cf_bm", "cf_clearance", "_abck", "ak_bmsc", "bm_sz", "datadome", "_px",
               "aws-waf-token", "incap_ses", "visid_incap", "reese84", "kp_uidz"]


def check_code(ctx: Ctx, url: str, opts, rep: dict):
    r = ctx.get(url, tag="base")
    rep["status"], rep["final_url"] = r.status_code, r.url
    headers, cookies = headers_and_cookies(r, ctx.s)
    rep["_base"] = {"status": r.status_code}
    html = r.text[:800_000]

    rendered = ""
    if opts.use_selenium and "html" in headers.get("content-type", ""):
        try:
            rendered, sel_cookies = render_page(url, ctx.read_timeout + 5, opts.render_wait)
            cookies.update(sel_cookies)
            ctx.n += 1
        except Exception as e:
            rep["errors"].append(f"selenium:{type(e).__name__}")
    full = html + "\n" + rendered[:800_000]

    cap = detect_captchas(full)
    rep["captcha"] = ", ".join(cap)
    for k, v in cap.items():
        rep["evidence"].append(("HTML", f"Captcha {k}", v))
    bots = first_match(full, BOT_JS_SIGNATURES)
    rep["bot_js"] = ", ".join(bots)

    waf = detect_waf(headers, cookies)
    rep["waf"] = ", ".join(sorted(waf))
    for k, v in sorted(waf.items()):
        rep["evidence"].append(("Headers", f"WAF/CDN {k}", ", ".join(sorted(set(v)))))
    rl = [f"{h}={headers[h]}" for h in RATE_LIMIT_HEADERS if h in headers]
    rep["server_header"] = headers.get("server", "")
    rep["got_429"] = r.status_code == 429

    hosts = {urlparse(r.url).netloc.lower(), urlparse(url).netloc.lower()}
    pages = [(r.url, full, headers)]
    lp = parse_html(full)
    auth_links = []
    for href, label in lp.links:
        u = urljoin(r.url, href.strip())
        pu = urlparse(u)
        if pu.scheme in ("http", "https") and pu.netloc.lower() in hosts and \
                not STATIC_EXT.search(pu.path) and (AUTH_RE.search(pu.path) or AUTH_RE.search(label)):
            auth_links.append(f"{pu.scheme}://{pu.netloc}{pu.path or '/'}")
    base_name = (urlparse(r.url).hostname or "").lower()
    root = ".".join(base_name.split(".")[-2:])
    ext_login = set()
    for h, l in lp.links:
        hn = (urlparse(urljoin(r.url, h)).hostname or "").lower()
        if hn and hn != base_name and hn.endswith("." + root) and \
                (AUTH_RE.search(h) or AUTH_RE.search(l)):
            ext_login.add(hn)
    rep["login_other_hosts"] = ", ".join(sorted(ext_login))

    for u in list(dict.fromkeys(auth_links))[:opts.max_login_pages]:
        try:
            rr = ctx.get(u)
        except requests.RequestException as e:
            rep["errors"].append(f"{u}:{type(e).__name__}")
            continue
        h2, c2 = headers_and_cookies(rr, ctx.s)
        cookies |= c2
        rep["got_429"] |= rr.status_code == 429
        page = rr.text[:800_000]
        if opts.use_selenium and "html" in h2.get("content-type", "") and \
                not PASSWORD_INPUT.search(page):
            try:
                rh, rc = render_page(u, ctx.read_timeout + 5, opts.render_wait)
                page += "\n" + rh[:800_000]
                cookies.update(rc)
                ctx.n += 1
            except Exception:
                pass
        pages.append((rr.url, page, h2))

    logins = []
    for purl, phtml, ph in pages:
        vis = SCRIPT_STYLE.sub(" ", phtml)
        if not PASSWORD_INPUT.search(vis):
            continue
        forms = [f for f in parse_html(phtml).forms if f["password"]]
        if forms:
            f = forms[0]
            submit = f"{f['method']} {urljoin(purl, f['action']) if f['action'] else purl}"
        else:
            submit = "JavaScript (sin <form>)" if LANG == "es" else "JavaScript (no <form>)"
        cap_p = detect_captchas(phtml)
        rl_p = [f"{h}={ph[h]}" for h in RATE_LIMIT_HEADERS if h in ph]
        logins.append({"url": purl, "submit": submit, "captcha": ", ".join(cap_p),
                       "rl_headers": "; ".join(rl_p), "mfa": bool(MFA_HINT.search(vis))})
        rl += [h for h in rl_p if h not in rl]
    rep["logins"] = logins
    rep["rl_headers"] = "; ".join(rl)
    rep["bot_cookies"] = ", ".join(sorted(c for c in cookies
                                          if any(c.startswith(b) for b in BOT_COOKIES)))

    js_paths = mine_js(full)
    scripts = [urljoin(r.url, s) for s in lp.scripts]
    scripts = [s for s in dict.fromkeys(scripts) if urlparse(s).netloc.lower() in hosts]
    for s in scripts[:8]:
        try:
            js_paths |= mine_js(ctx.get(s).text[:3_000_000])
        except requests.RequestException:
            pass
    rep["js_auth"] = sorted(p for p in js_paths if AUTH_RE.search(p))[:40]


def identify_blocker(headers: dict, body: str):
    for h, name in BLOCKER_HEADERS.items():
        if h in headers:
            return name, True
    for pat, name in BLOCKER_BODY:
        if re.search(pat, body, re.I):
            return name, True
    server = headers.get("server", "").lower()
    for key, name in SERVER_BLOCKERS:
        if key in server:
            return name, False
    return "", False


def check_methods(ctx: Ctx, url: str, rep: dict):
    p = urlparse(url)
    host, scheme = p.hostname, p.scheme
    port = p.port or (443 if scheme == "https" else 80)
    path = p.path or "/"
    for meth in ("TRACE", "DEBUG"):
        curl = f"curl -sk -X {meth} -o /dev/null -w '%{{http_code}}\\n' {shq(url)}"
        try:
            st, hd, body = ctx.raw(host, port, scheme, p.netloc, sni=host, path=path, method=meth)
            echoed = meth == "TRACE" and ("trace" in body.lower() or "user-agent" in body.lower())
            if meth == "TRACE" and st and st < 300 and echoed:
                sev, verd = SEV_MED, t("v_trace_on", st=st)
            elif st and st < 300:
                sev, verd = SEV_LOW, t("v_method_ok", m=meth, st=st)
            else:
                sev, verd = SEV_OK, t("v_method_block", m=meth, st=st or "reset")
        except (requests.RequestException, urllib3.exceptions.HTTPError, OSError) as e:
            sev, verd = SEV_OK, t("v_method_block", m=meth, st=type(e).__name__)
        rep["server_tests"].append({"name": t("t_method", m=meth), "curl": curl,
                                    "sev": sev, "verdict": verd, "kind": "method"})


def check_waf(ctx: Ctx, url: str, rep: dict):
    check_methods(ctx, url, rep)
    base = rep["_base"]["status"]
    if base >= 400:
        rep["waf_state"] = "manual"
        extra = t("d_waf_front", v=rep["waf"]) if rep["waf"] else ""
        rep["waf_detail"] = t("d_waf_base", st=base) + extra
        return
    res = {}
    for key, params in WAF_PROBES:
        full = url + ("&" if "?" in url else "?") + urlencode(params, quote_via=quote)
        try:
            r = ctx.get(full)
            st, hd, body = r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.text[:200_000]
            blocked = st in BLOCK_CODES or (st >= 400 and bool(BLOCK_PAGE_SIGNS.search(body)))
            who, sure = identify_blocker(hd, body) if blocked else ("", False)
            tag = f" ({who})" if sure else (f" (¿{who}?)" if who else "")
            if blocked:
                text = t("w_blocked", st=st, who=tag)
            elif key == "ctl":
                text = t("w_ctl_ok", st=st)
            else:
                text = t("w_pass", st=st)
        except requests.RequestException as e:
            st, blocked, who, sure = None, True, "", False
            text = t("w_cut", err=type(e).__name__)
        res[key] = {"st": st, "blocked": blocked, "who": who, "sure": sure}
        rep["server_tests"].append({"name": t(f"t_waf_{key}"), "curl": curl_fmt(full),
                                    "sev": SEV_OK, "verdict": text, "kind": "waf"})

    ctl = res["ctl"]
    if ctl["blocked"]:
        rep["waf_state"], rep["waf_detail"] = "manual", t("d_waf_ctl", ctl=ctl["st"])
        return
    classes = {"xss": "XSS", "sqli": "SQLi", "lfi": "path traversal"}
    hits = [k for k in ("xss", "sqli", "lfi") if res[k]["blocked"]]
    blocked_names = ", ".join(classes[k] for k in hits)
    if not hits:
        rep["waf_state"] = "no"
        rep["waf_detail"] = t("d_waf_no_cdn", v=rep["waf"]) if rep["waf"] else t("d_waf_no")
        return
    rep["waf_state"] = "yes"
    sure = [res[k]["who"] for k in hits if res[k]["sure"]]
    guess = [res[k]["who"] for k in hits if res[k]["who"]] or ([rep["waf"]] if rep["waf"] else [])
    if sure:
        rep["waf_name"] = sure[0]
        rep["waf_detail"] = t("d_waf_yes", who=sure[0], classes=blocked_names)
    elif guess:
        rep["waf_name"] = guess[0]
        rep["waf_detail"] = t("d_waf_yes_guess", who=guess[0], classes=blocked_names)
    else:
        rep["waf_detail"] = t("d_waf_yes_unk", classes=blocked_names)


def check_server(ctx: Ctx, url: str, opts, rep: dict):
    p = urlparse(rep["final_url"] or url)
    host, scheme = p.hostname, p.scheme
    port = p.port or (443 if scheme == "https" else 80)
    path = p.path or "/"
    hosthdr = p.netloc
    rnd = f"rdcheck-{secrets.token_hex(4)}.invalid"
    tests = rep["server_tests"]

    def run(name, curl, fn):
        try:
            st, hd, body = fn()
            res = {"status": st, "headers": hd, "body": body, "error": ""}
        except Exception as e:
            res = {"status": None, "headers": {}, "body": "", "error": type(e).__name__}
        res.update(name=name, curl=curl)
        tests.append(res)
        return res

    def verdict(x, sev, text):
        x["sev"], x["verdict"] = sev, text

    ref = run(t("t_ref"), curl_fmt(f"{scheme}://{hosthdr}{path}"),
              lambda: ctx.raw(host, port, scheme, hosthdr, sni=host, path=path))
    ref_len = len(ref["body"])
    verdict(ref, SEV_OK, t("v_status", st=ref["status"]) if ref["status"]
            else t("v_error", err=ref["error"]))

    x = run(t("t_host"), curl_fmt(f"{scheme}://{hosthdr}{path}", f"-H 'Host: {rnd}'"),
            lambda: ctx.raw(host, port, scheme, rnd, sni=host, path=path))
    loc = x["headers"].get("location", "")
    st = x["status"]
    if not st:
        verdict(x, SEV_OK, t("v_host_refused", err=x["error"]))
    elif rnd in x["body"]:
        verdict(x, SEV_HIGH, t("v_host_reflect_body"))
    elif rnd in loc and 300 <= st < 400:
        verdict(x, SEV_MED, t("v_host_reflect_redirect", st=st))
    elif rnd in loc:
        verdict(x, SEV_MED, t("v_host_reflect_other"))
    elif st in (400, 403, 404, 409, 421) or st >= 500:
        verdict(x, SEV_OK, t("v_host_rejects", st=st))
    elif ref["status"] and st == ref["status"] and similar(len(x["body"]), ref_len):
        verdict(x, SEV_MED, t("v_host_any", st=st))
    else:
        verdict(x, SEV_LOW, t("v_host_default", st=st))
    x["kind"] = "host"

    x = run(t("t_xfh"), curl_fmt(f"{scheme}://{hosthdr}{path}", f"-H 'X-Forwarded-Host: {rnd}'",
                                 "-D -"),
            lambda: ctx.raw(host, port, scheme, hosthdr, sni=host, path=path,
                            extra={"X-Forwarded-Host": rnd}))
    if x["status"] and (rnd in x["headers"].get("location", "") or rnd in x["body"]):
        verdict(x, SEV_HIGH, t("v_xfh_reflect"))
    elif x["status"]:
        verdict(x, SEV_OK, t("v_xfh_ok", st=x["status"]))
    else:
        verdict(x, SEV_OK, t("v_error", err=x["error"]))
    x["kind"] = "host"

    try:
        ips = sorted({ai[4][0] for ai in socket.getaddrinfo(host, port,
                                                            socket.AF_UNSPEC, socket.SOCK_STREAM)})
    except socket.gaierror:
        ips = []
    rep["ips"] = ", ".join(ips)
    if ips:
        ip = ips[0]
        v6 = ":" in ip
        hostpart = f"[{ip}]" if v6 else ip
        ipport = hostpart if port in (80, 443) else f"{hostpart}:{port}"
        x = run(t("t_ip", ip=ip), curl_fmt(f"{scheme}://{ipport}{path}"),
                lambda: ctx.raw(ip, port, scheme, ip, sni=None, path=path))
        st = x["status"]
        if not st:
            verdict(x, SEV_OK, t("v_ip_tls") if "SSL" in x["error"]
                    else t("v_ip_noresp", err=x["error"]))
        elif BLOCK_PAGE_SIGNS.search(x["body"]) or st in (400, 403, 409, 421):
            verdict(x, SEV_OK, t("v_ip_blocked", st=st))
        elif ref["status"] and st == ref["status"] and similar(len(x["body"]), ref_len):
            verdict(x, SEV_MED, t("v_ip_serves", st=st) if rep["waf"]
                    else t("v_ip_serves_nocdn", st=st))
        else:
            verdict(x, SEV_LOW, t("v_ip_default", st=st))
        x["kind"] = "ip"

    if scheme == "https":
        x = run(t("t_http"), "curl -s -o /dev/null -w '%{http_code} %{redirect_url}\\n' "
                             f"'http://{host}{path}'",
                lambda: ctx.raw(host, 80, "http", host, path=path))
        loc = x["headers"].get("location", "")
        if not x["status"]:
            verdict(x, SEV_OK, t("v_http_closed", err=x["error"]))
        elif x["status"] in (301, 302, 307, 308) and loc.lower().startswith("https://"):
            verdict(x, SEV_OK, t("v_http_redirect", st=x["status"], loc=loc[:60]))
        else:
            verdict(x, SEV_MED, t("v_http_plain", st=x["status"]))
        x["kind"] = "https"

    if opts.origin:
        o = opts.origin
        x = run(t("t_origin", ip=o),
                curl_fmt(f"{scheme}://{hosthdr}{path}", f"--resolve '{host}:{port}:{o}'"),
                lambda: ctx.raw(o, port, scheme, hosthdr, sni=host, path=path))
        if not x["status"]:
            verdict(x, SEV_OK, t("v_origin_noresp", err=x["error"]))
        elif ref["status"] and x["status"] == ref["status"] and similar(len(x["body"]), ref_len):
            verdict(x, SEV_HIGH, t("v_origin_bypass"))
        else:
            verdict(x, SEV_LOW, t("v_origin_diff", st=x["status"]))
        x["kind"] = "origin"

    x = run(t("t_options"), f"curl -sk -X OPTIONS -D - -o /dev/null '{scheme}://{hosthdr}{path}'",
            lambda: ctx.raw(host, port, scheme, hosthdr, sni=host, path=path, method="OPTIONS"))
    allow = x["headers"].get("allow", "") or x["headers"].get("access-control-allow-methods", "")
    methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
    rep["options_methods"] = methods
    risky = [m for m in methods if m in ("PUT", "DELETE", "PATCH", "TRACE", "CONNECT")]
    rep["options_risky"] = risky
    if not x["status"]:
        rep["options_state"] = "na"
        verdict(x, SEV_OK, t("v_error", err=x["error"]))
    elif not methods:
        rep["options_state"] = "na"
        verdict(x, SEV_OK, t("v_opt_none", st=x["status"]))
    elif risky:
        rep["options_state"] = "review"
        verdict(x, SEV_MED, t("v_opt_risky", v=", ".join(methods), r=", ".join(risky)))
    else:
        rep["options_state"] = "ok"
        verdict(x, SEV_OK, t("v_opt_ok", v=", ".join(methods)))
    x["kind"] = "options"

    for x in tests:
        for k in ("body", "headers", "status", "error"):
            x.pop(k, None)


TLS_RANK = {"SSLv2": 0, "SSLv3": 1, "TLSv1": 2, "TLSv1.1": 3, "TLSv1.2": 4, "TLSv1.3": 5}


def tls_is_weak(proto: str) -> bool:
    return bool(proto) and TLS_RANK.get(proto, 99) < TLS_RANK["TLSv1.2"]


def _tls_ctx(verify: bool, legacy_only: bool = False) -> ssl.SSLContext:
    """Contexto que permite negociar versiones antiguas para poder DETECTARLAS
    (el contexto por defecto de Python exige TLS 1.2 y las ocultaría como error)."""
    c = ssl.create_default_context() if verify else ssl._create_unverified_context()
    # Python marca TLS 1.0/1.1 como obsoletos y emite DeprecationWarning al usarlos;
    # aquí se usan a propósito para detectar servidores que aún los aceptan.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            c.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            if legacy_only:
                c.maximum_version = ssl.TLSVersion.TLSv1_1
        except (ValueError, AttributeError):
            pass
    try:
        c.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return c


def _handshake(host: str, port: int, to, c: ssl.SSLContext):
    with socket.create_connection((host, port), timeout=to) as sock:
        with c.wrap_socket(sock, server_hostname=host) as ss:
            return ss.version(), ss.getpeercert()


def check_tls(host: str, port: int, timeout, rep: dict):
    to = timeout[0] if isinstance(timeout, (tuple, list)) else timeout
    try:
        proto, cert = _handshake(host, port, to, _tls_ctx(verify=True))
        rep["tls_proto"] = proto
        rep["tls_valid"] = True
        not_after = cert.get("notAfter", "")
        rep["tls_issuer"] = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "")
        if not_after:
            secs = ssl.cert_time_to_seconds(not_after)
            rep["tls_days"] = int((secs - time.time()) / 86400)
            rep["tls_expires"] = datetime.fromtimestamp(secs, tz=timezone.utc).strftime("%Y-%m-%d")
    except ssl.SSLCertVerificationError as e:
        rep["tls_valid"] = False
        rep["tls_reason"] = getattr(e, "verify_message", "") or str(e).split("(")[0].strip()
        # 10 = X509_V_ERR_CERT_HAS_EXPIRED
        rep["tls_expired"] = getattr(e, "verify_code", None) == 10 or \
            "expired" in rep["tls_reason"].lower()
        try:
            rep["tls_proto"], _ = _handshake(host, port, to, _tls_ctx(verify=False))
        except (ssl.SSLError, OSError):
            pass
    except (ssl.SSLError, OSError) as e:
        rep["tls_error"] = type(e).__name__
        return

    # ¿Acepta además TLS 1.0/1.1 aunque negocie 1.2+ con clientes modernos?
    if not tls_is_weak(rep["tls_proto"]):
        try:
            legacy, _ = _handshake(host, port, to,
                                   _tls_ctx(verify=False, legacy_only=True))
            if tls_is_weak(legacy):
                rep["tls_legacy"] = legacy
        except (ssl.SSLError, OSError, ValueError):
            pass


def burst_test(url: str, n: int, timeout: int, workers: int, verify: bool = False) -> dict:
    hdr = {"User-Agent": UA}
    try:
        _RATE.wait()
        r0 = requests.get(url, timeout=timeout, headers=hdr, allow_redirects=False, verify=verify)
    except requests.RequestException as e:
        return {"state": "inconclusive", "detail": t("b_noresp", err=type(e).__name__)}
    if r0.status_code == 429:
        return {"state": "enforced", "detail": t("b_429_first")}
    if r0.status_code == 403:
        return {"state": "inconclusive", "detail": t("b_403_first")}

    def one(i):
        try:
            _RATE.wait()
            r = requests.get(url, timeout=timeout, headers=hdr, allow_redirects=False,
                             verify=verify)
            rem = r.headers.get("x-ratelimit-remaining") or r.headers.get("ratelimit-remaining")
            return i, r.status_code, (rem or "").strip()
        except requests.RequestException:
            return i, None, ""

    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        out = sorted(ex.map(one, range(2, n + 1)))
    secs = time.monotonic() - t0
    counts = Counter("error" if st is None else st for _, st, _ in out)
    counts[r0.status_code] += 1
    summ = ", ".join(f"{k}×{v}" for k, v in sorted(counts.items(), key=str))
    for i, st, rem in out:
        if st in (429, 503) or (st == 403 and r0.status_code != 403) or rem == "0":
            why = "remaining=0" if rem == "0" else f"HTTP {st}"
            return {"state": "enforced", "detail": t("b_hit", why=why, i=i, n=n, s=secs, summ=summ)}
    if counts["error"] > n // 4:
        return {"state": "enforced", "detail": t("b_cut", n=n, s=secs, summ=summ)}
    return {"state": "not_observed", "detail": t("b_none", n=n, s=secs, summ=summ)}


def verdicts(rep: dict) -> list:
    v = []
    if rep["burst_state"] == "enforced":
        v.append(("c_rl", "yes", rep["burst"]))
    elif rep["rl_headers"]:
        v.append(("c_rl", "yes", t("d_rl_headers", v=rep["rl_headers"])))
    elif rep["got_429"]:
        v.append(("c_rl", "yes", t("d_rl_429")))
    elif rep["burst_state"] == "not_observed":
        v.append(("c_rl", "no", rep["burst"]))
    else:
        v.append(("c_rl", "no", t("d_rl_none")))
    where = []
    if rep["captcha"]:
        where.append(t("d_captcha_where", v=rep["captcha"], where=t("w_home")))
    for lg in rep["logins"]:
        if lg["captcha"] and not rep["captcha"]:
            where.append(t("d_captcha_where", v=lg["captcha"], where=t("w_login")))
    v.append(("c_captcha", "yes" if where else "no", "; ".join(where) or t("d_none")))
    if rep["waf_state"]:
        v.append(("c_waf", rep["waf_state"], rep["waf_detail"]))
    else:
        v.append(("c_waf", "na", t("d_not_tested")))
    present = [n for n, ok, _ in rep["sec_headers"] if ok]
    det = ", ".join(present) or t("d_sec_none")
    if rep["obsolete_headers"]:
        det += " — " + t("d_sec_obsolete", v=", ".join(n for n, _ in rep["obsolete_headers"]))
    v.append(("c_sechead", f"{rep['sec_count']}/6", det))
    lines = " · ".join(rep["banner_lines"])
    if rep["banner_state"] == "version":
        v.append(("c_banner", "bannerver", lines))
    elif rep["banner_state"] == "banner":
        v.append(("c_banner", "banneronly", t("d_banner_nover", v=lines)))
    else:
        v.append(("c_banner", "nobanner", t("d_none")))
    if rep["options_state"] == "review":
        v.append(("c_options", "review", t("v_opt_risky", v=", ".join(rep["options_methods"]),
                                           r=", ".join(rep["options_risky"]))))
    elif rep["options_state"] == "ok":
        v.append(("c_options", "ok", ", ".join(rep["options_methods"])))
    elif rep["options_state"] == "na":
        v.append(("c_options", "na", t("d_opt_none")))
    if rep["proxy_names"]:
        v.append(("c_proxy", "yes", ", ".join(rep["proxy_names"]) + " — "
                  + "; ".join(rep["proxy_evidence"][:4])))
    else:
        v.append(("c_proxy", "no", t("d_none")))
    si = rep["shared_ip"]
    if si:
        tag = t("origin_tag") if si.get("origin") else ""
        if si.get("cdn"):
            v.append(("c_shared", "na", t("d_shared_behindcdn", ip=si["ip"])))
        elif si.get("error"):
            v.append(("c_shared", "na", t("d_shared_err", ip=si["ip"], e=si["error"])))
        else:
            doms = [d for d in si.get("domains", []) if d]
            n = len(doms)
            if n > 1:
                sample = ", ".join(doms[:6]) + (f" (+{n - 6})" if n > 6 else "")
                v.append(("c_shared", t("d_shared_many", ip=si["ip"] + tag, n=n), sample))
            else:
                v.append(("c_shared", t("d_shared_one", ip=si["ip"] + tag), ""))
    if rep["logins"]:
        lg = rep["logins"][0]
        v.append(("c_login", "yes", t("d_login", url=lg["url"], submit=lg["submit"])))
    elif rep["login_other_hosts"]:
        v.append(("c_login", "na", t("d_login_other", v=rep["login_other_hosts"])))
    else:
        v.append(("c_login", "no", t("d_login_none")))
    tests = rep["server_tests"]
    host_t = [x for x in tests if x.get("kind") == "host"]
    if not tests:
        v.append(("c_host", "na", t("d_not_tested")))
    else:
        worst = min(host_t, key=lambda x: SEV_ORDER[x["sev"]]) if host_t else None
        if worst and worst["sev"] == SEV_HIGH:
            v.append(("c_host", "vuln", f"{worst['name']}: {worst['verdict']}"))
        elif worst and worst["sev"] == SEV_MED:
            v.append(("c_host", "review", f"{worst['name']}: {worst['verdict']}"))
        else:
            v.append(("c_host", "ok", t("d_host_ok")))
    https_t = [x for x in tests if x.get("kind") == "https"]
    if https_t:
        x = https_t[0]
        v.append(("c_https", "no" if x["sev"] == SEV_MED else "yes", x["verdict"]))
    if rep["tls_valid"] is not None or rep["tls_error"]:
        proto = rep["tls_proto"] or "?"
        weak = tls_is_weak(rep["tls_proto"])
        legacy = rep.get("tls_legacy", "")
        if rep["tls_error"]:
            v.append(("c_tls", "na", t("d_tls_error", err=rep["tls_error"])))
        elif rep.get("tls_expired") or (rep["tls_days"] is not None and rep["tls_days"] < 0):
            v.append(("c_tls", "vuln", t("d_tls_expired", p=proto)))
        elif not rep["tls_valid"]:
            v.append(("c_tls", "vuln", t("d_tls_invalid", why=rep["tls_reason"] or "?", p=proto)))
        elif weak or legacy or (rep["tls_days"] is not None and rep["tls_days"] < 21):
            parts = []
            if weak:
                parts.append(t("d_tls_weak", p=proto))
            elif legacy:
                parts.append(t("d_tls_legacy", p=legacy))
            if rep["tls_days"] is not None and rep["tls_days"] < 21:
                soon = t("d_tls_soon", d=rep["tls_days"])
                if rep.get("tls_expires"):
                    soon += f" ({rep['tls_expires']})"
                parts.append(soon)
            v.append(("c_tls", "review", "; ".join(parts)))
        else:
            det = t("d_tls_ok", p=proto, iss=rep["tls_issuer"] or "?")
            if rep.get("tls_expires"):
                det += " — " + t("d_tls_exp", date=rep["tls_expires"],
                                 d=rep["tls_days"] if rep["tls_days"] is not None else "?")
            v.append(("c_tls", "ok", det))
    org = [x for x in tests if x.get("kind") == "origin"]
    if org:
        v.append(("c_origin", "exposed" if org[0]["sev"] == SEV_HIGH else "protected",
                  org[0]["verdict"]))
    return v


def findings(rep: dict) -> list:
    f = []
    waf_on = rep["waf_state"] == "yes"
    if rep["waf_state"] == "no":
        f.append((SEV_MED, t("f_waf_noblock", v=rep["waf"]) if rep["waf"] else t("f_no_waf")))
    if rep["tls_valid"] is False:
        if rep.get("tls_expired"):
            f.append((SEV_HIGH, t("f_tls_invalid", why=t("expired"))))
        else:
            f.append((SEV_HIGH, t("f_tls_invalid", why=rep["tls_reason"] or "?")))
    if rep["tls_valid"] is not None:
        if tls_is_weak(rep["tls_proto"]):
            f.append((SEV_MED, t("f_tls_weak", p=rep["tls_proto"])))
        elif rep.get("tls_legacy"):
            f.append((SEV_MED, t("f_tls_legacy", p=rep["tls_legacy"])))
    if rep["tls_valid"]:
        if rep["tls_days"] is not None and 0 <= rep["tls_days"] < 21:
            f.append((SEV_MED, t("f_tls_soon", d=rep["tls_days"])))
    for lg in rep["logins"]:
        confirmed = rep["burst_url"] == lg["url"] and rep["burst_state"] == "enforced"
        if not lg["captcha"] and not lg["rl_headers"] and not confirmed:
            f.append((SEV_MED if waf_on else SEV_HIGH,
                      t("f_login_unprot", url=lg["url"], submit=lg["submit"])
                      + ("" if rep["burst"] else t("f_confirm"))))
    if rep["burst_state"] == "not_observed":
        f.append((SEV_HIGH if rep["logins"] else SEV_MED,
                  t("f_burst", url=rep["burst_url"], d=rep["burst"])))
    for x in rep["server_tests"]:
        if x["sev"] in (SEV_HIGH, SEV_MED):
            f.append((x["sev"], f"{x['name']}: {x['verdict']}"))
    if rep["sec_count"] < 4:
        missing = [n for n, ok, _ in rep["sec_headers"] if not ok]
        f.append((SEV_MED, t("f_sechead", n=rep["sec_count"], v=", ".join(missing))))
    if rep["banner_versions"]:
        f.append((SEV_MED, t("f_banner", v=", ".join(rep["banner_versions"]))))
    if rep["obsolete_headers"]:
        f.append((SEV_LOW, t("f_obsolete",
                             v=", ".join(n for n, _ in rep["obsolete_headers"]))))
    if rep["options_risky"]:
        f.append((SEV_MED, t("f_options", r=", ".join(rep["options_risky"]))))
    if not rep["rl_headers"] and not rep["burst"] and not rep["got_429"]:
        f.append((SEV_LOW, t("f_no_rl")))
    if rep["login_other_hosts"]:
        f.append((SEV_LOW, t("f_other_host", v=rep["login_other_hosts"])))
    if rep["dns_a"] and not rep["dns_error"]:
        if not rep["spf"]:
            f.append((SEV_LOW, t("f_no_spf")))
        if not rep["dmarc"]:
            f.append((SEV_LOW, t("f_no_dmarc")))
        elif rep["dmarc"] == "none":
            f.append((SEV_MED, t("f_dmarc_none")))
    return sorted(f, key=lambda x: SEV_ORDER[x[0]])


def check_headers(ctx: Ctx, rep: dict):
    base = next((x for x in ctx.seen if x[0] == "base"), None)
    base_h = {k: v for k, v in (base[2] if base else [])}

    sec = [(name, k in base_h, base_h.get(k, "")) for k, name in SECURITY_HEADERS]
    rep["sec_headers"] = sec
    rep["sec_count"] = sum(1 for _, ok, _ in sec if ok)
    rep["obsolete_headers"] = [(name, base_h[k]) for k, name in OBSOLETE_HEADERS if k in base_h]

    groups = {}
    for _, _, hdrs, _ in ctx.seen:
        for k, v in hdrs:
            if k in BANNER_HEADERS and v.strip():
                lst = groups.setdefault(k, [])
                if v.strip() not in lst:
                    lst.append(v.strip())
    if base:
        m = META_GENERATOR.search(base[3])
        if m:
            groups.setdefault("meta generator", []).append(m.group(1).strip())
    for tag, st, _, body in ctx.seen:
        if st and st >= 400:
            for m in ERROR_PAGE_BANNER.finditer(body[:20_000]):
                lst = groups.setdefault("error page", [])
                if m.group(0) not in lst:
                    lst.append(m.group(0).strip())
    rep["banner_lines"] = [", ".join(f"{k}: {v}" for v in vals) for k, vals in groups.items()]
    rep["banner_versions"] = [f"{k}: {v}" for k, vals in groups.items() for v in vals
                              if VERSION_RE.search(v)]
    if rep["banner_versions"]:
        rep["banner_state"] = "version"
    elif groups:
        rep["banner_state"] = "banner"
    else:
        rep["banner_state"] = "none"

    names, ev = [], []
    servers = []
    for _, _, hdrs, _ in ctx.seen:
        for k, v in hdrs:
            if k in PROXY_HEADERS:
                n = PROXY_HEADERS[k]
                if n not in names:
                    names.append(n)
                    ev.append(f"{k}: {v[:40]}")
            elif k == "via":
                e = t("d_proxy_via", v=v[:40])
                if e not in ev:
                    ev.append(e)
                    n = next((n for key, n in PROXY_SERVERS if key in v.lower()), "proxy (Via)")
                    if n not in names:
                        names.append(n)
            if k == "server" and v.strip() and v.strip() not in servers:
                servers.append(v.strip())
    for sv in servers:
        for key, n in PROXY_SERVERS:
            if key in sv.lower() and n not in names:
                names.append(n)
                ev.append(f"server: {sv}")
    prods = {re.split(r"[/\s]", sv.lower())[0] for sv in servers}
    for line in groups.get("error page", []):
        prod = re.split(r"[/\s]", line.lower())[0]
        if prod not in prods:
            prods.add(prod)
            servers.append(f"{line} (error page)")
    if len(prods) > 1:
        ev.append(t("d_proxy_server_diff", v=" / ".join(servers)))
        if not names:
            names.append("proxy")
    rep["proxy_names"], rep["proxy_evidence"] = names, ev


DNS_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}
TXT_MAX_ROWS = 60
CDN_ASN_HINTS = ["cloudflare", "cloudfront", "fastly", "akamai", "incapsula", "imperva",
                 "sucuri", "stackpath", "bunny", "cdn77", "edgecast", "cachefly", "limelight",
                 "keycdn", "azure front door", "azurefd", "section.io", "gcore", "g-core"]

SPF_PROVIDERS = [
    ("_spf.google.com", "Google Workspace"), ("spf.protection.outlook.com", "Microsoft 365"),
    ("amazonses.com", "Amazon SES"), ("sendgrid.net", "SendGrid"), ("mailgun.org", "Mailgun"),
    ("spf.mandrillapp.com", "Mailchimp/Mandrill"), ("servers.mcsv.net", "Mailchimp"),
    ("_spf.salesforce.com", "Salesforce"), ("zoho", "Zoho"), ("sparkpostmail.com", "SparkPost"),
    ("_spf.mailjet.com", "Mailjet"), ("mailanyone.net", "Mail Anyone"), ("pphosted.com", "Proofpoint"),
    ("mimecast.com", "Mimecast"), ("_spf.qq.com", "Tencent QQ"),
]


VERIF_RE = re.compile(
    r"^([a-z][a-z0-9]*(?:[-_][a-z0-9]+)*?)[-_]?"
    r"(?:domain[-_]?verification|site[-_]?verification|site[-_]?validation|"
    r"domain[-_]?verify|verification[-_]?code|verification|verify)\b", re.I)
KNOWN_TXT_EQ = {
    "ms": "Microsoft 365", "amazonses": "Amazon SES", "mgverify": "Mailgun",
    "docusign": "DocuSign", "pardot": "Salesforce Pardot", "sending_domain": "Salesforce Pardot",
    "adobe-sign": "Adobe Sign", "stripe": "Stripe",
}
TXT_NICE = {
    "google": "Google", "facebook": "Facebook", "apple": "Apple", "openai": "OpenAI",
    "anthropic": "Anthropic", "atlassian": "Atlassian", "mongodb": "MongoDB", "figma": "Figma",
    "notion": "Notion", "airtable": "Airtable", "docker": "Docker", "cisco": "Cisco",
    "cisco-ci": "Cisco", "adobe": "Adobe", "adobe-idp": "Adobe", "paloaltonetworks": "Palo Alto",
    "globalsign": "GlobalSign", "onetrust": "OneTrust", "dynatrace": "Dynatrace",
    "mixpanel": "Mixpanel", "smartsheet": "Smartsheet", "monday-com": "Monday.com",
    "monday": "Monday.com", "unity": "Unity", "unity-sso": "Unity", "nulab": "Nulab",
    "sinch": "Sinch",
    "hcp": "HashiCorp", "hpe-greenlake": "HPE GreenLake", "mistral": "Mistral",
    "cursor": "Cursor", "heygen": "HeyGen", "lucidlink": "LucidLink", "remarkable": "reMarkable",
    "extensis": "Extensis", "bettercomp": "BetterComp", "clayton": "Clayton", "profound": "Profound",
    "mgverify": "Mailgun",
}


def txt_vendor(raw: str) -> str:
    s = raw.strip()
    low = s.lower()
    if low.startswith("v=spf1"):
        return "SPF"
    if low.startswith("v=dmarc1"):
        return "DMARC"
    if low.startswith("v=dkim1") or low.startswith("k=rsa"):
        return "DKIM"
    m = VERIF_RE.match(s)
    if m:
        token = m.group(1).lower().rstrip("-_")
        if len(token) >= 3:
            return TXT_NICE.get(token) or KNOWN_TXT_EQ.get(token) or token
    head = re.split(r"[=:]", s, 1)[0].lower()
    base = re.sub(r"\d+$", "", head)
    if base in KNOWN_TXT_EQ:
        return KNOWN_TXT_EQ[base]
    return ""


def short_txt(s: str) -> str:
    for sep in ("=", ":"):
        if sep in s:
            k, v = s.split(sep, 1)
            return f"{k}{sep}{v[:3]}..." if len(v) > 3 else s
    return s[:3] + "..." if len(s) > 3 else s


def parse_txt_verifications(txts: list) -> list:
    found = {}
    for raw in txts:
        v = txt_vendor(raw)
        if v and v not in ("SPF", "DMARC", "DKIM"):
            found[v] = True
    return sorted(found)


class DNSError(OSError):
    pass


def _parse_name(msg: bytes, off: int):
    labels, jumped, start_off, hops = [], False, off, 0
    while True:
        if off >= len(msg):
            raise DNSError("nombre DNS truncado")
        length = msg[off]
        if length & 0xC0 == 0xC0:
            hops += 1
            if hops > 32 or off + 1 >= len(msg):
                raise DNSError("bucle de punteros DNS")
            ptr = struct.unpack(">H", msg[off:off + 2])[0] & 0x3FFF
            if not jumped:
                start_off = off + 2
            off, jumped = ptr, True
            continue
        off += 1
        if length == 0:
            break
        labels.append(msg[off:off + length].decode("latin-1"))
        off += length
    return ".".join(labels), (start_off if jumped else off)


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise DNSError("conexión DNS cerrada")
        buf += chunk
    return buf


def dns_query(name: str, qtype: str, resolver: str, timeout: float, tcp: bool = False) -> list:
    qt = DNS_TYPES[qtype]
    qid = os.urandom(2)
    question = (b"".join(bytes([len(p)]) + p.encode() for p in name.rstrip(".").split(".") if p)
                + b"\x00" + struct.pack(">HH", qt, 1))
    opt = b"\x00" + struct.pack(">HHIH", 41, 4096, 0, 0)
    msg = qid + b"\x01\x00" + b"\x00\x01" + b"\x00\x00" * 2 + b"\x00\x01" + question + opt
    family = socket.AF_INET6 if ":" in resolver else socket.AF_INET
    if tcp:
        s = socket.create_connection((resolver, 53), timeout=timeout)
        try:
            s.sendall(struct.pack(">H", len(msg)) + msg)
            ln = struct.unpack(">H", _recv_exact(s, 2))[0]
            data = _recv_exact(s, ln)
        finally:
            s.close()
    else:
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(msg, (resolver, 53))
            deadline = time.monotonic() + timeout
            while True:
                data, _ = s.recvfrom(65535)
                if data[:2] == qid:
                    break
                if time.monotonic() > deadline:
                    raise socket.timeout()
        finally:
            s.close()
        if len(data) >= 3 and data[2] & 0x02:
            return dns_query(name, qtype, resolver, timeout, tcp=True)
    if len(data) < 12 or data[:2] != qid or not data[2] & 0x80:
        raise DNSError("respuesta DNS no válida")
    rcode = data[3] & 0x0F
    if rcode == 3:
        return []
    if rcode != 0:
        raise DNSError(f"rcode {rcode}")
    qdcount, ancount = struct.unpack(">HH", data[4:8])
    off = 12
    for _ in range(qdcount):
        _, off = _parse_name(data, off)
        off += 4
    out = []
    for _ in range(ancount):
        _, off = _parse_name(data, off)
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        if rtype == qt == 16:
            txt, i = "", 0
            while i < len(rdata):
                ln = rdata[i]
                txt += rdata[i + 1:i + 1 + ln].decode("latin-1")
                i += 1 + ln
            out.append(txt)
        elif rtype == qt == 15:
            pref = struct.unpack(">H", rdata[:2])[0]
            host, _ = _parse_name(data, off + 2)
            out.append(f"{pref} {host}")
        elif rtype == qt in (2, 5):
            host, _ = _parse_name(data, off)
            out.append(host)
        elif rtype == qt == 1 and rdlen == 4:
            out.append(".".join(str(b) for b in rdata))
        elif rtype == qt == 28 and rdlen == 16:
            out.append(socket.inet_ntop(socket.AF_INET6, rdata))
        off += rdlen
    return out


def rdap_ip(ip: str, timeout) -> dict:
    to = timeout[1] if isinstance(timeout, (tuple, list)) else timeout
    try:
        r = requests.get(f"https://rdap.org/ip/{ip}", timeout=to,
                         headers={"User-Agent": UA, "Accept": "application/rdap+json"})
        if r.status_code != 200:
            return {}
        d = r.json()
    except (requests.RequestException, ValueError):
        return {}
    cidr = ""
    for c in d.get("cidr0_cidrs", []) or []:
        pref = c.get("v4prefix") or c.get("v6prefix")
        if pref:
            cidr = f"{pref}/{c.get('length')}"
            break
    if not cidr and d.get("startAddress") and d.get("endAddress"):
        cidr = f"{d['startAddress']} - {d['endAddress']}"
    org = d.get("name", "")
    owner = ""
    for ent in d.get("entities", []) or []:
        roles = ent.get("roles", []) or []
        if ("registrant" in roles or "administrative" in roles) and not owner:
            owner = ent.get("handle", "")
        for item in (ent.get("vcardArray", [None, []])[1] or []):
            if item and item[0] == "fn" and len(item) > 3 and not org:
                org = item[3]
    blob = (d.get("port43", "") + " " + " ".join(
        l.get("href", "") for l in d.get("links", []) or [])).lower()
    rir = ""
    for key, name in (("arin", "ARIN"), ("ripe", "RIPE"), ("apnic", "APNIC"),
                      ("lacnic", "LACNIC"), ("afrinic", "AFRINIC")):
        if key in blob:
            rir = name
            break
    return {"cidr": cidr, "org": org, "handle": d.get("handle", ""), "owner": owner,
            "rir": rir, "country": d.get("country", "")}


def reverse_ip(ip: str, timeout) -> dict:
    to = timeout[1] if isinstance(timeout, (tuple, list)) else timeout
    try:
        r = requests.get("https://api.hackertarget.com/reverseiplookup/", params={"q": ip},
                         timeout=to, headers={"User-Agent": UA})
    except requests.RequestException as e:
        return {"error": type(e).__name__}
    text = (r.text or "").strip()
    low = text.lower()
    if r.status_code != 200 or "api count exceeded" in low or "api limit" in low:
        return {"error": t("api_limit") if "exceeded" in low or "limit" in low else t("no_data")}
    if "no records" in low or "no dns" in low or ("error" in low and len(text) < 60):
        return {"domains": []}
    domains = [ln.strip() for ln in text.splitlines() if ln.strip() and "." in ln]
    return {"domains": sorted(set(domains))}


def cymru_asn(ip: str, resolver: str, to: float) -> dict:
    try:
        if ":" in ip:
            full = socket.inet_pton(socket.AF_INET6, ip).hex()
            qname = ".".join(reversed(full)) + ".origin6.asn.cymru.com"
        else:
            qname = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
        txts = dns_query(qname, "TXT", resolver, to)
    except (OSError, struct.error):
        return {}
    if not txts:
        return {}
    p = [x.strip() for x in txts[0].split("|")]
    asn = p[0].split()[0] if p and p[0] else ""
    return {"asn": asn, "prefix": p[1] if len(p) > 1 else "",
            "cc": p[2] if len(p) > 2 else "", "registry": p[3] if len(p) > 3 else ""}


def cymru_asname(asn: str, resolver: str, to: float, cache: dict) -> str:
    if not asn:
        return ""
    if asn in cache:
        return cache[asn]
    name = ""
    try:
        txts = dns_query(f"AS{asn}.asn.cymru.com", "TXT", resolver, to)
        if txts:
            p = [x.strip() for x in txts[0].split("|")]
            name = p[4] if len(p) > 4 else ""
    except (OSError, struct.error):
        pass
    cache[asn] = name
    return name


def _resolve_host(host: str, resolver: str, to: float) -> str:
    host = host.rstrip(".")
    try:
        a = dns_query(host, "A", resolver, to)
        return a[0] if a else ""
    except (OSError, struct.error):
        return ""


def enrich_ip(ip: str, host: str, resolver: str, to: float, cache: dict) -> dict:
    c = cymru_asn(ip, resolver, to) if ip else {}
    asn = c.get("asn", "")
    name = cymru_asname(asn, resolver, to, cache) if asn else ""
    asn_txt = (f"AS{asn} - {name}" if name else (f"AS{asn}" if asn else "-"))
    return {"host": host.rstrip("."), "ip": ip or "-", "prefix": c.get("prefix", "-") or "-",
            "asn": asn_txt, "cc": c.get("cc", "")}


def check_dns(host: str, opts, rep: dict):
    res, to = opts.resolver, min(opts.dns_timeout, 5)
    try:
        rep["dns_a"] = dns_query(host, "A", res, to)
    except (OSError, struct.error):
        rep["dns_error"] = True
        return
    for rt in ("AAAA", "NS", "MX", "TXT"):
        try:
            rep[f"dns_{rt.lower()}"] = dns_query(host, rt, res, to)
        except (OSError, struct.error):
            pass
    try:
        rep["dns_dmarc"] = dns_query(f"_dmarc.{host}", "TXT", res, to)
    except (OSError, struct.error):
        pass

    if not opts.no_asn:
        cache = {}
        rep["dns_rows"]["A"] = [enrich_ip(ip, "", res, to, cache) for ip in rep["dns_a"][:8]]
        rep["dns_rows"]["AAAA"] = [enrich_ip(ip, "", res, to, cache)
                                   for ip in rep["dns_aaaa"][:4]]
        for raw in rep["dns_mx"][:8]:
            parts = raw.split()
            mxhost = parts[-1] if parts else raw
            pref = parts[0] if len(parts) > 1 else ""
            ip = _resolve_host(mxhost, res, to)
            row = enrich_ip(ip, f"({pref}) {mxhost}" if pref else mxhost, res, to, cache)
            rep["dns_rows"]["MX"].append(row)
        for ns in rep["dns_ns"][:8]:
            ip = _resolve_host(ns, res, to)
            rep["dns_rows"]["NS"].append(enrich_ip(ip, ns, res, to, cache))

    for txt in rep["dns_txt"]:
        low = txt.lower()
        if low.startswith("v=spf1"):
            rep["spf"] = txt
            for frag, prov in SPF_PROVIDERS:
                if frag in low and prov not in rep["mail_providers"]:
                    rep["mail_providers"].append(prov)
    for txt in rep.get("dns_dmarc", []):
        if txt.lower().startswith("v=dmarc1"):
            m = re.search(r"\bp=(\w+)", txt)
            rep["dmarc"] = m.group(1) if m else "present"

    rep["txt_verifs"] = parse_txt_verifications(rep["dns_txt"])

    if rep["dns_a"] and not opts.no_rdap:
        rep["rdap"] = rdap_ip(rep["dns_a"][0], opts.timeout)

    if not opts.no_shared_ip:
        ip_for_reverse = opts.origin or ""
        if not ip_for_reverse and rep["dns_a"]:
            first = rep["dns_a"][0]
            org = (rep["rdap"].get("org", "") + " "
                   + (rep["dns_rows"]["A"][0]["asn"] if rep["dns_rows"]["A"] else "")).lower()
            if any(h in org for h in CDN_ASN_HINTS):
                rep["shared_ip"] = {"ip": first, "cdn": True}
            else:
                ip_for_reverse = first
        if ip_for_reverse:
            rep["shared_ip"] = {"ip": ip_for_reverse, "origin": bool(opts.origin),
                                **reverse_ip(ip_for_reverse, opts.timeout)}


def check_domain(url: str, opts) -> dict:
    rep = {"target": url, "status": "", "final_url": "", "captcha": "", "bot_js": "",
           "bot_cookies": "", "waf": "", "server_header": "", "rl_headers": "", "got_429": False,
           "waf_state": "", "waf_detail": "", "waf_name": "", "burst": "",
           "burst_state": "", "burst_url": "", "logins": [], "login_other_hosts": "",
           "js_auth": [], "ips": "", "server_tests": [], "evidence": [], "errors": [],
           "requests": 0, "verdicts": [], "findings": [], "sec_headers": [], "sec_count": 0,
           "banner_lines": [], "banner_state": "none", "banner_versions": [],
           "obsolete_headers": [], "options_methods": [], "options_risky": [],
           "options_state": "", "tls_valid": None, "tls_proto": "", "tls_days": None,
           "tls_issuer": "", "tls_reason": "", "tls_error": "", "tls_expires": "",
           "tls_expired": False, "tls_legacy": "",
           "dns_a": [], "dns_aaaa": [], "dns_ns": [], "dns_mx": [], "dns_txt": [],
           "dns_dmarc": [], "dns_error": False, "spf": "", "dmarc": "", "mail_providers": [],
           "txt_verifs": [], "rdap": {}, "dns_rows": {"A": [], "AAAA": [], "MX": [], "NS": []},
           "shared_ip": {},
           "proxy_names": [], "proxy_evidence": []}
    if not opts.no_dns:
        try:
            check_dns(urlparse(url).hostname, opts, rep)
        except Exception as e:
            LOG.debug("DNS error: %s", e)
    ctx = Ctx(opts.timeout, retries=opts.retries, verify=opts.verify_tls)
    try:
        check_code(ctx, url, opts, rep)
    except requests.RequestException as e:
        rep["errors"].append(type(e).__name__)
        rep["requests"] = ctx.n
        rep["findings"] = [(SEV_LOW, t("f_noresp", err=type(e).__name__))]
        rep["unreachable"] = True
        return rep
    pf = urlparse(rep["final_url"] or url)
    if pf.scheme == "https":
        check_tls(pf.hostname, pf.port or 443, opts.timeout, rep)
    if not opts.passive:
        check_server(ctx, url, opts, rep)
        check_waf(ctx, rep["final_url"] or url, rep)
    if opts.burst:
        target = rep["logins"][0]["url"] if rep["logins"] else (rep["final_url"] or url)
        b = burst_test(target, opts.burst, opts.timeout, opts.burst_workers, opts.verify_tls)
        ctx.n += opts.burst
        rep["burst_url"], rep["burst_state"], rep["burst"] = target, b["state"], b["detail"]
    check_headers(ctx, rep)
    rep.pop("_base", None)
    rep["requests"] = ctx.n
    rep["verdicts"] = verdicts(rep)
    rep["findings"] = findings(rep)
    return rep


VALUE_COLOR = {"yes": C.GREEN, "no": C.RED, "partial": C.YELLOW, "ok": C.GREEN,
               "manual": C.YELLOW,
               "vuln": C.RED, "review": C.YELLOW, "exposed": C.RED, "protected": C.GREEN,
               "nobanner": C.GREEN, "banneronly": C.YELLOW, "bannerver": C.RED,
               "na": C.DIM}
SEV_COLOR = {SEV_HIGH: C.RED, SEV_MED: C.YELLOW, SEV_LOW: C.DIM, SEV_OK: C.GREEN}


def cell(v, maxlen=None) -> str:
    if isinstance(v, bool):
        v = t("yes") if v else t("no")
    v = "-" if v in (None, "") else str(v)
    v = v.replace("\n", " ").replace("\r", " ").replace("|", "\\|")
    if maxlen and len(v) > maxlen:
        v = v[: maxlen - 1] + "…"
    return v


def table(headers, rows, colors=None, box=False) -> str:
    rows = [[cell(c) for c in r] for r in rows]
    w = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h)
         for i, h in enumerate(headers)]

    def line(cells, colored=None):
        parts = []
        for ci, c in enumerate(cells):
            txt = c.ljust(w[ci])
            col = (colored or {}).get(ci)
            parts.append(f"{col}{txt}{C.RESET}" if col else txt)
        bar = "│" if box else "|"
        return f"{bar} " + f" {bar} ".join(parts) + f" {bar}"

    if not box:
        out = ["| " + " | ".join(h.ljust(w[i]) for i, h in enumerate(headers)) + " |",
               "|" + "|".join("-" * (x + 2) for x in w) + "|"]
        for ri, r in enumerate(rows):
            out.append(line(r, {ci: col for (rr, ci), col in (colors or {}).items() if rr == ri}))
        return "\n".join(out)

    def rule(left, mid, right):
        return left + mid.join("─" * (x + 2) for x in w) + right

    hcol = {i: C.BOLD for i in range(len(headers))}
    out = [rule("┌", "┬", "┐"), line(list(headers), hcol), rule("├", "┼", "┤")]
    for ri, r in enumerate(rows):
        out.append(line(r, {ci: col for (rr, ci), col in (colors or {}).items() if rr == ri}))
    out.append(rule("└", "┴", "┘"))
    return "\n".join(out)


def tv(val: str) -> str:
    return t(val) if val in TEXTS else val


def value_color(val: str) -> str:
    m = re.match(r"(\d)/6$", val)
    if m:
        n = int(m.group(1))
        return C.GREEN if n >= 5 else C.YELLOW if n >= 3 else C.RED
    return VALUE_COLOR.get(val, "")


def verdict_table(rep, color=False, maxlen=None, box=False) -> str:
    info = f"HTTP {rep['status']}" + (f" · {rep['server_header']}" if rep["server_header"] else "")
    rows, colors = [[t("c_domain"), rep["target"], info]], {}
    for i, (k, val, det) in enumerate(rep["verdicts"], 1):
        rows.append([t(k), tv(val), cell(det, maxlen)])
        if color:
            colors[(i, 1)] = value_color(val)
    return table([t("h_control"), t("h_result"), t("h_detail")], rows, colors, box=box)


def summary_table(reps, color=False, box=False) -> str:
    keys = ["c_rl", "c_captcha", "c_waf", "c_login", "c_host", "c_https", "c_tls", "c_sechead",
            "c_banner", "c_options", "c_proxy"]
    if any(k == "c_origin" for r in reps for k, _, _ in r["verdicts"]):
        keys.append("c_origin")
    rows, colors = [], {}
    for ri, r in enumerate(sorted(reps, key=lambda x: x["target"])):
        vals = {k: val for k, val, _ in r["verdicts"]}
        row = [r["target"] + (f" ({t('k_unreach')})" if r.get("unreachable") else "")]
        for ci, k in enumerate(keys, 1):
            val = vals.get(k, "na")
            row.append(tv(val))
            if color:
                colors[(ri, ci)] = value_color(val)
        rows.append(row)
    return table([t("c_domain")] + [t(k) for k in keys], rows, colors, box=box)


def build_markdown(reps: list, source: str, opts) -> str:
    reps = sorted(reps, key=lambda r: r["target"])
    mode = "requests + Selenium" if opts.use_selenium else t("r_reqonly")
    L = [f"# {t('r_title')}\n", f"## {t('r_summary')}\n", summary_table(reps), ""]

    allf = [(s, r["target"], txt) for r in reps for s, txt in r["findings"]
            if s in (SEV_HIGH, SEV_MED)]
    if allf:
        L += [f"## {t('r_priority')}\n",
              table([t("h_sev"), t("c_domain"), t("h_finding")],
                    [[sev(s), d, x] for s, d, x in sorted(allf, key=lambda y: SEV_ORDER[y[0]])]), ""]

    for r in reps:
        info = [[t("i_final"), r["final_url"] or "-"], ["HTTP", r["status"] or "-"],
                ["Server", r["server_header"] or "-"],
                [t("i_cdn"), ", ".join(r["proxy_names"]) or t("d_none")],
                ["IP", r["ips"] or "-"], [t("h_requests"), r["requests"]]]
        if r["errors"]:
            info.append([t("r_errors"), "; ".join(r["errors"])])
        L += [f"## {r['target']}\n", table([t("h_field"), t("h_value")], info), ""]
        if r.get("unreachable"):
            L += [f"- {r['findings'][0][1]}", ""]
            continue
        L += [f"### {t('r_verdict')}\n", verdict_table(r), ""]
        sec_rows = [[n, ok, "`" + cell(val, 90).replace("`", "'") + "`" if val else "-"]
                    for n, ok, val in r["sec_headers"]]
        sec_rows += [[n + " (obsoleta)" if LANG == "es" else n + " (obsolete)", True,
                      "`" + cell(val, 90).replace("`", "'") + "`"] for n, val in r["obsolete_headers"]]
        L += [f"### {t('r_sechead')} ({r['sec_count']}/6)\n",
              table([t("h_header"), t("h_present"), t("h_value")], sec_rows), ""]
        if r["banner_lines"]:
            tag = tv(r["banner_state"] if r["banner_state"] != "none" else "nobanner")
            L += [f"### {t('r_banner')} — {tag}\n", "```"] + r["banner_lines"] + ["```", ""]
        if r["proxy_names"]:
            L += [f"### {t('r_proxy')}\n", f"**{', '.join(r['proxy_names'])}**\n"] + \
                 [f"- `{e}`" for e in r["proxy_evidence"]] + [""]
        if r["dns_a"] or r["dns_txt"] or r["rdap"]:
            L.append(f"### {t('r_dns')}\n")
            dt = dns_record_tables(r, full=True)
            if dt:
                for title, tbl in dt:
                    L += [f"**{title}**\n", tbl, ""]
            rows = []
            rd = r["rdap"]
            if rd.get("org") or rd.get("cidr"):
                prov = rd.get("org", "-") + (f" ({rd['country']})" if rd.get("country") else "")
                rows.append([t("dns_prov"), f"{prov} — {rd.get('cidr', '-')}"])
            reg = " / ".join(x for x in (rd.get("rir"), rd.get("owner"), rd.get("handle")) if x)
            if reg:
                rows.append([t("dns_reg"), reg])
            if not dt:
                for label, key in (("A", "dns_a"), ("AAAA", "dns_aaaa"), ("NS", "dns_ns"),
                                   ("MX", "dns_mx")):
                    if r[key]:
                        rows.append([label, ", ".join(r[key][:6])])
            if r["spf"]:
                rows.append(["SPF", r["spf"]])
            if r["mail_providers"]:
                rows.append(["Mail", ", ".join(r["mail_providers"])])
            if r["dmarc"]:
                rows.append(["DMARC", f"p={r['dmarc']}"])
            if r["txt_verifs"]:
                rows.append([t("dns_verifs"), ", ".join(r["txt_verifs"])])
            if rows:
                L += [table([t("dns_records"), t("h_value")],
                            [[a, "`" + cell(b, 120).replace("`", "'") + "`"] for a, b in rows]), ""]
        if r["evidence"]:
            L += [f"### {t('r_code')}\n",
                  table([t("h_source"), t("h_indicator"), t("h_evidence")],
                        [[a, b, "`" + cell(c, 140).replace("`", "'") + "`"]
                         for a, b, c in r["evidence"]]), ""]
        if r["logins"]:
            L += [f"### Login\n",
                  table([t("h_page"), t("h_submit"), "Captcha", "Rate limit", "MFA"],
                        [[l["url"], l["submit"], l["captcha"] or t("no"),
                          l["rl_headers"] or t("no"), l["mfa"]] for l in r["logins"]]), ""]
        if r["js_auth"]:
            L += [f"{t('r_js')}: " + ", ".join(f"`{p}`" for p in r["js_auth"]), ""]
        if r["server_tests"]:
            L += [f"### {t('r_server')}\n",
                  table([t("h_test"), t("h_result"), t("h_sev"), t("h_repro")],
                        [[x["name"], x["verdict"], sev(x["sev"]), f"`{x['curl']}`"]
                         for x in r["server_tests"]]), ""]
        if r["burst"]:
            L += [f"### {t('r_burst_sec')}\n", f"- **URL:** {r['burst_url']}",
                  f"- **{t('r_result')}:** {t('b_' + r['burst_state'])} — {r['burst']}", ""]
        L += [f"### {t('r_exec')}\n", executive_table(r), ""]
    return "\n".join(L).rstrip() + "\n"


def csv_rows(reps):
    for r in sorted(reps, key=lambda x: x["target"]):
        d = r["target"]
        info = f"HTTP {r['status']}" + (f" · {r['server_header']}" if r["server_header"] else "")
        if r.get("unreachable"):
            yield [d, t("c_domain"), d, r["findings"][0][1]]
            continue
        yield [d, t("c_domain"), d, info]
        for k, val, det in r["verdicts"]:
            yield [d, t(k), tv(val), det]
        for x in r["server_tests"]:
            if x["name"] != t("t_ref"):
                yield [d, x["name"], x["verdict"], ""]
        rows = r.get("dns_rows", {})
        for x in rows.get("A", []) + rows.get("AAAA", []):
            yield [d, "DNS A", x["ip"], f"{x['prefix']} · {x['asn']}"]
        for x in rows.get("MX", []):
            yield [d, "DNS MX", x["host"], f"{x['ip']} · {x['prefix']} · {x['asn']}"]
        for x in rows.get("NS", []):
            yield [d, "DNS NS", x["host"], f"{x['ip']} · {x['prefix']} · {x['asn']}"]
        si = r.get("shared_ip", {})
        for dom in si.get("domains", []):
            yield [d, t("c_shared"), si.get("ip", ""), dom]
        for txt in r.get("dns_txt", []):
            yield [d, "TXT", txt_vendor(txt) or "-", txt]


SARIF_LEVEL = {SEV_HIGH: "error", SEV_MED: "warning", SEV_LOW: "note"}


def worst_severity(reps) -> str:
    best = SEV_OK
    for r in reps:
        for s, _ in r["findings"]:
            if SEV_ORDER[s] < SEV_ORDER[best]:
                best = s
    return best


def build_sarif(reps: list) -> dict:
    rules, results = {}, []
    for r in reps:
        for s, txt in r["findings"]:
            rule_id = re.sub(r"[^a-z0-9]+", "-", txt.lower().split(":")[0])[:60] or "finding"
            rules.setdefault(rule_id, {"id": rule_id,
                                       "shortDescription": {"text": txt.split(":")[0][:120]},
                                       "defaultConfiguration": {"level": SARIF_LEVEL[s]}})
            results.append({
                "ruleId": rule_id, "level": SARIF_LEVEL[s],
                "message": {"text": txt},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": r["target"]}}}],
                "properties": {"severity": s},
            })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "rd-check", "version": __version__,
                                          "rules": list(rules.values())}},
                      "results": results}]}


def build_html(reps: list, source: str, opts) -> str:
    import html as _h
    rows = ""
    for r in sorted(reps, key=lambda x: x["target"]):
        vals = {k: (tv(val), det) for k, val, det in r["verdicts"]}
        cells = "".join(f"<td title='{_h.escape(d)}'>{_h.escape(v)}</td>"
                        for v, d in (vals.get(k, ("-", "")) for k in
                                     ("c_rl", "c_waf", "c_tls", "c_host", "c_sechead")))
        fnd = "<br>".join(f"<span class='sev-{s}'>[{sev(s)}]</span> {_h.escape(x)}"
                          for s, x in r["findings"] if s in (SEV_HIGH, SEV_MED)) or "-"
        rows += (f"<tr><td class='dom'>{_h.escape(r['target'])}</td>{cells}"
                 f"<td class='f'>{fnd}</td></tr>\n")
    hdr = "".join(f"<th>{t(k)}</th>" for k in ("c_domain", "c_rl", "c_waf", "c_tls",
                                               "c_host", "c_sechead"))
    return (
        f"<!doctype html><html lang=\"{LANG}\"><head><meta charset=\"utf-8\">\n"
        f"<title>{t('r_title')}</title><style>\n"
        f"body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#1a1a1a}}\n"
        f"h1{{font-size:1.4rem}} table{{border-collapse:collapse;width:100%;margin-top:1rem}}\n"
        f"th,td{{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;vertical-align:top}}\n"
        f"th{{background:#f4f4f5}} .dom{{font-weight:600}} .f{{font-size:.85em}}\n"
        f".sev-{SEV_HIGH}{{color:#c0392b;font-weight:600}} "
        f".sev-{SEV_MED}{{color:#b7791f;font-weight:600}}\n"
        f"small{{color:#666}}</style></head><body>\n"
        f"<h1>{t('r_title')}</h1><small>{t('r_input')}: {_h.escape(source)} · "
        f"{datetime.now():%Y-%m-%d %H:%M}</small>\n"
        f"<table><thead><tr>{hdr}<th>{t('h_finding')}</th></tr></thead><tbody>\n"
        f"{rows}</tbody></table></body></html>")


def diff_baseline(reps: list, path: str):
    try:
        with open(path, encoding="utf-8") as f:
            old = {r["target"]: r for r in json.load(f)}
    except (OSError, ValueError) as e:
        return None, str(e)
    changes = []
    for r in sorted(reps, key=lambda x: x["target"]):
        o = old.get(r["target"])
        if not o:
            changes.append((r["target"], "nuevo objetivo" if LANG == "es" else "new target"))
            continue
        nv = {k: val for k, val, _ in r["verdicts"]}
        ov = {k: val for k, val, _ in o.get("verdicts", [])}
        for k in sorted(set(nv) | set(ov)):
            if nv.get(k) != ov.get(k):
                changes.append((r["target"],
                                f"{t(k)}: {tv(ov.get(k, '-'))} → {tv(nv.get(k, '-'))}"))
    return changes, None


def _h(es: str, en: str) -> str:
    return es if LANG == "es" else en


class BannerParser(argparse.ArgumentParser):
    def compact_usage(self) -> str:
        dom = "DOMINIO" if LANG == "es" else "DOMAIN"
        fic = "FICHERO" if LANG == "es" else "FILE"
        opt = "[opciones]" if LANG == "es" else "[options]"
        head = t("u_usage")
        pad = " " * len(head)
        return (f"{head}{self.prog} {opt} {dom}\n"
                f"{pad}{self.prog} {opt} -f {fic}\n")

    def print_short_help(self, file=None):
        """Pantalla reducida: se muestra al ejecutar sin argumentos."""
        print_banner()
        more = _h("  -h, --help     ver todas las opciones",
                  "  -h, --help     show all options")
        (file or sys.stdout).write(self.compact_usage() + "\n" + self.epilog + more + "\n\n")

    def print_help(self, file=None):
        """Ayuda completa (-h / --help): uso, todas las opciones agrupadas y ejemplos."""
        print_banner()
        (file or sys.stdout).write(self.compact_usage() + "\n" + self.format_help() + "\n")

    def error(self, message):
        print_banner()
        sys.stderr.write(self.compact_usage())
        self.exit(2, f"\n{C.RED}error:{C.RESET} {message}\n"
                     f"{C.DIM}{t('e_help')}{C.RESET}\n\n")


class HelpFormatter(argparse.RawDescriptionHelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=30, width=100)

    def start_section(self, heading):
        super().start_section(f"{C.BOLD}{C.CYAN}{heading}{C.RESET}" if heading else heading)


def build_parser():
    prog = os.path.basename(sys.argv[0]) or "rd-check.py"
    ex = [f"  python3 {prog} example.com",
          f"  python3 {prog} -f {t('u_list')}",
          f"  python3 {prog} example.com --passive",
          f"  python3 {prog} example.com --burst 30",
          f"  python3 {prog} example.com --origin 203.0.113.10",
          f"  python3 {prog} example.com --lang {'en' if LANG == 'es' else 'es'}"]
    epilog = t("u_examples") + "\n" + "\n".join(ex) + "\n\n"
    dom, fic = ("DOMINIO", "FICHERO") if LANG == "es" else ("DOMAIN", "FILE")
    sec = "SEG" if LANG == "es" else "SEC"
    ap = BannerParser(prog=prog, epilog=epilog, formatter_class=HelpFormatter, add_help=False,
                      usage=argparse.SUPPRESS)

    g = ap.add_argument_group(_h("Objetivo", "Target"))
    g.add_argument("target", nargs="?", metavar=dom,
                   help=_h("dominio o URL a analizar", "domain or URL to scan"))
    g.add_argument("-f", "--file", metavar=fic,
                   help=_h("lista de dominios, uno por línea ('-' = stdin)",
                           "list of domains, one per line ('-' = stdin)"))

    g = ap.add_argument_group(_h("Pruebas", "Tests"))
    g.add_argument("--passive", action="store_true",
                   help=_h("solo observación: sin pruebas WAF, Host header, métodos, ráfaga ni origen",
                           "observe only: no WAF, Host header, methods, burst or origin tests"))
    g.add_argument("--burst", type=int, default=0, metavar="N",
                   help=_h("ráfaga de N peticiones para confirmar el rate limit (máx. 200)",
                           "burst of N requests to confirm rate limiting (max 200)"))
    g.add_argument("--origin", metavar="IP",
                   help=_h("IPv4 del servidor de origen: comprueba si se salta el CDN/WAF",
                           "origin server IPv4: checks whether the CDN/WAF can be bypassed"))
    g.add_argument("--no-selenium", action="store_true",
                   help=_h("no renderizar con Chrome headless", "do not render with headless Chrome"))
    g.add_argument("--render-wait", type=float, default=2.0, metavar=sec,
                   help=_h("espera tras renderizar con Selenium (def. 2)",
                           "wait after Selenium render (def. 2)"))
    g.add_argument("--verify-tls", action="store_true",
                   help=_h("verificar certificados en las peticiones HTTP",
                           "verify certificates on HTTP requests"))
    g.add_argument("--deny-private", action="store_true",
                   help=_h("omitir objetivos con IP privada, loopback o metadatos cloud",
                           "skip targets resolving to private, loopback or cloud-metadata IPs"))

    g = ap.add_argument_group(_h("Rendimiento", "Performance"))
    g.add_argument("-t", "--threads", type=int, default=3, metavar="N",
                   help=_h("dominios en paralelo (1-32, def. 3)", "domains in parallel (1-32, def. 3)"))
    g.add_argument("--timeout", type=int, default=10, metavar=sec,
                   help=_h("tiempo máximo por petición (def. 10)", "per-request timeout (def. 10)"))
    g.add_argument("--max-rps", type=float, default=0.0, metavar="N",
                   help=_h("límite de peticiones por segundo (0 = sin límite)",
                           "max requests per second (0 = unlimited)"))
    g.add_argument("--retries", type=int, default=1, metavar="N",
                   help=_h("reintentos ante 502/503/504 (0-5, def. 1)",
                           "retries on 502/503/504 (0-5, def. 1)"))
    g.add_argument("--max-login-pages", type=int, default=2, help=argparse.SUPPRESS)
    g.add_argument("--burst-workers", type=int, default=5, help=argparse.SUPPRESS)

    g = ap.add_argument_group("DNS")
    g.add_argument("--no-dns", action="store_true",
                   help=_h("omitir todo el análisis DNS", "skip all DNS analysis"))
    g.add_argument("--no-rdap", action="store_true",
                   help=_h("no consultar RDAP (propietario del rango IP)",
                           "do not query RDAP (IP range owner)"))
    g.add_argument("--no-asn", action="store_true",
                   help=_h("no consultar ASN (Team Cymru)", "do not query ASN (Team Cymru)"))
    g.add_argument("--no-shared-ip", action="store_true",
                   help=_h("no buscar otros dominios en la misma IP",
                           "do not look up other domains on the same IP"))
    g.add_argument("--resolver", default="1.1.1.1", metavar="IP",
                   help=_h("servidor DNS (def. 1.1.1.1)", "DNS resolver (def. 1.1.1.1)"))
    g.add_argument("--dns-timeout", type=float, default=3.0, metavar=sec,
                   help=_h("tiempo máximo por consulta DNS (def. 3)", "per-query DNS timeout (def. 3)"))

    g = ap.add_argument_group(_h("Informes", "Reports"))
    g.add_argument("-o", "--output", metavar="NOMBRE" if LANG == "es" else "NAME",
                   help=_h("nombre del informe o de la carpeta de salida",
                           "report name or output folder"))
    g.add_argument("--json", action="store_true", help=_h("generar también JSON", "also write JSON"))
    g.add_argument("--html", action="store_true", help=_h("generar también HTML", "also write HTML"))
    g.add_argument("--sarif", action="store_true", help=_h("generar también SARIF", "also write SARIF"))
    g.add_argument("--baseline", metavar="JSON",
                   help=_h("comparar con un informe JSON anterior",
                           "compare against a previous JSON report"))
    g.add_argument("--fail-on", choices=["never", "medium", "high"], default="never",
                   help=_h("salir con código 2 si hay hallazgos de esa severidad (CI/CD)",
                           "exit with code 2 on findings of that severity (CI/CD)"))
    g.add_argument("--lang", choices=["es", "en"], default="es",
                   help=_h("idioma de la salida (def. es)", "output language (def. es)"))

    g = ap.add_argument_group(_h("Otros", "Other"))
    g.add_argument("-q", "--quiet", action="store_true",
                   help=_h("salida mínima en consola", "minimal console output"))
    g.add_argument("--no-color", action="store_true",
                   help=_h("desactivar colores (también NO_COLOR)", "disable colours (also NO_COLOR)"))
    g.add_argument("--debug", action="store_true",
                   help=_h("registrar cada petición", "log every request"))
    g.add_argument("-h", "--help", action="help",
                   help=_h("mostrar la ayuda completa", "show the full help"))
    g.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}",
                   help=_h("mostrar la versión", "show version"))
    return ap


def normalize(line: str) -> str:
    line = line.strip()
    if not line or line.startswith("#"):
        return ""
    if not re.match(r"^https?://", line, re.I):
        line = "https://" + line
    p = urlparse(line)
    return f"{p.scheme}://{p.netloc}{p.path or '/'}" + (f"?{p.query}" if p.query else "")


def _is_private(host, args) -> bool:
    if not host:
        return False
    try:
        ips = {ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_UNSPEC)}
    except socket.gaierror:
        return False
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
                or a.is_multicast or str(a) == "169.254.169.254"):
            log(f"{C.YELLOW}[!]{C.RESET} {t('k_skip_private', h=host)}", args.quiet)
            return True
    return False


def safe_name(text: str) -> str:
    return re.sub(r"[^\w.-]+", "_", text).strip("._") or "rd-check"


def load_targets(args, ap):
    if args.target and args.file:
        ap.error(t("e_both"))
    if args.target:
        return [normalize(args.target)]
    if not args.file:
        ap.error(t("e_none"))
    try:
        if args.file == "-":
            lines = sys.stdin.read().splitlines()
        else:
            with open(args.file, encoding="utf-8") as f:
                lines = f.read().splitlines()
    except OSError as e:
        ap.error(t("e_read", f=args.file, e=e.strerror))
    urls = list(dict.fromkeys(u for u in (normalize(l) for l in lines) if u))
    if not urls:
        ap.error(t("e_empty", f=args.file))
    return urls


def output_paths(args, urls):
    if args.target:
        return ".", safe_name(args.output or urlparse(urls[0]).netloc)
    if args.output:
        folder = args.output
    else:
        src = "stdin" if args.file == "-" else os.path.splitext(os.path.basename(args.file))[0]
        folder = f"rd-check_{safe_name(src)}_{datetime.now():%Y%m%d_%H%M}"
    os.makedirs(folder, exist_ok=True)
    return folder, "report" if LANG == "en" else "informe"


def selenium_available(timeout: int) -> bool:
    try:
        import selenium
    except ImportError:
        log(f"{C.YELLOW}[!]{C.RESET} {t('k_no_selenium')}")
        return False
    try:
        make_driver(timeout).quit()
        return True
    except Exception as e:
        log(f"{C.YELLOW}[!]{C.RESET} {t('k_no_chrome', e=type(e).__name__)}")
        return False


def dns_record_tables(r: dict, full: bool = False, box: bool = False) -> list:
    rows = r.get("dns_rows", {})
    out = []
    if rows.get("A") or rows.get("AAAA"):
        data = [[x["ip"], x["prefix"], x["asn"]] for x in rows.get("A", []) + rows.get("AAAA", [])]
        out.append((t("dns_t_a"), table(["A/AAAA", t("dns_prefix"), "ASN"], data, box=box)))
    if rows.get("MX"):
        data = [[x["host"], x["ip"], x["prefix"], x["asn"]] for x in rows["MX"]]
        out.append((t("dns_t_mx"), table(["MX", "IP", t("dns_prefix"), "ASN"], data, box=box)))
    if rows.get("NS"):
        data = [[x["host"], x["ip"], x["prefix"], x["asn"]] for x in rows["NS"]]
        out.append((t("dns_t_ns"), table(["NS", "IP", t("dns_prefix"), "ASN"], data, box=box)))
    si = r.get("shared_ip", {})
    doms = si.get("domains", []) if si else []
    if doms:
        shown = doms if full else doms[:20]
        title = t("dns_t_shared", ip=si.get("ip", "-"))
        if not full and len(doms) > 20:
            title += f" (20/{len(doms)})"
        out.append((title, table([t("dns_h_domain")], [[d] for d in shown], box=box)))
    if r.get("dns_txt"):
        if full:
            data = [[txt_vendor(x) or "-", cell(x, 110)] for x in r["dns_txt"]]
            out.append((t("dns_t_txt"), table([t("dns_h_vendor"), t("h_value")], data, box=box)))
        else:
            seen = {}
            for x in r["dns_txt"]:
                ven = txt_vendor(x)
                if ven and ven not in ("SPF", "DMARC", "DKIM") and ven not in seen:
                    seen[ven] = x
            if seen:
                data = [[v, short_txt(val)] for v, val in sorted(seen.items())]
                out.append((t("dns_t_txt"),
                            table([t("dns_h_vendor"), t("h_value")], data, box=box)))
    return out


EXEC_SECTIONS = [
    ("Protección", ["c_rl", "c_captcha", "c_waf"]),
    ("Transporte", ["c_https", "c_tls"]),
    ("Cabeceras", ["c_sechead", "c_banner"]),
    ("Infraestructura", ["c_proxy", "c_shared"]),
]
EXEC_SECTIONS_EN = {"Protección": "Protection", "Transporte": "Transport",
                    "Cabeceras": "Headers", "Infraestructura": "Infrastructure"}


def executive_table(r: dict, color: bool = False, box: bool = False) -> str:
    vals = {k: (val, det) for k, val, det in r["verdicts"]}
    rows, colors, ri = [], {}, 0
    for sec, members in EXEC_SECTIONS:
        entries = [(t(k), tv(vals[k][0]), cell(vals[k][1], 60), value_color(vals[k][0]))
                   for k in members if k in vals]
        name = sec if LANG == "es" else EXEC_SECTIONS_EN.get(sec, sec)
        for i, (ctrl, res, det, col) in enumerate(entries):
            rows.append([name if i == 0 else " ", ctrl, res, det])
            if color and col:
                colors[(ri, 2)] = col
            ri += 1
    return table([t("h_section"), t("h_control"), t("h_result"), t("h_detail")],
                 rows, colors, box=box)


def console_block(r: dict) -> str:
    head = f"{C.BOLD}[*] {r['target']}{C.RESET}  {C.DIM}" \
           f"{t('k_header', st=r['status'] or '-', n=r['requests'])}{C.RESET}\n"
    if r.get("unreachable"):
        return head + f"    {C.RED}{r['findings'][0][1]}{C.RESET}\n"
    out = [head, verdict_table(r, color=True, maxlen=72, box=True), ""]
    dns_t = dns_record_tables(r, box=True)
    if dns_t:
        out.append(f"{C.BOLD}{t('r_dns')}{C.RESET}")
        for title, tbl in dns_t:
            out += [f"{C.CYAN}{title}{C.RESET}", tbl, ""]
    out += [f"{C.BOLD}{t('r_exec')}{C.RESET}", executive_table(r, color=True, box=True), ""]
    return "\n".join(out) + "\n"


def main():
    ap = build_parser()
    if len(sys.argv) == 1:
        ap.print_short_help()
        sys.exit(0)
    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    for name, lo, hi in (("threads", 1, 32), ("burst", 0, 200), ("burst_workers", 1, 20),
                         ("max_login_pages", 0, 10), ("retries", 0, 5)):
        if not lo <= getattr(args, name) <= hi:
            ap.error(t("e_range", n=name.replace("_", "-"), lo=lo, hi=hi))
    if args.max_rps < 0:
        ap.error(t("e_range", n="max-rps", lo=0, hi="∞"))
    global _RATE
    _RATE = RateLimiter(args.max_rps)
    if args.passive:
        args.burst = 0
        args.origin = None
    if args.origin:
        try:
            ipaddress.IPv4Address(args.origin)
        except ValueError:
            ap.error(t("e_origin"))

    targets = load_targets(args, ap)
    if args.deny_private:
        targets = [u for u in targets if not _is_private(urlparse(u).hostname, args)]
        if not targets:
            ap.error(t("e_all_private"))
    q = args.quiet
    if not q:
        print_banner()
    args.use_selenium = not args.no_selenium and selenium_available(args.timeout)
    folder, base = output_paths(args, targets)
    md_path, csv_path, json_path = (os.path.join(folder, base + e) for e in (".md", ".csv", ".json"))

    mode = "requests + Selenium" if args.use_selenium else t("r_reqonly")
    log(f"{C.DIM}{t('k_domains', n=len(targets))} · {mode}"
        f"{' · ' + t('r_passive') if args.passive else ''}"
        f"{' · ' + t('r_burst').lower() + ' ' + str(args.burst) if args.burst else ''}"
        f"{C.RESET}\n", q)

    reps = []
    ex = ThreadPoolExecutor(max_workers=args.threads)
    try:
        futs = {ex.submit(check_domain, x, args): x for x in targets}
        for fut in as_completed(futs):
            try:
                r = fut.result()
            except Exception as e:
                LOG.debug("fallo en %s", futs[fut], exc_info=True)
                r = {"target": futs[fut], "unreachable": True, "status": "", "requests": 0,
                     "final_url": "", "server_header": "", "proxy_names": [], "ips": "",
                     "errors": [type(e).__name__], "verdicts": [],
                     "findings": [(SEV_LOW, t("f_noresp", err=type(e).__name__))]}
            reps.append(r)
            log(console_block(r), q)
        ex.shutdown(wait=True)
    except KeyboardInterrupt:
        log(f"\n{C.YELLOW}[!]{C.RESET} {t('k_interrupted')}")
        ex.shutdown(wait=False, cancel_futures=True)
    finally:
        for d in list(_all_drivers):
            try:
                d.quit()
            except Exception:
                pass

    if not reps:
        log(f"{C.RED}[x]{C.RESET} {t('k_noresults')}")
        sys.exit(1)

    ok = [r for r in reps if not r.get("unreachable")]
    if len(reps) > 1 and ok:
        log(f"{C.BOLD}{t('k_all')}{C.RESET}\n\n{summary_table(ok, color=True, box=True)}\n", q)

    src = args.target or args.file
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(build_markdown(reps, src, args))
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([t("c_domain"), t("h_control"), t("h_result"), t("h_detail")])
        w.writerows(csv_rows(reps))
    log(f"{C.GREEN}[+]{C.RESET} Markdown: {md_path}")
    log(f"{C.GREEN}[+]{C.RESET} CSV:      {csv_path}")
    if args.json:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(reps, f, ensure_ascii=False, indent=2)
        log(f"{C.GREEN}[+]{C.RESET} JSON:     {json_path}")
    if args.html:
        hp = os.path.join(folder, base + ".html")
        with open(hp, "w", encoding="utf-8") as f:
            f.write(build_html(reps, src, args))
        log(f"{C.GREEN}[+]{C.RESET} HTML:     {hp}")
    if args.sarif:
        sp = os.path.join(folder, base + ".sarif")
        with open(sp, "w", encoding="utf-8") as f:
            json.dump(build_sarif(reps), f, ensure_ascii=False, indent=2)
        log(f"{C.GREEN}[+]{C.RESET} SARIF:    {sp}")

    if args.baseline:
        changes, err = diff_baseline(reps, args.baseline)
        if err:
            log(f"{C.YELLOW}[!]{C.RESET} baseline: {err}")
        elif changes:
            log(f"\n{C.BOLD}{t('k_changes')}{C.RESET}", q)
            for dom, ch in changes:
                log(f"    {dom} — {ch}", q)
        else:
            log(f"{C.DIM}{t('k_nochange')}{C.RESET}", q)

    worst = worst_severity(reps)
    if args.fail_on == "high" and worst == SEV_HIGH:
        sys.exit(2)
    if args.fail_on == "medium" and worst in (SEV_HIGH, SEV_MED):
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
