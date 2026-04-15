"""
API: GET /api/whois?domain=example.com
Returns JSON with created, expires, registrar, raw WHOIS text.
"""
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import json
import socket
import re
from datetime import datetime


# TLD → WHOIS server mapping
WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io":  "whois.nic.io",
    "co":  "whois.nic.co",
    "info": "whois.afilias.net",
    "biz": "whois.biz",
    "me":  "whois.nic.me",
    "us":  "whois.nic.us",
    "xyz": "whois.nic.xyz",
    "online": "whois.nic.online",
    "site": "whois.nic.site",
    "store": "whois.nic.store",
    "app": "whois.nic.google",
    "dev": "whois.nic.google",
    "ai":  "whois.nic.ai",
    "cc":  "ccwhois.verisign-grs.com",
    "tv":  "tvwhois.verisign-grs.com",
}


def _raw_whois_query(domain, server, port=43, timeout=10):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((server, port))
    s.sendall((domain + "\r\n").encode("utf-8"))
    response = b""
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
        except socket.timeout:
            break
    s.close()
    return response.decode("utf-8", errors="ignore")


def _parse_date(date_str):
    date_str = date_str.strip().rstrip(".")
    date_str = re.sub(r'\s*\(?\s*UTC\s*\)?\s*$', '', date_str, flags=re.I)
    date_str = re.sub(r'\s*[A-Z]{2,4}\s*$', '', date_str)
    formats = [
        "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%d %b %Y",
        "%d/%m/%Y", "%Y/%m/%d", "%Y.%m.%d", "%B %d, %Y", "%b %d, %Y",
        "%d-%b-%Y %H:%M:%S", "%a %b %d %H:%M:%S %Y", "%Y%m%d",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(date_str.strip(), fmt)
        except ValueError:
            continue
    return None


def _parse_whois_text(text):
    result = {"created": None, "expires": None, "registrar": None, "raw": text}

    created_patterns = [
        r'Creat(?:ion|ed)\s*Date\s*:\s*(.+)', r'Registration\s*Date\s*:\s*(.+)',
        r'Created\s*:\s*(.+)', r'created\s*:\s*(.+)',
        r'Registration\s*Time\s*:\s*(.+)', r'\[Created on\]\s*(.+)',
        r'Domain\s+Name\s+Commencement\s+Date\s*:\s*(.+)',
    ]
    expiry_patterns = [
        r'(?:Registry\s+)?Expir(?:y|ation)\s*Date\s*:\s*(.+)',
        r'Registrar\s+Registration\s+Expiration\s+Date\s*:\s*(.+)',
        r'Expir(?:es|ation)\s*:\s*(.+)', r'paid-till\s*:\s*(.+)',
        r'Expiration\s*Time\s*:\s*(.+)', r'\[Expires on\]\s*(.+)',
        r'Renewal\s+Date\s*:\s*(.+)',
    ]
    registrar_patterns = [
        r'Registrar\s*:\s*(.+)', r'Sponsoring\s+Registrar\s*:\s*(.+)',
        r'registrar\s*:\s*(.+)',
    ]

    for pattern in created_patterns:
        m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if m and not result["created"]:
            result["created"] = _parse_date(m.group(1).strip())
            if result["created"]:
                break

    for pattern in expiry_patterns:
        m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if m and not result["expires"]:
            result["expires"] = _parse_date(m.group(1).strip())
            if result["expires"]:
                break

    for pattern in registrar_patterns:
        m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if m and not result["registrar"]:
            reg = m.group(1).strip()
            if reg.upper() not in ("", "N/A") and "whois." not in reg.lower():
                result["registrar"] = reg
                break

    # Fallback: ISO date scan
    if not result["created"] or not result["expires"]:
        date_candidates = re.findall(
            r'(\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}Z?)?)', text
        )
        parsed_dates = []
        for dc in date_candidates:
            pd = _parse_date(dc)
            if pd and pd.year > 1990:
                parsed_dates.append(pd)
        if parsed_dates:
            parsed_dates.sort()
            if not result["created"]:
                result["created"] = parsed_dates[0]
            if not result["expires"] and len(parsed_dates) >= 2:
                result["expires"] = parsed_dates[-1]

    return result


def whois_lookup(domain_name):
    domain_name = domain_name.strip().lower()
    tld = domain_name.rsplit(".", 1)[-1] if "." in domain_name else ""
    server = WHOIS_SERVERS.get(tld, f"whois.nic.{tld}")

    raw_text = _raw_whois_query(domain_name, server)

    referral_match = re.search(
        r'Registrar\s+WHOIS\s+Server\s*:\s*(\S+)', raw_text, re.IGNORECASE
    )
    if referral_match:
        ref_server = referral_match.group(1).strip().rstrip(".")
        if ref_server and ref_server != server:
            try:
                raw_text2 = _raw_whois_query(domain_name, ref_server)
                if raw_text2.strip():
                    raw_text = raw_text + "\n\n" + raw_text2
            except Exception:
                pass

    return _parse_whois_text(raw_text)


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            query = parse_qs(urlparse(self.path).query)
            domain = query.get("domain", [""])[0].strip().lower()
            if not domain:
                self._json_response(400, {"error": "Missing 'domain' parameter"})
                return

            w = whois_lookup(domain)
            fmt = lambda d: d.strftime("%Y-%m-%d") if isinstance(d, datetime) else None

            created = fmt(w.get("created"))
            expires = fmt(w.get("expires"))
            years = None
            if created and expires:
                try:
                    cd = datetime.strptime(created, "%Y-%m-%d")
                    ed = datetime.strptime(expires, "%Y-%m-%d")
                    years = round((ed - cd).days / 365.25, 1)
                except ValueError:
                    pass

            self._json_response(200, {
                "domain": domain,
                "created": created,
                "expires": expires,
                "years": years,
                "registrar": w.get("registrar"),
                "raw": w.get("raw", ""),
            })

        except Exception as e:
            self._json_response(500, {"error": str(e), "domain": domain if 'domain' in dir() else None})

    def _json_response(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
