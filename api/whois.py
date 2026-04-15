"""
POST /api/whois
Body: { "domain": "example.com" }
  or: { "domains": ["a.com", "b.com"] }
Returns: { "results": { "example.com": { created, expires, registrar } } }
"""

import json
import re
import socket
from http.server import BaseHTTPRequestHandler
from datetime import datetime


# ─── WHOIS Client (inlined for Vercel compatibility) ───

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


def _raw_whois_query(domain, server, port=43, timeout=8):
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
    result = {"created": None, "expires": None, "registrar": None}

    created_patterns = [
        r'Creat(?:ion|ed)\s*Date\s*:\s*(.+)', r'Registration\s*Date\s*:\s*(.+)',
        r'Created\s*:\s*(.+)', r'created\s*:\s*(.+)',
        r'Registration\s*Time\s*:\s*(.+)', r'\[Created on\]\s*(.+)',
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


# ─── Serverless Handler ───

def _cors_headers():
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
    }


def _fmt_date(d):
    if isinstance(d, datetime):
        return d.strftime("%Y-%m-%d")
    return str(d) if d else None


def _lookup_one(domain):
    try:
        w = whois_lookup(domain)
        return {
            "created": _fmt_date(w.get("created")),
            "expires": _fmt_date(w.get("expires")),
            "registrar": (w.get("registrar") or "")[:80],
            "error": None,
        }
    except Exception as e:
        return {
            "created": None,
            "expires": None,
            "registrar": None,
            "error": str(e),
        }


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            data = json.loads(body) if body else {}
        except Exception:
            self._respond(400, {"error": "Invalid JSON"})
            return

        domain_list = data.get("domains", [])
        if not domain_list and data.get("domain"):
            domain_list = [data["domain"]]

        if not domain_list:
            self._respond(400, {"error": "Provide 'domain' or 'domains'"})
            return

        # Cap at 10 per request (Vercel hobby = 10s timeout)
        domain_list = domain_list[:10]

        results = {}
        for d in domain_list:
            d = d.strip().lower()
            if d:
                results[d] = _lookup_one(d)

        self._respond(200, {"results": results})

    def do_OPTIONS(self):
        self.send_response(200)
        for k, v in _cors_headers().items():
            self.send_header(k, v)
        self.end_headers()

    def _respond(self, code, payload):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in _cors_headers().items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())
