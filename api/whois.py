"""
POST /api/whois
Body: { "domain": "example.com" }
  or: { "domains": ["a.com", "b.com"] }
Returns: { "results": { "example.com": { created, expires, registrar } } }
"""

import json
from http.server import BaseHTTPRequestHandler
from datetime import datetime

# Import shared WHOIS library (Vercel bundles files starting with _)
from api._whois_lib import whois_lookup


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

        # Accept single domain or list
        domain_list = data.get("domains", [])
        if not domain_list and data.get("domain"):
            domain_list = [data["domain"]]

        if not domain_list:
            self._respond(400, {"error": "Provide 'domain' or 'domains'"})
            return

        # Cap at 20 per request to avoid timeout (Vercel 10s limit on hobby)
        domain_list = domain_list[:20]

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
