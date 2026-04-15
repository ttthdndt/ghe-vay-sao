"""
POST /api/whois
Body: { "domain": "example.com" }
  or: { "domains": ["a.com", "b.com"] }
Returns: { "results": { "example.com": { created, expires, registrar, error } } }
"""

import json
import sys
import os
from http.server import BaseHTTPRequestHandler
from datetime import datetime

# Ensure lib/ is importable when Vercel runs from the api/ directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib.whois_lib import whois_lookup


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

    def log_message(self, format, *args):
        # Suppress default request logging noise in Vercel logs
        pass

    def do_OPTIONS(self):
        self.send_response(200)
        for k, v in _cors_headers().items():
            self.send_header(k, v)
        self.end_headers()

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            data = json.loads(body) if body else {}
        except Exception:
            self._respond(400, {"error": "Invalid JSON body"})
            return

        domain_list = data.get("domains", [])
        if not domain_list and data.get("domain"):
            domain_list = [data["domain"]]

        if not domain_list:
            self._respond(400, {"error": "Provide 'domain' or 'domains'"})
            return

        # Cap at 20 per request (Vercel hobby: 10s execution limit)
        domain_list = domain_list[:20]

        results = {}
        for d in domain_list:
            d = d.strip().lower()
            if d:
                results[d] = _lookup_one(d)

        self._respond(200, {"results": results})

    def _respond(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in _cors_headers().items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)
