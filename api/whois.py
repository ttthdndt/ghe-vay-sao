"""
POST /api/whois
Body: { "domain": "example.com" }
  or: { "domains": ["a.com", "b.com"] }
Returns: { "results": { "example.com": { created, expires, registrar, error } } }
"""

import json
import sys
import os
from datetime import datetime
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from lib.whois_lib import whois_lookup


CORS = {
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
            "created":   _fmt_date(w.get("created")),
            "expires":   _fmt_date(w.get("expires")),
            "registrar": (w.get("registrar") or "")[:80],
            "error":     None,
        }
    except Exception as e:
        return {"created": None, "expires": None, "registrar": None, "error": str(e)}


class handler(BaseHTTPRequestHandler):

    def log_message(self, *a):
        pass

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in CORS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        for k, v in CORS.items():
            self.send_header(k, v)
        self.end_headers()

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n)) if n else {}
        except Exception:
            self._send(400, {"error": "Invalid JSON body"}); return

        domains = data.get("domains") or ([data["domain"]] if data.get("domain") else [])
        if not domains:
            self._send(400, {"error": "Provide 'domain' or 'domains'"}); return

        results = {}
        for d in domains[:20]:
            d = d.strip().lower()
            if d:
                results[d] = _lookup_one(d)

        self._send(200, {"results": results})
