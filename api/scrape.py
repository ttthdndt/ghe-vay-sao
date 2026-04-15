"""
POST /api/scrape
Body: { "keyword": "sport", "price_max": "495", "max_rows": 100 }
Returns: { "domains": [...], "count": N }
"""

import json
import re
import sys
import os
from http.server import BaseHTTPRequestHandler

# Ensure lib/ is importable when Vercel runs from the api/ directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError as _import_err:
    requests = None
    BeautifulSoup = None
    _import_err_msg = str(_import_err)
else:
    _import_err_msg = None


def _cors_headers():
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
    }


def scrape_hugedomains(keyword, price_max="495", max_rows=100):
    if not requests or not BeautifulSoup:
        raise ImportError(f"Missing dependencies: {_import_err_msg}")

    url = "https://www.hugedomains.com/domain_search.cfm"
    params = {
        "domain_name": keyword,
        "anchor": "all",
        "price_from": "",
        "price_to": price_max,
        "length_start": "",
        "length_end": "",
        "highlightbg": "0",
        "maxRows": str(max_rows),
    }
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    resp = requests.get(url, params=params, headers=headers, timeout=25)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "lxml")
    domains = []

    # Strategy 1: JSON in script blocks
    for script_tag in soup.find_all("script"):
        text = script_tag.string or ""
        if "domainName" in text or "domain_name" in text:
            for match in re.finditer(r'\{[^{}]*"(?:domainName|domain_name)"[^{}]*\}', text):
                try:
                    obj = json.loads(match.group())
                    name = obj.get("domainName") or obj.get("domain_name", "")
                    price = obj.get("price") or obj.get("salePrice", "")
                    if name:
                        domains.append({"domain": name.strip(), "price": str(price).strip()})
                except (json.JSONDecodeError, AttributeError):
                    pass

    # Strategy 2: HTML selectors
    if not domains:
        selectors = [
            ("div.domain-listing", "a", ".price"),
            ("div.domain-result", "a", ".price"),
            ("tr.domainResult", "td:first-child", "td.price"),
            ("div[class*='domain']", "a[href*='domain']", "span[class*='price']"),
            ("li.result", "a", ".price"),
        ]
        for cs, ns, ps in selectors:
            containers = soup.select(cs)
            if containers:
                for c in containers:
                    ne = c.select_one(ns)
                    pe = c.select_one(ps)
                    if ne:
                        raw = ne.get_text(strip=True)
                        dn = re.sub(r'^(buy\s+|get\s+)', '', raw, flags=re.I).strip()
                        if "." in dn and len(dn) > 3:
                            domains.append({
                                "domain": dn,
                                "price": pe.get_text(strip=True) if pe else "",
                            })
                if domains:
                    break

    # Strategy 3: link scan
    if not domains:
        for a in soup.find_all("a", href=True):
            m = re.search(r'domain_name=([a-zA-Z0-9-]+\.\w+)', a["href"])
            if m:
                d = m.group(1)
                if d not in [x["domain"] for x in domains]:
                    domains.append({"domain": d, "price": ""})
            elif re.match(r'^[a-zA-Z0-9-]+\.(com|net|org|io|co)$', a.get_text(strip=True)):
                t = a.get_text(strip=True)
                if t not in [x["domain"] for x in domains]:
                    domains.append({"domain": t, "price": ""})

    # Strategy 4: regex fallback on page text
    if not domains:
        page_text = soup.get_text()
        found = re.findall(
            r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
            r'\.(?:com|net|org|io|co|info|biz))\b',
            page_text,
        )
        seen = set()
        for d in found:
            low = d.lower()
            if low not in seen and keyword.lower() in low:
                seen.add(low)
                domains.append({"domain": low, "price": ""})

    # Deduplicate preserving order
    seen = set()
    unique = []
    for item in domains:
        key = item["domain"].lower().strip()
        if key not in seen:
            seen.add(key)
            unique.append(item)

    return unique


class handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
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

        keyword = data.get("keyword", "").strip()
        if not keyword:
            self._respond(400, {"error": "Missing 'keyword'"})
            return

        try:
            results = scrape_hugedomains(
                keyword=keyword,
                price_max=data.get("price_max", "495"),
                max_rows=int(data.get("max_rows", 100)),
            )
            self._respond(200, {"domains": results, "count": len(results)})
        except Exception as e:
            self._respond(500, {"error": str(e)})

    def _respond(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in _cors_headers().items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)
