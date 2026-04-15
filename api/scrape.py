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

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    import requests
    from bs4 import BeautifulSoup
    _missing = None
except ImportError as e:
    requests = None
    BeautifulSoup = None
    _missing = str(e)


CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}


def scrape_hugedomains(keyword, price_max="495", max_rows=100):
    if not requests or not BeautifulSoup:
        raise ImportError(f"Missing dependency: {_missing}")

    url = "https://www.hugedomains.com/domain_search.cfm"
    params = {
        "domain_name": keyword, "anchor": "all",
        "price_from": "", "price_to": price_max,
        "length_start": "", "length_end": "",
        "highlightbg": "0", "maxRows": str(max_rows),
    }
    hdrs = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    resp = requests.get(url, params=params, headers=hdrs, timeout=25)
    resp.raise_for_status()

    # Try lxml first, fall back to html.parser
    try:
        soup = BeautifulSoup(resp.text, "lxml")
    except Exception:
        soup = BeautifulSoup(resp.text, "html.parser")

    domains = []

    # Strategy 1: JSON in <script> blocks
    for tag in soup.find_all("script"):
        text = tag.string or ""
        if "domainName" in text or "domain_name" in text:
            for m in re.finditer(r'\{[^{}]*"(?:domainName|domain_name)"[^{}]*\}', text):
                try:
                    obj = json.loads(m.group())
                    name = obj.get("domainName") or obj.get("domain_name", "")
                    price = obj.get("price") or obj.get("salePrice", "")
                    if name:
                        domains.append({"domain": name.strip(), "price": str(price).strip()})
                except Exception:
                    pass

    # Strategy 2: CSS selectors
    if not domains:
        for cs, ns, ps in [
            ("div.domain-listing", "a", ".price"),
            ("div.domain-result",  "a", ".price"),
            ("tr.domainResult",    "td:first-child", "td.price"),
            ("div[class*='domain']", "a[href*='domain']", "span[class*='price']"),
            ("li.result", "a", ".price"),
        ]:
            containers = soup.select(cs)
            for c in containers:
                ne = c.select_one(ns)
                pe = c.select_one(ps)
                if ne:
                    raw = re.sub(r'^(buy\s+|get\s+)', '', ne.get_text(strip=True), flags=re.I).strip()
                    if "." in raw and len(raw) > 3:
                        domains.append({"domain": raw, "price": pe.get_text(strip=True) if pe else ""})
            if domains:
                break

    # Strategy 3: <a href> scan
    if not domains:
        for a in soup.find_all("a", href=True):
            m = re.search(r'domain_name=([a-zA-Z0-9-]+\.\w+)', a["href"])
            txt = a.get_text(strip=True)
            d = m.group(1) if m else (txt if re.match(r'^[a-zA-Z0-9-]+\.(com|net|org|io|co)$', txt) else None)
            if d and d not in [x["domain"] for x in domains]:
                domains.append({"domain": d, "price": ""})

    # Strategy 4: regex over full page text
    if not domains:
        for d in re.findall(
            r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:com|net|org|io|co|info|biz))\b',
            soup.get_text()
        ):
            low = d.lower()
            if keyword.lower() in low:
                domains.append({"domain": low, "price": ""})

    # Deduplicate
    seen, unique = set(), []
    for item in domains:
        key = item["domain"].lower().strip()
        if key not in seen:
            seen.add(key)
            unique.append(item)

    return unique


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

        keyword = data.get("keyword", "").strip()
        if not keyword:
            self._send(400, {"error": "Missing 'keyword'"}); return

        try:
            results = scrape_hugedomains(
                keyword=keyword,
                price_max=data.get("price_max", "495"),
                max_rows=int(data.get("max_rows", 100)),
            )
            self._send(200, {"domains": results, "count": len(results)})
        except Exception as e:
            self._send(500, {"error": str(e)})
