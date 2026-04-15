"""
API: GET /api/scrape?keyword=sport&price_max=495&max_rows=100
Returns JSON array of domain listings from HugeDomains.
"""
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import json
import re
import requests
from bs4 import BeautifulSoup


def scrape_hugedomains(keyword, price_min="", price_max="495",
                       length_start="", length_end="", max_rows=100):
    url = "https://www.hugedomains.com/domain_search.cfm"
    params = {
        "domain_name": keyword,
        "anchor": "all",
        "price_from": price_min,
        "price_to": price_max,
        "length_start": length_start,
        "length_end": length_end,
        "highlightbg": "0",
        "maxRows": str(max_rows),
    }
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    resp = requests.get(url, params=params, headers=headers, timeout=30)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")
    domains = []

    # Strategy 1: structured data in JS
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

    # Strategy 2: HTML listing cards
    if not domains:
        selectors = [
            ("div.domain-listing", "a", ".price"),
            ("div.domain-result", "a", ".price"),
            ("tr.domainResult", "td:first-child", "td.price"),
            ("div[class*='domain']", "a[href*='domain']", "span[class*='price']"),
            ("li.result", "a", ".price"),
        ]
        for container_sel, name_sel, price_sel in selectors:
            containers = soup.select(container_sel)
            if containers:
                for c in containers:
                    name_el = c.select_one(name_sel)
                    price_el = c.select_one(price_sel)
                    if name_el:
                        raw_name = name_el.get_text(strip=True)
                        domain_name = re.sub(r'^(buy\s+|get\s+)', '', raw_name, flags=re.I).strip()
                        if "." in domain_name and len(domain_name) > 3:
                            price_text = price_el.get_text(strip=True) if price_el else ""
                            domains.append({"domain": domain_name, "price": price_text})
                if domains:
                    break

    # Strategy 3: link scan
    if not domains:
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            text = a_tag.get_text(strip=True)
            m = re.search(r'domain_name=([a-zA-Z0-9-]+\.\w+)', href)
            if m:
                d = m.group(1)
                if d not in [x["domain"] for x in domains]:
                    domains.append({"domain": d, "price": ""})
            elif re.match(r'^[a-zA-Z0-9-]+\.(com|net|org|io|co)$', text):
                if text not in [x["domain"] for x in domains]:
                    domains.append({"domain": text, "price": ""})

    # Strategy 4: regex all domain-like strings
    if not domains:
        page_text = soup.get_text()
        found = re.findall(
            r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
            r'\.(?:com|net|org|io|co|info|biz))\b',
            page_text
        )
        seen = set()
        for d in found:
            low = d.lower()
            if low not in seen and keyword.lower() in low:
                seen.add(low)
                domains.append({"domain": low, "price": ""})

    # Deduplicate
    seen = set()
    unique = []
    for d in domains:
        key = d["domain"].lower().strip()
        if key not in seen:
            seen.add(key)
            unique.append(d)

    return unique


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            query = parse_qs(urlparse(self.path).query)
            keyword = query.get("keyword", [""])[0].strip()
            if not keyword:
                self._json_response(400, {"error": "Missing 'keyword' parameter"})
                return

            price_max = query.get("price_max", ["495"])[0]
            max_rows = int(query.get("max_rows", ["100"])[0])

            results = scrape_hugedomains(
                keyword=keyword,
                price_max=price_max,
                max_rows=max_rows,
            )
            self._json_response(200, {"domains": results, "count": len(results)})

        except Exception as e:
            self._json_response(500, {"error": str(e)})

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
