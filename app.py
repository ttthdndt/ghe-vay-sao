"""
Domain Hunter — Flask Web App
Deploy to Vercel via GitHub.
"""

from flask import Flask, request, jsonify, render_template
import re
import json
import socket
import threading
from datetime import datetime

try:
    import requests as http_requests
    from bs4 import BeautifulSoup
    SCRAPER_AVAILABLE = True
except ImportError:
    SCRAPER_AVAILABLE = False

app = Flask(__name__)

# ─────────────────── WHOIS Servers ───────────────────

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

# ─────────────────── Raw WHOIS Client ───────────────────

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
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y",
        "%d %b %Y", "%d/%m/%Y", "%Y/%m/%d", "%Y.%m.%d",
        "%B %d, %Y", "%b %d, %Y", "%d-%b-%Y %H:%M:%S",
        "%a %b %d %H:%M:%S %Y", "%Y%m%d",
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
        r'Creat(?:ion|ed)\s*Date\s*:\s*(.+)',
        r'Registration\s*Date\s*:\s*(.+)',
        r'Created\s*:\s*(.+)',
        r'created\s*:\s*(.+)',
        r'Registration\s*Time\s*:\s*(.+)',
        r'\[Created on\]\s*(.+)',
    ]
    expiry_patterns = [
        r'(?:Registry\s+)?Expir(?:y|ation)\s*Date\s*:\s*(.+)',
        r'Registrar\s+Registration\s+Expiration\s+Date\s*:\s*(.+)',
        r'Expir(?:es|ation)\s*:\s*(.+)',
        r'paid-till\s*:\s*(.+)',
        r'Expiration\s*Time\s*:\s*(.+)',
        r'\[Expires on\]\s*(.+)',
        r'Renewal\s+Date\s*:\s*(.+)',
    ]
    registrar_patterns = [
        r'Registrar\s*:\s*(.+)',
        r'Sponsoring\s+Registrar\s*:\s*(.+)',
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
        parsed_dates = [_parse_date(dc) for dc in date_candidates]
        parsed_dates = [d for d in parsed_dates if d and d.year > 1990]
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


# ─────────────────── Scraper ───────────────────

def scrape_hugedomains(keyword, price_max="495", max_rows=100):
    if not SCRAPER_AVAILABLE:
        raise ImportError("Missing: pip install requests beautifulsoup4")

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
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    resp = http_requests.get(url, params=params, headers=headers, timeout=25)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")
    domains = []

    # Strategy 1: JSON in script tags
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

    # Strategy 3: Link scan
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

    # Strategy 4: Text scan
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

    return domains


# ─────────────────── Flask Routes ───────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/search", methods=["POST"])
def api_search():
    data = request.get_json() or {}
    keyword   = data.get("keyword", "").strip()
    price_max = data.get("price_max", "495")
    max_rows  = int(data.get("max_rows", 100))

    if not keyword:
        return jsonify({"error": "keyword required"}), 400

    try:
        results = scrape_hugedomains(keyword, price_max=price_max, max_rows=max_rows)
        seen = set()
        clean = []
        for i, item in enumerate(results, 1):
            d = item["domain"].lower().strip()
            if d in seen:
                continue
            seen.add(d)
            clean.append({
                "num":       len(clean) + 1,
                "domain":    item["domain"],
                "price":     item.get("price", ""),
                "created":   "",
                "expires":   "",
                "registrar": "",
                "years":     "",
            })
        return jsonify({"domains": clean, "count": len(clean)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/whois", methods=["POST"])
def api_whois():
    data   = request.get_json() or {}
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "domain required"}), 400

    try:
        w = whois_lookup(domain)
        fmt = lambda d: d.strftime("%Y-%m-%d") if isinstance(d, datetime) else (str(d) if d else "")
        created = fmt(w.get("created"))
        expires = fmt(w.get("expires"))

        years = ""
        if created and expires:
            try:
                cd = datetime.strptime(created, "%Y-%m-%d")
                ed = datetime.strptime(expires, "%Y-%m-%d")
                y = (ed - cd).days / 365.25
                years = f"{y:.1f}"
            except Exception:
                pass

        return jsonify({
            "domain":    domain,
            "created":   created  or "N/A",
            "expires":   expires  or "N/A",
            "registrar": (w.get("registrar") or "")[:60],
            "years":     years,
            "raw":       w.get("raw", ""),
        })
    except Exception as e:
        return jsonify({"error": str(e), "domain": domain}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)
