import requests
from bs4 import BeautifulSoup
import re
import time
from typing import Optional

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
}

BASE_URL = "https://www.hugedomains.com/domain_search.cfm"
BASE_PARAMS = dict(
    domain_name="sport",
    anchor="right",
    price_from=15,
    price_to=1000,
    length_start=8,
    length_end=10,
    highlightbg=0,
    maxrows=100,
    catsearch=0,
    sort="PriceAsc",
)


def parse_hugedomains_page(soup: BeautifulSoup) -> list[dict]:
    rows = []
    for a in soup.find_all("a", href=re.compile(r"/domain_profile\.cfm")):
        domain = a.get_text(strip=True)
        container = a.find_parent(["li", "div", "tr"]) or a.parent
        price_match = re.search(r"\$[\d,]+", container.get_text()) if container else None
        price = price_match.group(0) if price_match else "N/A"
        if domain and "." in domain:
            rows.append({"domain": domain, "price": price})
    return rows


def scrape_hugedomains() -> list[dict]:
    all_rows = []
    start = 1
    while True:
        r = requests.get(
            BASE_URL, params={**BASE_PARAMS, "start": start}, headers=HEADERS, timeout=15
        )
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "lxml")
        rows = parse_hugedomains_page(soup)
        all_rows.extend(rows)
        if not rows or not soup.find("a", string=re.compile(r"(?i)next")):
            break
        start += 100
        time.sleep(1)

    # Deduplicate
    seen = set()
    unique = []
    for row in all_rows:
        if row["domain"] not in seen:
            seen.add(row["domain"])
            unique.append(row)
    return unique


# ── WHOIS ────────────────────────────────────────────────────────────────────

WHOIS_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://who.is/",
}


def get_date_by_label(soup: BeautifulSoup, label: str) -> str:
    """Mimics XPath: //dt[text()="{label}"]/parent::div/dd"""
    dt = soup.find("dt", string=lambda t: t and t.strip() == label)
    if dt:
        parent = dt.find_parent("div")
        if parent:
            dd = parent.find("dd")
            if dd:
                return dd.get_text(strip=True)
    return "N/A"


def whois_lookup(domain: str) -> dict:
    url = f"https://who.is/whois/{domain}"
    try:
        resp = requests.get(url, headers=WHOIS_HEADERS, timeout=12)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")
        return {
            "created": get_date_by_label(soup, "Created"),
            "expires": get_date_by_label(soup, "Expires"),
        }
    except Exception:
        return {"created": "Error", "expires": "Error"}


def scrape_with_whois(delay: float = 1.2) -> list[dict]:
    domains = scrape_hugedomains()
    results = []
    for row in domains:
        whois = whois_lookup(row["domain"])
        results.append({**row, **whois})
        time.sleep(delay)
    return results
