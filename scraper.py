import requests
from bs4 import BeautifulSoup
import re
import time
import random
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
}

WHOIS_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://who.is/",
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
    maxrows=50,
    catsearch=0,
    sort="PriceAsc",
)

DOMAIN_LIMIT = 50


# ── Proxy helpers ─────────────────────────────────────────────────────────────

def tcp_check(ip: str, port: int, timeout: float = 5.0) -> bool:
    """Raw TCP connect test — same approach as the notebook socket check."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
        return True
    except Exception:
        return False


def check_proxies(proxy_list: list[str], log: Callable = print) -> list[str]:
    """
    TCP-test all proxies in parallel. Return only the ones that connect.
    """
    if not proxy_list:
        return []

    log(f"[Proxy] Testing {len(proxy_list)} proxies via TCP…")

    def test(proxy_str: str):
        parts = proxy_str.strip().split(":")
        ip, port = parts[0], int(parts[1])
        ok = tcp_check(ip, port)
        return proxy_str, ok

    alive = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(test, p): p for p in proxy_list}
        for f in as_completed(futures):
            proxy_str, ok = f.result()
            parts = proxy_str.split(":")
            label = f"{parts[0]}:{parts[1]}"
            if ok:
                log(f"[Proxy] ✓ {label} — alive")
                alive.append(proxy_str)
            else:
                log(f"[Proxy] ✗ {label} — dead (TCP failed)")

    log(f"[Proxy] {len(alive)}/{len(proxy_list)} proxies alive.")
    return alive


def parse_proxy(proxy_str: str) -> dict:
    """Parse IP:PORT:USER:PASS → requests proxy dict."""
    parts = proxy_str.strip().split(":")
    ip, port, user, pwd = parts[0], parts[1], parts[2], parts[3]
    url = f"http://{user}:{pwd}@{ip}:{port}"
    return {"http": url, "https": url}


def random_proxy(proxies: list[str]) -> dict | None:
    if not proxies:
        return None
    return parse_proxy(random.choice(proxies))


# ── HugeDomains ───────────────────────────────────────────────────────────────

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


def scrape_hugedomains(log: Callable = print) -> list[dict]:
    log(f"[HugeDomains] Fetching first {DOMAIN_LIMIT} domains...")
    r = requests.get(BASE_URL, params={**BASE_PARAMS, "start": 1}, headers=HEADERS, timeout=15)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "lxml")
    rows = parse_hugedomains_page(soup)

    seen, unique = set(), []
    for row in rows:
        if row["domain"] not in seen:
            seen.add(row["domain"])
            unique.append(row)
        if len(unique) >= DOMAIN_LIMIT:
            break

    log(f"[HugeDomains] Got {len(unique)} unique domains.")
    return unique


# ── WHOIS ─────────────────────────────────────────────────────────────────────

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


def whois_lookup(domain: str, proxies: list[str] = None, log: Callable = print) -> dict:
    url = f"https://who.is/whois/{domain}"
    max_attempts = 2
    for attempt in range(1, max_attempts + 1):
        proxy = random_proxy(proxies) if proxies else None
        proxy_label = list(proxy.values())[0].split("@")[-1] if proxy else "direct"
        try:
            resp = requests.get(url, headers=WHOIS_HEADERS, proxies=proxy, timeout=8)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "lxml")
            created = get_date_by_label(soup, "Created")
            expires = get_date_by_label(soup, "Expires")
            log(f"[WHOIS] ✓ {domain} [{proxy_label}] → Created: {created} | Expires: {expires}")
            return {"created": created, "expires": expires}
        except requests.exceptions.Timeout:
            log(f"[WHOIS] ⏱ {domain} [{proxy_label}] → Timeout (attempt {attempt}/{max_attempts})")
        except Exception as e:
            log(f"[WHOIS] ✗ {domain} [{proxy_label}] → {e}")
            break
    return {"created": "N/A", "expires": "N/A"}


# ── Full pipeline ─────────────────────────────────────────────────────────────

def scrape_with_whois(
    log: Callable = print,
    delay: float = 1.2,
    proxies: list[str] = None,
) -> list[dict]:
    # Step 1 — TCP-test proxies, keep only alive ones
    if proxies:
        proxies = check_proxies(proxies, log=log)
        if not proxies:
            log("[Proxy] ⚠ No alive proxies found — falling back to direct connection.")
    else:
        log("[Proxy] No proxies configured — using direct connection.")

    # Step 2 — Scrape domain list
    domains = scrape_hugedomains(log=log)
    results = []
    total = len(domains)

    # Step 3 — WHOIS lookup per domain
    for i, row in enumerate(domains, 1):
        log(f"[{i}/{total}] {row['domain']} — fetching WHOIS...")
        whois = whois_lookup(row["domain"], proxies=proxies, log=log)
        results.append({**row, **whois})
        time.sleep(delay)

    log(f"[Done] ✓ {len(results)} domains collected.")
    return results
