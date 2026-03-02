import requests
from bs4 import BeautifulSoup
import re
import time
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

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
    maxrows=100,
    catsearch=0,
    sort="PriceAsc",
)


# ── Proxy Manager ─────────────────────────────────────────────────────────────

class ProxyManager:
    """
    Rotating proxy pool. Format per entry: IP:Port:User:Pass (or IP:Port)

    Example:
        proxies = [
            "123.45.67.89:8080:myuser:mypass",
            "98.76.54.32:3128:user2:pass2",
        ]
        pm = ProxyManager(proxies)
    """

    def __init__(self, proxy_list: list[str]):
        self.proxies = list(proxy_list)
        self._index = 0

    def _parse(self, proxy_str: str) -> dict:
        parts = proxy_str.strip().split(":")
        if len(parts) == 4:
            ip, port, user, password = parts
            url = f"http://{user}:{password}@{ip}:{port}"
        elif len(parts) == 2:
            ip, port = parts
            url = f"http://{ip}:{port}"
        else:
            raise ValueError(f"Bad proxy format: {proxy_str!r}. Use IP:Port:User:Pass")
        return {"http": url, "https": url}

    @property
    def current(self) -> str | None:
        if not self.proxies:
            return None
        return self.proxies[self._index % len(self.proxies)]

    def current_dict(self) -> dict | None:
        p = self.current
        return self._parse(p) if p else None

    def remove_current(self):
        if not self.proxies:
            return
        bad = self.proxies[self._index % len(self.proxies)]
        logger.warning(f"❌ Removing blocked proxy: {bad} ({len(self.proxies)-1} remaining)")
        self.proxies.pop(self._index % len(self.proxies))
        if self.proxies:
            self._index = self._index % len(self.proxies)

    def rotate(self):
        if len(self.proxies) > 1:
            self._index = (self._index + 1) % len(self.proxies)
            logger.info(f"🔄 Rotated → {self.current}")

    def __len__(self):
        return len(self.proxies)

    def __repr__(self):
        return f"<ProxyManager {len(self.proxies)} proxies, current={self.current}>"


# ── Block detection ───────────────────────────────────────────────────────────

BLOCK_SIGNALS = ["access denied", "too many requests", "rate limit",
                 "blocked", "captcha", "unusual traffic"]

def is_blocked(resp: requests.Response) -> bool:
    if resp.status_code in (403, 429, 503):
        return True
    return any(s in resp.text.lower() for s in BLOCK_SIGNALS)

def block_reason(resp: requests.Response) -> str:
    """Return a short human-readable reason for the block."""
    if resp.status_code == 403:
        return "403 Forbidden"
    if resp.status_code == 429:
        return "429 Too Many Requests"
    if resp.status_code == 503:
        return "503 Service Unavailable"
    text = resp.text.lower()
    for s in BLOCK_SIGNALS:
        if s in text:
            return s.title()
    return f"HTTP {resp.status_code}"


# ── Robust GET with automatic proxy rotation ──────────────────────────────────

def get_with_proxy(
    url: str,
    headers: dict,
    proxy_manager: "ProxyManager | None" = None,
    timeout: int = 12,
    max_retries: int = 5,
    **kwargs,
) -> requests.Response:
    last_exc = None

    for attempt in range(max_retries):
        proxy_dict  = proxy_manager.current_dict() if proxy_manager else None
        proxy_label = proxy_manager.current        if proxy_manager else "direct"

        try:
            resp = requests.get(url, headers=headers, proxies=proxy_dict,
                                timeout=timeout, **kwargs)

            if is_blocked(resp):
                reason = block_reason(resp)
                logger.warning(f"⛔ Blocked [{proxy_label}] {reason} → {url}")
                if proxy_manager and len(proxy_manager) > 0:
                    proxy_manager.remove_current()
                    continue
                return resp

            return resp

        except requests.exceptions.Timeout as e:
            last_exc = e
            logger.warning(f"⏱ Timeout [{proxy_label}]: {url}")
            if proxy_manager and len(proxy_manager) > 0:
                proxy_manager.remove_current()
            else:
                time.sleep(2)

        except (requests.exceptions.ProxyError,
                requests.exceptions.ConnectionError) as e:
            last_exc = e
            logger.warning(f"⚠️  Connection error [{proxy_label}]: {e}")
            if proxy_manager and len(proxy_manager) > 0:
                proxy_manager.remove_current()
            else:
                time.sleep(2)

    logger.warning("⚠️  All proxies exhausted — falling back to direct connection.")
    return requests.get(url, headers=headers, timeout=timeout, **kwargs)


# ── HugeDomains scraper ───────────────────────────────────────────────────────

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


def scrape_hugedomains(proxy_manager: "ProxyManager | None" = None) -> list[dict]:
    all_rows, start = [], 1
    while True:
        logger.info(f"Fetching HugeDomains records {start}–{start+99}…")
        resp = get_with_proxy(BASE_URL, headers=HEADERS, proxy_manager=proxy_manager,
                              params={**BASE_PARAMS, "start": start})
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")
        rows = parse_hugedomains_page(soup)
        logger.info(f"  → {len(rows)} domains found")
        all_rows.extend(rows)
        if not rows or not soup.find("a", string=re.compile(r"(?i)next")):
            break
        start += 100
        time.sleep(1)

    seen, unique = set(), []
    for row in all_rows:
        if row["domain"] not in seen:
            seen.add(row["domain"])
            unique.append(row)
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


def whois_lookup(domain: str, proxy_manager: "ProxyManager | None" = None) -> dict:
    """
    Returns dict with keys: created, expires, error (None if success).
    """
    url = f"https://who.is/whois/{domain}"
    try:
        resp = get_with_proxy(url, headers=WHOIS_HEADERS, proxy_manager=proxy_manager)

        # Blocked even after retries
        if is_blocked(resp):
            reason = block_reason(resp)
            logger.error(f"  ⛔ WHOIS blocked [{domain}]: {reason}")
            return {"created": "N/A", "expires": "N/A", "error": reason}

        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")
        created = get_date_by_label(soup, "Created")
        expires = get_date_by_label(soup, "Expires")
        logger.info(f"  ✅ WHOIS {domain} → Created: {created} | Expires: {expires}")
        return {"created": created, "expires": expires, "error": None}

    except requests.exceptions.Timeout:
        msg = "Timeout"
        logger.error(f"  ⏱ WHOIS timeout [{domain}]")
        return {"created": "N/A", "expires": "N/A", "error": msg}

    except requests.exceptions.ConnectionError as e:
        msg = f"Connection error: {e}"
        logger.error(f"  ❌ WHOIS connection error [{domain}]: {e}")
        return {"created": "N/A", "expires": "N/A", "error": msg}

    except Exception as e:
        msg = str(e)
        logger.error(f"  ❌ WHOIS failed [{domain}]: {e}")
        return {"created": "N/A", "expires": "N/A", "error": msg}


# ── Full pipeline ─────────────────────────────────────────────────────────────

def scrape_with_whois(
    proxy_list: list[str] | None = None,
    delay: float = 1.2,
) -> list[dict]:
    """
    Full pipeline: scrape HugeDomains → enrich with WHOIS dates.

    Args:
        proxy_list: List of proxies in "IP:Port:User:Pass" format.
        delay:      Seconds between WHOIS requests.
    """
    pm = ProxyManager(proxy_list) if proxy_list else None
    if pm:
        logger.info(f"🌐 Proxy pool loaded: {len(pm)} proxies")
    else:
        logger.info("🌐 No proxies — using direct connection")

    domains = scrape_hugedomains(proxy_manager=pm)
    results = []

    for row in domains:
        whois = whois_lookup(row["domain"], proxy_manager=pm)
        results.append({**row, **whois})
        if pm and len(pm) > 1:
            pm.rotate()
        time.sleep(delay)

    errors = [r for r in results if r.get("error")]
    logger.info(f"✅ Done — {len(results)} domains | {len(errors)} WHOIS errors")
    return results
