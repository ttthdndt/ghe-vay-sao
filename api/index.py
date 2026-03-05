import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fastapi import FastAPI, BackgroundTasks, Query
from fastapi.responses import StreamingResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import io
import csv
import time
from scraper import scrape_with_whois

app = FastAPI(title="HugeDomains Scraper API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory cache
_cache: dict = {
    "data": [],
    "last_updated": None,
    "running": False,
    "error": None,        # fatal scrape-level error
}

# ── HTML UI ───────────────────────────────────────────────────────────────────

HTML_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "index.html")

@app.get("/", response_class=HTMLResponse)
def index():
    with open(HTML_PATH) as f:
        return f.read()


# ── API routes ────────────────────────────────────────────────────────────────

@app.get("/api/domains")
def get_domains(
    search: str = Query(default=""),
    min_price: int = Query(default=0),
    max_price: int = Query(default=99999),
):
    data = _cache["data"]
    if search:
        data = [d for d in data if search.lower() in d["domain"].lower()]

    def parse_price(p: str) -> int:
        try:
            return int(p.replace("$", "").replace(",", ""))
        except Exception:
            return 0

    data = [d for d in data if min_price <= parse_price(d.get("price", "0")) <= max_price]

    whois_errors = [
        {"domain": d["domain"], "error": d["error"]}
        for d in data if d.get("error")
    ]

    return {
        "total": len(data),
        "last_updated": _cache["last_updated"],
        "running": _cache["running"],
        "fatal_error": _cache["error"],
        "whois_errors": whois_errors,
        "data": data,
    }


class ScrapeRequest(BaseModel):
    proxy_list: list[str] = []

@app.post("/api/scrape")
def trigger_scrape(body: ScrapeRequest, background_tasks: BackgroundTasks):
    if _cache["running"]:
        return {"message": "Scrape already in progress"}
    _cache["error"] = None
    proxies = body.proxy_list if body.proxy_list else None
    background_tasks.add_task(_run_scrape, proxies)
    return {"message": "Scrape started", "proxies_loaded": len(body.proxy_list)}


def _run_scrape(proxy_list=None):
    _cache["running"] = True
    _cache["error"] = None
    try:
        results = scrape_with_whois(proxy_list=proxy_list)
        _cache["data"] = results
        _cache["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    except Exception as e:
        _cache["error"] = str(e)
    finally:
        _cache["running"] = False


@app.get("/api/export")
def export_csv(search: str = Query(default="")):
    data = _cache["data"]
    if search:
        data = [d for d in data if search.lower() in d["domain"].lower()]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["domain", "price", "created", "expires", "error"])
    writer.writeheader()
    writer.writerows(data)
    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=hugedomains_sport.csv"},
    )


@app.get("/api/status")
def status():
    errors = [d for d in _cache["data"] if d.get("error")]
    return {
        "total_domains": len(_cache["data"]),
        "whois_errors": len(errors),
        "last_updated": _cache["last_updated"],
        "running": _cache["running"],
        "fatal_error": _cache["error"],
    }
