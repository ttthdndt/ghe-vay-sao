import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fastapi import FastAPI, BackgroundTasks, Query
from fastapi.responses import StreamingResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import io
import csv
import time
from scraper import scrape_with_whois, whois_lookup

app = FastAPI(title="HugeDomains Scraper API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory cache: { "data": [...], "last_updated": timestamp }
_cache: dict = {"data": [], "last_updated": None, "running": False}


# ── HTML UI ──────────────────────────────────────────────────────────────────

HTML_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "index.html")

@app.get("/", response_class=HTMLResponse)
def index():
    with open(HTML_PATH) as f:
        return f.read()


# ── API routes ───────────────────────────────────────────────────────────────

@app.get("/api/domains")
def get_domains(
    search: str = Query(default="", description="Filter by domain name"),
    min_price: int = Query(default=0),
    max_price: int = Query(default=99999),
):
    data = _cache["data"]

    # Filter by search
    if search:
        data = [d for d in data if search.lower() in d["domain"].lower()]

    # Filter by price (strip $ and commas)
    def parse_price(p: str) -> int:
        try:
            return int(p.replace("$", "").replace(",", ""))
        except Exception:
            return 0

    data = [d for d in data if min_price <= parse_price(d.get("price", "0")) <= max_price]

    return {
        "total": len(data),
        "last_updated": _cache["last_updated"],
        "running": _cache["running"],
        "data": data,
    }


@app.post("/api/scrape")
def trigger_scrape(background_tasks: BackgroundTasks):
    if _cache["running"]:
        return {"message": "Scrape already in progress"}
    background_tasks.add_task(_run_scrape)
    return {"message": "Scrape started"}


def _run_scrape():
    _cache["running"] = True
    try:
        results = scrape_with_whois()
        _cache["data"] = results
        _cache["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    finally:
        _cache["running"] = False


@app.get("/api/export")
def export_csv(search: str = Query(default="")):
    data = _cache["data"]
    if search:
        data = [d for d in data if search.lower() in d["domain"].lower()]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["domain", "price", "created", "expires"])
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
    return {
        "total_domains": len(_cache["data"]),
        "last_updated": _cache["last_updated"],
        "running": _cache["running"],
    }
