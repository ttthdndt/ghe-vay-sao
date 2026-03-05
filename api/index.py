import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fastapi import FastAPI, BackgroundTasks, Query
from fastapi.responses import StreamingResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import io
import csv
import time
import asyncio
from collections import deque
from scraper import scrape_with_whois

app = FastAPI(title="HugeDomains Scraper API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

HTML_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "index.html")

# ── In-memory state ───────────────────────────────────────────────────────────
_cache: dict = {
    "data": [],
    "last_updated": None,
    "running": False,
}
_logs: deque = deque(maxlen=500)   # ring buffer — last 500 log lines
_log_listeners: list = []          # SSE subscriber queues


def _emit(msg: str):
    """Append a log line and push to all SSE listeners."""
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    _logs.append(line)
    for q in list(_log_listeners):
        try:
            q.put_nowait(line)
        except Exception:
            pass


# ── HTML UI ───────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def index():
    with open(HTML_PATH) as f:
        return f.read()


# ── Domains API ───────────────────────────────────────────────────────────────

@app.get("/api/domains")
def get_domains(
    search: str = Query(default=""),
    min_price: int = Query(default=0),
    max_price: int = Query(default=99999),
):
    def parse_price(p: str) -> int:
        try:
            return int(p.replace("$", "").replace(",", ""))
        except Exception:
            return 0

    data = _cache["data"]
    if search:
        data = [d for d in data if search.lower() in d["domain"].lower()]
    data = [d for d in data if min_price <= parse_price(d.get("price", "0")) <= max_price]

    return {
        "total": len(data),
        "last_updated": _cache["last_updated"],
        "running": _cache["running"],
        "data": data,
    }


# ── Scrape trigger ────────────────────────────────────────────────────────────

@app.post("/api/scrape")
def trigger_scrape(background_tasks: BackgroundTasks):
    if _cache["running"]:
        return {"message": "Scrape already in progress"}
    _logs.clear()
    background_tasks.add_task(_run_scrape)
    return {"message": "Scrape started"}


def _run_scrape():
    _cache["running"] = True
    _cache["data"] = []
    try:
        results = scrape_with_whois(log=_emit, delay=1.2)
        _cache["data"] = results
        _cache["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    except Exception as e:
        _emit(f"[ERROR] {e}")
    finally:
        _cache["running"] = False


# ── SSE log stream ────────────────────────────────────────────────────────────

@app.get("/api/logs/stream")
async def log_stream():
    """
    Server-Sent Events endpoint.
    Client connects once; receives new log lines in real time.
    """
    import asyncio
    from asyncio import Queue

    q: Queue = asyncio.Queue()
    _log_listeners.append(q)

    # Replay existing logs so the client doesn't miss anything
    history = list(_logs)

    async def event_generator():
        try:
            # Send backlog
            for line in history:
                yield f"data: {line}\n\n"
            # Stream new lines
            while True:
                try:
                    line = await asyncio.wait_for(q.get(), timeout=25)
                    yield f"data: {line}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"   # keep-alive
        finally:
            _log_listeners.remove(q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/logs")
def get_logs():
    """Return all buffered log lines as JSON (for initial page load)."""
    return {"logs": list(_logs), "running": _cache["running"]}


# ── Export ────────────────────────────────────────────────────────────────────

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
