"""
Sentinellama web GUI - FastAPI backend.

Serves the dashboard and exposes:
  GET  /                 -> dashboard HTML
  GET  /api/status       -> per-log monitoring state + config
  POST /api/start        -> start monitors (body {"log": name} for one, empty for all)
  POST /api/stop         -> stop monitors  (body {"log": name} for one, empty for all)
  GET  /api/alerts       -> recent alert history
  POST /api/analyze      -> analyze a pasted log line on demand
  GET  /api/search?q=    -> semantic search over the MITRE knowledge base
  WS   /ws               -> live alert stream

Run with:  python run_web.py   (or: python -m uvicorn app:app --reload)
"""
import asyncio
import os
import queue
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

import core

# The monitor depends on pywin32; guard the import so the rest of the API
# (manual analysis, search, history) still works on non-Windows machines.
try:
    from monitor import IDSMonitor, LOG_CONFIGS
    MONITOR_AVAILABLE = True
    MONITOR_IMPORT_ERROR = None
except Exception as e:  # pragma: no cover - platform dependent
    IDSMonitor = None
    LOG_CONFIGS = {}
    MONITOR_AVAILABLE = False
    MONITOR_IMPORT_ERROR = str(e)

app = FastAPI(title="Sentinellama")

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

# Thread-safe bridge: monitor threads -> async broadcaster -> websocket clients.
alert_queue: "queue.Queue" = queue.Queue()
clients: set = set()


def _on_alert(alert):
    alert_queue.put(alert)


# One independent monitor per configured log, so an access failure on
# Security (needs admin) doesn't take down System/Application.
monitors = (
    {name: IDSMonitor(on_alert=_on_alert, log_name=name) for name in LOG_CONFIGS}
    if MONITOR_AVAILABLE else {}
)


class AnalyzeRequest(BaseModel):
    log: str


class LogTarget(BaseModel):
    log: Optional[str] = None


@app.on_event("startup")
async def _startup():
    asyncio.create_task(_broadcaster())


async def _broadcaster():
    """Drain the alert queue and fan out to every connected websocket."""
    loop = asyncio.get_event_loop()
    while True:
        alert = await loop.run_in_executor(None, alert_queue.get)
        dead = set()
        for ws in clients:
            try:
                await ws.send_json({"type": "alert", "data": alert})
            except Exception:
                dead.add(ws)
        clients.difference_update(dead)


def _targets(req: Optional[LogTarget]):
    """Resolve a start/stop request to a list of monitors, or an error."""
    if req and req.log:
        if req.log not in monitors:
            return None, JSONResponse(
                {"ok": False, "error": f"Unknown log '{req.log}'."}, status_code=404
            )
        return [req.log], None
    return list(monitors), None


# --- ROUTES ---
@app.get("/")
async def index():
    return FileResponse(os.path.join(WEB_DIR, "index.html"))


@app.get("/api/status")
async def status():
    logs = {
        name: {"running": m.running, "error": m.last_error}
        for name, m in monitors.items()
    }
    return {
        "monitor_available": MONITOR_AVAILABLE,
        "monitor_error": MONITOR_IMPORT_ERROR,
        "monitoring": any(m.running for m in monitors.values()),
        "logs": logs,
        "model": core.OLLAMA_MODEL,
        "index": core.INDEX_NAME,
    }


@app.post("/api/start")
async def start(req: Optional[LogTarget] = None):
    if not monitors:
        return JSONResponse(
            {"ok": False, "error": f"Monitoring unavailable: {MONITOR_IMPORT_ERROR}"},
            status_code=400,
        )
    names, err = _targets(req)
    if err:
        return err
    started = {name: monitors[name].start() for name in names}
    return {"ok": True, "started": started}


@app.post("/api/stop")
async def stop(req: Optional[LogTarget] = None):
    if not monitors:
        return JSONResponse({"ok": False, "error": "Monitoring unavailable"}, status_code=400)
    names, err = _targets(req)
    if err:
        return err
    stopped = {name: monitors[name].stop() for name in names}
    return {"ok": True, "stopped": stopped}


@app.get("/api/alerts")
async def alerts(limit: int = 200):
    loop = asyncio.get_event_loop()
    data = await loop.run_in_executor(None, core.load_alerts, limit)
    return {"alerts": data}


@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest):
    log = (req.log or "").strip()
    if not log:
        return JSONResponse({"ok": False, "error": "Empty log."}, status_code=400)
    loop = asyncio.get_event_loop()
    try:
        alert = await loop.run_in_executor(
            None, lambda: core.analyze_log(log, source="Manual")
        )
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)
    # Also push to the live feed so every open dashboard sees it.
    alert_queue.put(alert)
    return {"ok": True, "alert": alert}


@app.get("/api/search")
async def search(q: str, top_k: int = 5):
    q = (q or "").strip()
    if not q:
        return JSONResponse({"ok": False, "error": "Empty query."}, status_code=400)
    loop = asyncio.get_event_loop()
    try:
        results = await loop.run_in_executor(None, core.search_knowledge, q, top_k)
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)
    return {"ok": True, "results": results}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    clients.add(ws)
    try:
        while True:
            # We only push; this keeps the connection open and detects disconnects.
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        clients.discard(ws)
