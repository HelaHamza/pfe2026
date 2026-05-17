 #la façade HTTP. Il reçoit les requêtes HTTP, valide les paramètres, appelle le bon controller, 
 #et retourne la réponse. Il ne contient aucune logique métier. C'est juste le routeur.

import asyncio
import json
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from backend.controllers.analyse_controller import run_analyse, get_state
from backend.controllers.stats_controller   import StatsController
from backend.controllers.results_controller import ResultsController

app = FastAPI(title="IDS API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── HEALTH ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}

# ── PIPELINE ──────────────────────────────────────────────────────────────────

@app.post("/run/analyse")
async def start_analyse():
    state = get_state()
    if state["running"]:
        return {"status": "already_running", "started_at": state["started_at"]}
    asyncio.create_task(run_analyse())
    return {"status": "started"}

@app.get("/run/analyse/status")
def analyse_status():
    state = get_state()
    return {
        "running":    state["running"],
        "done":       state["done"],
        "started_at": state["started_at"],
        "error":      state["error"],
        "last_log":   state["logs"][-1]["msg"] if state["logs"] else None,
    }

@app.get("/run/analyse/stream")
async def stream_progress():
    async def generator():
        sent = 0
        while True:
            state = get_state()
            logs  = state["logs"]
            while sent < len(logs):
                yield f"data: {json.dumps(logs[sent])}\n\n"
                sent += 1
            if state["done"] and sent >= len(logs) and sent > 0:
                yield f"data: {json.dumps({'msg': '__DONE__'})}\n\n"
                break
            yield ": keepalive\n\n"
            await asyncio.sleep(0.5)
    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

# ── STATS ─────────────────────────────────────────────────────────────────────

@app.get("/stats")
def get_stats():
    return StatsController.get_stats()

@app.get("/stats/timeline")
def get_timeline(days: int = Query(7, ge=1, le=30)):
    return StatsController.get_timeline(days)

@app.get("/stats/by-level")
def get_by_level():
    return StatsController.get_by_level()

@app.get("/stats/by-source")
def get_by_source():
    return StatsController.get_by_source()

# ── RÉSULTATS ─────────────────────────────────────────────────────────────────

@app.get("/results")
def get_results(
    limit:  int = Query(100, ge=1, le=200),
    level:  str = Query(None),
    source: str = Query(None),
):
    return ResultsController.get_results(limit, level=level, source=source)

@app.get("/results/{doc_type}/{doc_id}")
def get_detail(doc_type: str, doc_id: str):
    try:
        return ResultsController.get_detail(doc_type, doc_id)
    except ValueError as e:
        raise HTTPException(404, str(e))