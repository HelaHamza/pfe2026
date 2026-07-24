"""
main.py
=======
Point d'entrée FastAPI. COMPOSITION UNIQUEMENT : montage des routeurs,
middleware, cycle de vie. Aucune logique métier, aucun accès base direct.
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import config as CFG
from core.database import close_client, ping

from views.auth_views import router as auth_router
from views.profile_views import router as profile_router
from views.admin_views import router as admin_router
from views.feedback_views import router as feedback_router

# Routeurs SOC
from views.analyse_views import router as analyse_router
from views.results_views import router as results_router
from views.dashboard_views import router as dashboard_router
from views.ai_dashboard_views import router as ai_dashboard_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s :: %(message)s")
log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # La panne de base se découvre AU DÉMARRAGE, pas à la première requête
    # utilisateur sous forme de 500 opaque.
    try:
        ping()
        log.info("Connexion MongoDB établie.")
    except Exception as e:
        log.critical("MongoDB INDISPONIBLE au démarrage : %s", e)
    yield
    close_client()


app = FastAPI(title="Sentinel — PFE 2026 API", version="2.2.0",
              lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CFG.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

for r in (auth_router, profile_router, admin_router, feedback_router,
          analyse_router, results_router, dashboard_router,
          ai_dashboard_router):
    app.include_router(r)


@app.get("/", tags=["Health"])
def home():
    return {"message": "API running"}


@app.get("/health", tags=["Health"])
def health():
    """Sonde de disponibilité — utile pour la démo et pour la CI."""
    try:
        ping()
        return {"status": "ok", "mongo": "up"}
    except Exception as e:
        return {"status": "degraded", "mongo": "down", "detail": str(e)}