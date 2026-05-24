from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Routers métier (existants)
from views.auth_views      import router as auth_router
from views.profile_views   import router as profile_router
from views.admin_views     import router as admin_router
from views.feedback_views  import router as feedback_router

# Routers SOC (nouveaux)
from views.analyse_views   import router as analyse_router
from views.results_views   import router as results_router
from views.dashboard_views import router as dashboard_router

from views.ai_dashboard_views import router as ai_dashboard_router

app = FastAPI(title="PFE 2026 API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers métier
app.include_router(auth_router)
app.include_router(profile_router)
app.include_router(admin_router)
app.include_router(feedback_router)

# Routers SOC
app.include_router(analyse_router)
app.include_router(results_router)
app.include_router(dashboard_router)



app.include_router(ai_dashboard_router)


@app.get("/")
def home():
    return {"message": "API running"}