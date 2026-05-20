from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from views.auth_views     import router as auth_router
from views.profile_views  import router as profile_router
from views.admin_views    import router as admin_router
from views.feedback_views import router as feedback_router

app = FastAPI(title="PFE 2026 API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(profile_router)
app.include_router(admin_router)
app.include_router(feedback_router)


@app.get("/")
def home():
    return {"message": "API running"}


@app.get("/test-email")
def test_email():
    import traceback
    from core.email import send_admin_welcome, ADMIN_EMAIL
    try:
        send_admin_welcome(ADMIN_EMAIL)
        return {"status": "success", "sent_to": ADMIN_EMAIL}
    except Exception as e:
        return {"status": "error", "error": str(e), "trace": traceback.format_exc()}