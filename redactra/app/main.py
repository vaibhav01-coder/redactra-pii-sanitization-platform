from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.core.config import settings

# Resolve paths relative to this file so UI works from any cwd
_APP_DIR = Path(__file__).resolve().parent.parent
UI_DIR = _APP_DIR / "ui"
INDEX_HTML = UI_DIR / "index.html"
from app.database import Base, SessionLocal, engine
from app.routers import audit, auth, dashboard, files, scan, upload, users
from app.services.auto_destruct_service import auto_destruct_service
from app.services.bootstrap import ensure_admin_user
from app.services.file_service import ensure_storage_dirs

scheduler = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    ensure_storage_dirs(settings.raw_storage_path, settings.sanitized_storage_path)

    db = SessionLocal()
    try:
        ensure_admin_user(db, settings.initial_admin_email, settings.initial_admin_password)
    finally:
        db.close()

    global scheduler
    try:
        from apscheduler.schedulers.background import BackgroundScheduler

        scheduler = BackgroundScheduler()
        scheduler.add_job(auto_destruct_service.run_once, "interval", minutes=30)
        scheduler.start()
    except Exception:
        scheduler = None

    try:
        yield
    finally:
        if scheduler:
            scheduler.shutdown(wait=False)


app = FastAPI(title=settings.app_name, debug=settings.debug, lifespan=lifespan)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(upload.router)
app.include_router(files.router)
app.include_router(scan.router)
app.include_router(audit.router)
app.include_router(dashboard.router)

app.mount("/ui", StaticFiles(directory=str(UI_DIR), html=False), name="ui")


def _serve_ui():
    """Serve the SPA shell so the vanilla app can load."""
    return FileResponse(str(INDEX_HTML), media_type="text/html")


@app.get("/", response_class=FileResponse)
def root():
    return _serve_ui()


@app.get("/login", response_class=FileResponse)
def login_page():
    return _serve_ui()


@app.middleware("http")
async def spa_fallback(request: Request, call_next):
    """
    Serve the static UI for browser navigation routes like /login, /dashboard, etc.
    API routes keep working normally.
    """
    response = await call_next(request)
    if request.method != "GET":
        return response
    if response.status_code != 404:
        return response

    path = request.url.path
    # Never hijack actual static assets or FastAPI docs.
    if path.startswith("/ui/") or path.startswith("/docs") or path == "/openapi.json":
        return response

    # Serve SPA shell for browser navigations (HTML requests), plus known UI routes.
    accept = request.headers.get("accept", "")
    wants_html = "text/html" in accept.lower()
    is_ui_route = path in {"/", "/login", "/register", "/dashboard", "/upload", "/operations"} or (
        path.startswith("/files/") and path.count("/") == 2
    )
    if not (wants_html or is_ui_route):
        return response

    return FileResponse(str(INDEX_HTML), media_type="text/html")


@app.get("/health")
def health():
    return {"status": "ok", "service": settings.app_name}
