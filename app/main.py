"""VDI Orchestrator — FastAPI app factory."""
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware

from .config import settings
from .database import init_schema, seed_default_template
from .routers import auth as auth_router
from .routers import portal as portal_router
from .routers import admin as admin_router
from .routers import api as api_router
from .services import session_monitor, proxmox

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("vdi-orchestrator")


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("VDI Orchestrator starting...")

    try:
        init_schema()
        seed_default_template()
    except Exception as e:
        log.error(f"DB init failed: {e}")

    try:
        ok = await proxmox.ping()
        log.info(f"Proxmox connection: {'OK' if ok else 'FAILED'}")
    except Exception as e:
        log.error(f"Proxmox ping failed: {e}")

    monitor_task = asyncio.create_task(session_monitor.run())
    log.info("Session monitor started")

    yield

    monitor_task.cancel()
    try:
        await monitor_task
    except asyncio.CancelledError:
        pass
    log.info("VDI Orchestrator stopped")


class AuthGateMiddleware(BaseHTTPMiddleware):
    PUBLIC_PATHS = {"/login", "/login/verify", "/login/verify/resend",
                    "/logout", "/api/health", "/favicon.ico"}

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if (path in self.PUBLIC_PATHS
                or path.startswith("/static")
                or path.startswith("/api/health")):
            return await call_next(request)
        if not request.session.get("user"):
            if path.startswith("/api/"):
                return JSONResponse({"detail": "Non authentifié"}, status_code=401)
            return RedirectResponse("/login", status_code=303)
        return await call_next(request)


def create_app() -> FastAPI:
    app = FastAPI(title="VDI Orchestrator", version="2.0.0", lifespan=lifespan)

    # Ordre important : les middlewares s'exécutent du dernier ajouté au premier.
    # AuthGate doit voir la session → il doit être ajouté APRÈS SessionMiddleware.
    # add_middleware empile : le dernier ajouté est le plus externe.
    # Ordre d'exécution : SessionMiddleware (externe) → AuthGate (interne) → route.
    # AuthGate a besoin de session → SessionMiddleware doit être plus externe.
    app.add_middleware(AuthGateMiddleware)
    app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY, same_site="lax")

    app.include_router(auth_router.router)
    app.include_router(portal_router.router)
    app.include_router(admin_router.router)
    app.include_router(api_router.router)

    return app


app = create_app()
