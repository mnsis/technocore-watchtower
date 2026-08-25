"""Local read-only FastAPI dashboard for Watchtower telemetry."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import WatchtowerConfig
from .runtime import PollingWorker, RuntimeState
from .storage import EventStore
from .transport import TechnocoreTransport
from .watcher import Watcher

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True, slots=True)
class DashboardSettings:
    host: str = "127.0.0.1"
    port: int = 8787
    database_path: Path = PROJECT_ROOT / "data" / "watchtower.sqlite3"
    monitored_rooms: tuple[str, ...] = ("lobby", "technocore")
    polling_enabled: bool = False

    def __post_init__(self) -> None:
        if self.host != "127.0.0.1":
            raise ValueError("Phase 3B dashboard must bind to 127.0.0.1")
        if not 1024 <= self.port <= 65535:
            raise ValueError("dashboard port must be an unprivileged TCP port")
        for room in self.monitored_rooms:
            TechnocoreTransport.validate_room(room)
        if not self.monitored_rooms or len(set(self.monitored_rooms)) != len(self.monitored_rooms):
            raise ValueError("monitored room allowlist must be non-empty and unique")


def create_app(settings: DashboardSettings | None = None) -> FastAPI:
    settings = settings or DashboardSettings()
    store = EventStore(settings.database_path)
    store.initialize()
    runtime_state = RuntimeState(settings.monitored_rooms)
    watcher = Watcher(store, WatchtowerConfig())
    transport = TechnocoreTransport()
    worker = PollingWorker(transport, watcher, runtime_state)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        stop_event = asyncio.Event()
        task = asyncio.create_task(worker.run(stop_event)) if settings.polling_enabled else None
        try:
            yield
        finally:
            if task is not None:
                stop_event.set()
                await task

    dashboard = FastAPI(
        title="Technocore Watchtower",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    templates = Jinja2Templates(directory=PROJECT_ROOT / "web" / "templates")
    dashboard.mount(
        "/static", StaticFiles(directory=PROJECT_ROOT / "web" / "static"), name="static"
    )

    dashboard.state.settings = settings
    dashboard.state.store = store
    dashboard.state.runtime = runtime_state
    dashboard.state.worker = worker

    @dashboard.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self'; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; "
            "frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

    def context(request: Request) -> dict[str, object]:
        return {
            "request": request,
            "runtime": runtime_state.snapshot(),
            "summary": store.dashboard_summary(),
        }

    @dashboard.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={**context(request), "events": store.recent_events(10), "rooms": store.observed_rooms()},
        )

    @dashboard.get("/events", response_class=HTMLResponse)
    async def events(request: Request):
        return templates.TemplateResponse(
            request=request,
            name="events.html",
            context={**context(request), "events": store.recent_events(100)},
        )

    @dashboard.get("/events/{event_id}", response_class=HTMLResponse)
    async def event_detail(request: Request, event_id: int):
        event = store.event_by_id(event_id)
        if event is None:
            raise HTTPException(status_code=404, detail="Event not found")
        return templates.TemplateResponse(
            request=request,
            name="event_detail.html",
            context={**context(request), "event": event},
        )

    @dashboard.get("/health")
    async def health():
        snapshot = runtime_state.snapshot()
        return {
            "status": "ok",
            "mode": "read-only",
            "polling_enabled": settings.polling_enabled,
            "monitored_rooms": snapshot["monitored_rooms"],
            "last_successful_poll": snapshot["last_successful_poll"],
            "total_transport_failures": snapshot["total_transport_failures"],
        }

    return dashboard


app = create_app()


def run_local() -> None:
    import uvicorn

    settings = DashboardSettings()
    uvicorn.run("app.dashboard:app", host=settings.host, port=settings.port, log_level="info")
