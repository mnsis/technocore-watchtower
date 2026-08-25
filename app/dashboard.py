"""Local read-only FastAPI dashboard for Watchtower telemetry."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import WatchtowerConfig
from .runtime import PollingWorker, RuntimeState
from .storage import SECURITY_FLAG_NAMES, SEVERITY_NAMES, EventStore
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
        if request.url.path.startswith("/api/") or request.url.path == "/health":
            response.headers["Cache-Control"] = "no-store"
        return response

    def context(request: Request) -> dict[str, object]:
        return {
            "request": request,
            "current_path": request.url.path,
            "runtime": runtime_state.snapshot(),
            "summary": store.dashboard_summary(),
        }

    @dashboard.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={
                **context(request),
                "events": store.recent_events(10),
                "rooms": store.api_room_summaries(),
                "charts": store.dashboard_charts(),
            },
        )

    @dashboard.get("/events", response_class=HTMLResponse)
    async def events(
        request: Request,
        room: str | None = None,
        severity: str | None = None,
        flag: str | None = None,
        before_id: int | None = Query(default=None, ge=1),
    ):
        selected_room = validated_room(room) if room else None
        selected_severity = severity.upper() if severity else None
        if selected_severity is not None and selected_severity not in SEVERITY_NAMES:
            raise HTTPException(status_code=422, detail="unknown severity")
        selected_flag = flag.upper() if flag else None
        if selected_flag is not None and selected_flag not in SECURITY_FLAG_NAMES:
            raise HTTPException(status_code=422, detail="unknown security flag")
        selected_events, next_before_id = store.filtered_events(
            room=selected_room,
            severity=selected_severity,
            flag=selected_flag,
            before_id=before_id,
        )
        return templates.TemplateResponse(
            request=request,
            name="events.html",
            context={
                **context(request),
                "events": selected_events,
                "next_before_id": next_before_id,
                "filters": {
                    "room": selected_room,
                    "severity": selected_severity,
                    "flag": selected_flag,
                },
                "room_options": store.api_room_summaries(),
                "severity_options": SEVERITY_NAMES,
                "flag_options": SECURITY_FLAG_NAMES,
            },
        )

    @dashboard.get("/rooms", response_class=HTMLResponse)
    async def rooms(request: Request):
        return templates.TemplateResponse(
            request=request,
            name="rooms.html",
            context={**context(request), "rooms": store.api_room_summaries()},
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

    def validated_room(room: str) -> str:
        try:
            return TechnocoreTransport.validate_room(room)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @dashboard.get("/api/v1/summary")
    async def api_summary(hours: int = Query(default=24, ge=1, le=8760)):
        return {"api_version": "v1", **store.security_report(hours)}

    @dashboard.get("/api/v1/events")
    async def api_events(
        room: str | None = None,
        severity: str | None = None,
        flag: str | None = None,
        limit: int = Query(default=50, ge=1, le=200),
        before_id: int | None = Query(default=None, ge=1),
    ):
        selected_room = validated_room(room) if room is not None else None
        selected_severity = severity.upper() if severity is not None else None
        if selected_severity is not None and selected_severity not in SEVERITY_NAMES:
            raise HTTPException(status_code=422, detail="unknown severity")
        selected_flag = flag.upper() if flag is not None else None
        if selected_flag is not None and selected_flag not in SECURITY_FLAG_NAMES:
            raise HTTPException(status_code=422, detail="unknown security flag")
        events, next_before_id = store.api_events(
            room=selected_room,
            severity=selected_severity,
            flag=selected_flag,
            limit=limit,
            before_id=before_id,
        )
        return {
            "api_version": "v1",
            "events": events,
            "pagination": {"limit": limit, "next_before_id": next_before_id},
            "filters": {
                "room": selected_room,
                "severity": selected_severity,
                "flag": selected_flag,
                "before_id": before_id,
            },
        }

    @dashboard.get("/api/v1/rooms")
    async def api_rooms():
        return {"api_version": "v1", "rooms": store.api_room_summaries()}

    @dashboard.get("/api/v1/rooms/{room}")
    async def api_room(room: str):
        selected_room = validated_room(room)
        summaries = store.api_room_summaries(selected_room)
        if not summaries:
            raise HTTPException(status_code=404, detail="Observed room not found")
        return {"api_version": "v1", "room": summaries[0]}

    return dashboard


app = create_app()


def run_local() -> None:
    import uvicorn

    settings = DashboardSettings()
    uvicorn.run("app.dashboard:app", host=settings.host, port=settings.port, log_level="info")
