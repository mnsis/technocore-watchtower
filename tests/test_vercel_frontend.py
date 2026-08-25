import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VERCEL_ROOT = PROJECT_ROOT / "vercel"
BACKEND_ORIGIN = "https://watchtower.37.27.18.191.sslip.io"


def test_vercel_config_has_only_explicit_read_only_public_rewrites():
    config = json.loads((VERCEL_ROOT / "vercel.json").read_text())
    rewrites = {item["source"]: item["destination"] for item in config["rewrites"]}
    assert rewrites == {
        "/api/v1/summary": "/api/watchtower?route=summary",
        "/api/v1/events": "/api/watchtower?route=events",
        "/api/v1/rooms": "/api/watchtower?route=rooms",
        "/api/v1/rooms/:room": "/api/watchtower?route=room&room=:room",
        "/health": "/api/watchtower?route=health",
    }
    assert config["buildCommand"] == "sh build.sh"
    assert config["outputDirectory"] == "dist"


def test_vercel_security_headers_and_cache_controls_are_strict():
    config = json.loads((VERCEL_ROOT / "vercel.json").read_text())
    header_rules = {item["source"]: item["headers"] for item in config["headers"]}
    global_headers = {item["key"]: item["value"] for item in header_rules["/(.*)"]}
    assert "default-src 'self'" in global_headers["Content-Security-Policy"]
    assert "connect-src 'self'" in global_headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in global_headers["Content-Security-Policy"]
    assert global_headers["X-Content-Type-Options"] == "nosniff"
    api_headers = {item["key"]: item["value"] for item in header_rules["/api/v1/:path*"]}
    assert api_headers == {
        "Cache-Control": "no-store",
        "x-vercel-enable-rewrite-caching": "0",
    }


def test_vercel_browser_assets_use_relative_api_paths_and_safe_dom_updates():
    pages = "\n".join(
        (VERCEL_ROOT / name).read_text()
        for name in ("index.html", "events.html", "rooms.html")
    )
    live_script = (PROJECT_ROOT / "web" / "static" / "live.js").read_text()
    assert BACKEND_ORIGIN not in live_script
    assert pages.count(
        f'data-stream-url="{BACKEND_ORIGIN}/api/v1/stream"'
    ) == 3
    assert 'fetchJson("/api/v1/summary?hours=24"' in live_script
    assert 'fetchJson("/api/v1/events?limit=20"' in live_script
    assert 'fetchJson("/api/v1/rooms"' in live_script
    assert ".textContent" in live_script
    assert ".innerHTML" not in live_script
    assert "data-static-frontend" in pages
    config = json.loads((VERCEL_ROOT / "vercel.json").read_text())
    csp = next(
        header["value"]
        for rule in config["headers"]
        for header in rule["headers"]
        if header["key"] == "Content-Security-Policy"
    )
    assert f"connect-src 'self' {BACKEND_ORIGIN}" in csp


def test_vercel_proxy_is_allowlisted_and_rejects_write_methods():
    proxy = (VERCEL_ROOT / "api" / "watchtower.js").read_text()
    assert f'const BACKEND_ORIGIN = "{BACKEND_ORIGIN}"' in proxy
    assert 'request.method !== "GET" && request.method !== "HEAD"' in proxy
    assert "response.status(405)" in proxy
    assert "redirect: \"error\"" in proxy
    assert "ROUTES[routeName]" in proxy
    assert "request.url" not in proxy
    assert "message_body" not in proxy
