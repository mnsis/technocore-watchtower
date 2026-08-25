<p align="center"><img src="web/static/watchtower-mark.svg" width="96" height="96" alt="Technocore Watchtower segmented observation mark"></p>
<h1 align="center">Technocore Watchtower</h1>
<p align="center">Read-only security observability for Technocore</p>
<p align="center"><a href="https://technocore-watchtower.vercel.app">Live Dashboard</a> · <a href="https://watchtower.37.27.18.191.sslip.io/api/v1/summary?hours=24">API</a> · <a href="https://github.com/mnsis/technocore-watchtower">Source</a></p>

Watchtower monitors configured public Technocore rooms. It stores event metadata,
shows server-exposed DID information, warns about unsigned privileged-looking
names, and detects documented Technocore write-route patterns.

> Independent community project. Technocore Watchtower is not official FLOP Labs
> software and does not speak for FLOP Labs or Technocore operators.

## What it does

- Monitors configured public Technocore rooms
- Shows server-exposed signed DID metadata
- Warnings for unsigned privileged-looking names
- Conservative protected-name confusable detection in the risk-v2 shadow engine
- Static detection of documented Technocore write-capable URL patterns
- Produces explainable scanner flags and severity levels
- Stores event metadata in SQLite
- Includes CLI reports and a JSON API
- Streams updates with Server-Sent Events (SSE)
- Serves public Overview, Events, and Rooms pages over HTTPS

New observations normally appear in the dashboard without a page reload. SSE is
the primary live transport; aggregate summary and room updates are debounced to
limit load. Five-second polling activates only as a fallback when SSE is
temporarily unavailable and stops after the stream recovers.

## CLI report

The CLI report summarizes identity signals, write-route detections, severity
counts, scanner flags, and flagged rooms.

```bash
python -m app.report --hours 24
```

For JSON output:

```bash
python -m app.report --hours 24 --json
```

The JSON output contains aggregate metadata for scripts and monitoring systems.

## For developers and agents

The versioned API is GET-only. It does not return message bodies or detected URLs
and does not enable wildcard CORS.

```bash
curl 'https://watchtower.37.27.18.191.sslip.io/api/v1/summary?hours=24'
curl 'https://watchtower.37.27.18.191.sslip.io/api/v1/events?severity=high&limit=20'
```

Available endpoints:

- `GET /api/v1/summary`
- `GET /api/v1/events`
- `GET /api/v1/rooms`
- `GET /api/v1/rooms/{room}`

Event filtering supports room, severity, scanner flag, result limit, and the
exclusive `before_id` pagination cursor. The public dashboard uses
`GET /api/v1/stream` for live updates. Browser access to the stream is restricted
to the production Vercel origin; it is not a general cross-origin endpoint.

The API reports Watchtower's observations, not a complete index of Technocore.

## Read-only by design

Watchtower requests fixed public read endpoints. It does not construct known
write routes. Redirects are blocked, TLS verification stays enabled, room names
are validated locally, and requests stay on the configured origin.

Watchtower parses URL structure without resolving, previewing, or following the
URL. Message content cannot select a network destination.

Raw message bodies are processed briefly in memory and are not stored. SQLite
contains timestamps, room and sequence metadata, sender/identity metadata,
scanner flags, severity, and a SHA-256 message hash. Detected message URLs are
not persisted.

## Security model

The scanner emits these deterministic indicators:

- `DID_PRESENT`: a `did:key` identifier appeared in normalized metadata. This is
  not independent signature verification.
- `UNSIGNED_PRIVILEGED_NAME`: a configured privileged-looking display name
  appeared without signed identity metadata.
- `POTENTIAL_TECHNOCORE_WRITE_URL`: static URL structure matched a documented
  write-capable Technocore route on a configured Technocore host. The URL was not
  contacted.
- `SUSPICIOUS_COMBINATION`: multiple objective indicators occurred together. It
  is not proof of malicious intent.

Watchtower is not an identity authority or reputation system. It does not create
DIDs, hold keys or wallets, or send messages to Technocore.

For Technocore JSON records, the adapter treats a canonical Ed25519 `did:key` in
`from` together with the signed-record-only integer `nonce` as server-exposed
signed identity metadata. Watchtower does not currently re-verify that record's
signature independently because the stored JSON record does not include the
signature itself.

See [SECURITY.md](SECURITY.md) for the threat model and vulnerability-reporting
guidance.

### Risk-v2 shadow model

`risk-v2-shadow-1` is a versioned event-risk model. It evaluates identity,
impersonation, capability, behavioral, and bounded temporal signals. Name
normalization and confusable matching are intentionally conservative.

Risk-v2 runs in **shadow mode**. Its results are stored separately and do not
replace the public severity classification. Historical context can modify an
event score, but Watchtower does not assign permanent DID reputation scores.
Run `python -m app.report --risk-v2` to inspect aggregate shadow results.

Zero HIGH or CRITICAL events is a valid result when the evidence does not meet
those thresholds. Scores and flags are indicators, not conclusions about intent.

## Architecture

```text
Technocore public rooms
  -> VPS Watchtower collector
  -> metadata-only SQLite
  -> scanner + risk-v2 shadow processing
  -> read-only API + SSE
  -> Vercel public dashboard
  -> humans / agents / monitoring tools
```

The VPS collects and scans observations, stores metadata, and serves the API and
SSE stream. Vercel serves the frontend and proxies allowlisted API routes. The
browser connects directly to the VPS stream under an exact-origin CORS policy.

## Requirements

- Python 3.12 or newer
- A POSIX-like local development environment

## Installation

```bash
git clone https://github.com/mnsis/technocore-watchtower.git
cd technocore-watchtower
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

No API token, DID, wallet, or `.env` file is required. Polling is disabled by
default in the dashboard application.

## Run locally

Start the dashboard on loopback only:

```bash
source .venv/bin/activate
uvicorn app.dashboard:app --host 127.0.0.1 --port 8787
```

Then open `http://127.0.0.1:8787/`. Do not change the bind address for an
internet-facing deployment without completing a separate security and deployment
review.

## Dashboard

The dashboard shows live totals, 24-hour charts, filtered events, room summaries,
runtime health, and API links.
Charts use a small local canvas renderer; no remote frontend assets, analytics,
or message-derived resources are loaded.

The production dashboard is hosted at
[https://technocore-watchtower.vercel.app](https://technocore-watchtower.vercel.app).

![Technocore Watchtower security dashboard](docs/dashboard.png)

Run the tests and publication checks:

```bash
pytest
ruff check .
mypy app
pip-audit
```

## Deployment

- **Frontend:** Vercel serves the public dashboard at
  [technocore-watchtower.vercel.app](https://technocore-watchtower.vercel.app).
- **Collector, API, and SSE:** a VPS continuously observes configured
  rooms and exposes the backend at
  [watchtower.37.27.18.191.sslip.io](https://watchtower.37.27.18.191.sslip.io).
- **Application stack:** FastAPI, SQLite, systemd, and Nginx on the VPS; static
  HTML, local CSS, and vanilla JavaScript on Vercel.

The VPS application remains loopback-bound behind Nginx. Vercel does not run the
collector, polling worker, SQLite database, or Technocore transport.

## Data and privacy

The default database path is `data/watchtower.sqlite3`; database files are ignored
by Git. There is no original-message view. Sender names, DIDs, room names, and
other remote fields are untrusted metadata.

Watchtower does not verify identity trust, persist message bodies or detected
URLs, follow message-derived URLs, enrich identities externally, or write to
Technocore. Flags describe observed conditions, not intent.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). By contributing, you agree that your
contribution is licensed under the Apache License 2.0.

## License

Apache License 2.0. See [LICENSE](LICENSE).
