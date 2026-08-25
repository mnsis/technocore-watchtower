# Technocore Watchtower

Technocore Watchtower is a read-only security-observability tool for public
Technocore rooms. It records lightweight event metadata, surfaces identity
visibility, warns when unsigned nicknames resemble configured privileged names,
and statically identifies URLs shaped like documented Technocore write routes.

> Independent community project. Technocore Watchtower is not official FLOP Labs
> software and does not speak for FLOP Labs or Technocore operators.

## Security Report

The metadata-only CLI report gives developers and agents a quick view of identity
signals, write-capable URL detections, severity counts, scanner flags, and the
most frequently flagged observed rooms without requiring the dashboard.

```bash
python -m app.report --hours 24
```

Short output example:

```text
Technocore Watchtower — Security Report
Period: Last 24 hours
Rooms observed: <count>
Observations: <count>
```

For stable machine-readable output:

```bash
python -m app.report --hours 24 --json
```

JSON output contains aggregate metadata only and can be consumed by other agents,
scripts, or monitoring systems.

## Read-only API

The versioned metadata API is intended for agents, monitoring tools, security
dashboards, and developers investigating observed Technocore activity. It is
GET-only, has no wildcard CORS policy, and never returns raw message bodies or
message-derived URLs.

```bash
curl 'http://127.0.0.1:8787/api/v1/summary?hours=24'
curl 'http://127.0.0.1:8787/api/v1/events?severity=high&limit=20'
```

Available endpoints are `/api/v1/summary`, `/api/v1/events`, `/api/v1/rooms`,
and `/api/v1/rooms/{room}`. Event filtering supports room, severity, scanner
flag, result limit, and the exclusive `before_id` pagination cursor. The API
reports Watchtower's local observations only; it is not an official FLOP Labs
integration or a complete index of Technocore activity.

## Read-only by design

Watchtower's network transport exposes only fixed public read operations. It uses
GET because Technocore's public read API uses GET, but it never constructs known
write-capable GET routes. Redirects are blocked, TLS verification remains enabled,
room names are validated locally, and runtime requests stay on the configured
origin.

URLs found in messages are untrusted text. Watchtower parses their structure
without resolving, previewing, following, or otherwise contacting them. Message
content is never executed or used to choose a network destination.

Raw message bodies are processed briefly in memory and are not stored. SQLite
contains timestamps, room and sequence metadata, sender/identity metadata,
scanner flags, severity, and a SHA-256 message hash.

## Security model

The current scanner emits neutral, deterministic indicators:

- `DID_PRESENT`: a `did:key` identifier appeared in normalized metadata. This is
  not independent signature verification.
- `UNSIGNED_PRIVILEGED_NAME`: a configured privileged-looking display name
  appeared without signed identity metadata.
- `POTENTIAL_TECHNOCORE_WRITE_URL`: static URL structure matched a documented
  write-capable Technocore route on a configured Technocore host. The URL was not
  contacted.
- `SUSPICIOUS_COMBINATION`: multiple objective indicators occurred together. It
  is not proof of malicious intent.

Watchtower is not an identity authority or reputation system. It does not label
users as trusted, official, malicious, or verified. It does not create DIDs,
hold keys or wallets, or send messages to Technocore.

For Technocore JSON records, the adapter treats a canonical Ed25519 `did:key` in
`from` together with the signed-record-only integer `nonce` as server-exposed
signed identity metadata. Watchtower does not currently re-verify that record's
signature independently because the stored JSON record does not include the
signature itself.

See [SECURITY.md](SECURITY.md) for the threat model and vulnerability-reporting
guidance.

## Architecture

```text
fixed Technocore read endpoint
        |
        v
strict GET-only transport -> explicit JSON adapter
        |                         |
        +-------------------------+
                    |
                    v
parser -> deterministic scanner -> metadata-only SQLite
                                      |
                                      v
                         local FastAPI dashboard
```

The parser, scanner, storage, transport, adapter, polling worker, and dashboard
remain separate. This keeps untrusted content handling independent from network
request construction.

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

Run the tests and publication checks:

```bash
pytest
ruff check .
mypy app
pip-audit
```

## Deployment status

Technocore Watchtower has been successfully deployed as a hardened systemd
service in a live VPS environment. The systemd unit is not currently distributed
with this repository. The dashboard remains private and loopback-only in the
current deployment; there is no public live demo. Docker packaging is not
currently provided.

## Data and privacy

The default database path is `data/watchtower.sqlite3`; database files are ignored
by Git. The dashboard intentionally has no original-message view. Treat sender
names, DIDs, room names, and all other remote fields as untrusted metadata.

## Screenshots

Screenshots will be added after the interface and publication process are reviewed.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). By contributing, you agree that your
contribution is licensed under the Apache License 2.0.

## License

Apache License 2.0. See [LICENSE](LICENSE).
