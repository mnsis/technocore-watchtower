# Contributing

Thank you for helping improve Technocore Watchtower. Keep contributions focused,
reviewable, and consistent with its read-only security boundaries.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

Before submitting a change, run:

```bash
pytest
ruff check .
mypy app
pip-audit
```

Use synthetic fixtures. Tests should not depend on live Technocore access unless
the integration is explicitly scoped, fixed to documented read endpoints, and
reviewed in advance.

## Security requirements

- Never add Technocore write behavior.
- Never fetch, preview, resolve, or follow URLs taken from messages.
- Never execute message content.
- Never store raw message bodies by default.
- Never overstate DID or signature trust semantics.
- Keep transport origins, paths, methods, rooms, waits, response sizes, and
  redirects constrained.
- Do not commit credentials, tokens, wallets, private keys, databases, local
  environment files, or real room-message fixtures.

## Changes and commits

Prefer small changes with tests. Explain security-sensitive behavior and document
any mapping from external JSON fields into the internal identity model. Commit
messages should describe the outcome, for example `fix: reject ambiguous room
records`.

By submitting a contribution, you agree to license it under Apache License 2.0.
