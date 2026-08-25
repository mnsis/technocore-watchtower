# Security policy

## Supported versions

The project is pre-release. Security fixes currently target the latest revision
on the default branch.

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue. Use GitHub's private
vulnerability-reporting feature if it is enabled. Otherwise, contact the
repository maintainers privately through a channel listed in the repository
profile.

Include the affected revision, impact, reproduction steps using synthetic data,
and any suggested mitigation. Never include real private keys, wallet material,
tokens, non-public room contents, or other people's personal data.

## Threat model and invariants

Technocore room data is untrusted. Watchtower is designed so that:

- only fixed, configured Technocore read endpoints can be requested;
- message-derived URLs are parsed statically and never contacted;
- redirects are blocked and TLS certificate verification stays enabled;
- no POST, HEAD, write-route, arbitrary-URL, shell, or code-execution facility is
  exposed by the message pipeline;
- room polling is allowlisted, bounded, rate-limit aware, and conservative;
- raw message bodies are not persisted;
- displayed remote metadata is HTML-escaped;
- DID presence and signed metadata are not described as independent identity
  verification.

The VPS application remains bound to `127.0.0.1`. Reviewed Nginx and Vercel
layers provide the public dashboard, fixed read-only API proxy, and exact-origin
SSE access. Directly exposing the application server remains unsupported.

Risk-v2 remains a separately stored shadow evaluation. It does not replace
public severity, establish intent, or create permanent DID trust/reputation
profiles.

## Out of scope

Reports that depend on directly exposing the local application server, disabling
TLS verification, or modifying the code to add write behavior are outside the
current supported configuration. Reports about real Technocore content should
redact message bodies and personal data.
