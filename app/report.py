"""Command-line security summary for metadata stored by Watchtower."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .storage import EventStore

DEFAULT_DATABASE = Path(__file__).resolve().parent.parent / "data" / "watchtower.sqlite3"


def positive_hours(value: str) -> int:
    try:
        hours = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("hours must be a positive integer") from exc
    if hours <= 0:
        raise argparse.ArgumentTypeError("hours must be a positive integer")
    return hours


def render_human(report: dict[str, Any]) -> str:
    identity = report["identity"]
    url_safety = report["url_safety"]
    severity = report["severity"]
    flags = report["flags"]
    rooms = report["top_flagged_rooms"]
    lines = [
        "Technocore Watchtower — Security Report",
        "",
        f"Period: Last {report['period_hours']} hours",
        f"Generated: {report['generated_at']}",
        "",
        f"Rooms observed: {report['rooms_observed']}",
        f"Observations: {report['observations']}",
    ]
    if report["observations"] == 0:
        lines.extend(["", "No observations in the selected period."])
    lines.extend(
        [
            "",
            "Identity",
            f"Signed DID metadata:          {identity['signed_identity_present']}",
            f"Unsigned observations:       {identity['unsigned']}",
            f"Unsigned privileged names:   {identity['unsigned_privileged_name']}",
            "",
            "URL Safety",
            f"Write-capable URLs detected: {url_safety['potential_write_urls']}",
            "",
            "Risk Events",
            f"HIGH:   {severity['high']}",
            f"MEDIUM: {severity['medium']}",
            f"LOW:    {severity['low']}",
            f"INFO:   {severity['info']}",
            f"NONE:   {severity['none']}",
            "",
            "Top flagged rooms",
        ]
    )
    if rooms:
        lines.extend(f"{room['room']:<30} {room['events']}" for room in rooms)
    else:
        lines.append("None")
    lines.extend(["", "Scanner flags"])
    lines.extend(f"{name:<34} {count}" for name, count in flags.items())
    shadow = report.get("risk_v2_shadow")
    if isinstance(shadow, dict):
        classification = shadow["classification"]
        lines.extend(
            [
                "",
                f"Risk v2 shadow ({shadow['engine_version']})",
                f"Evaluated:  {shadow['evaluated']}",
                f"Unevaluated:{shadow['unevaluated']:>5}",
                f"CRITICAL:   {classification['critical']}",
                f"HIGH:       {classification['high']}",
                f"MEDIUM:     {classification['medium']}",
                f"LOW:        {classification['low']}",
                f"INFO:       {classification['info']}",
                f"NONE:       {classification['none']}",
                "",
                "Top shadow contribution codes",
            ]
        )
        signals = shadow["top_contributing_signals"]
        if signals:
            lines.extend(
                f"{item['code']:<40} {item['events']}" for item in signals
            )
        else:
            lines.append("None")
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Summarize metadata-only Technocore Watchtower telemetry."
    )
    parser.add_argument("--hours", type=positive_hours, default=24)
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument(
        "--risk-shadow",
        action="store_true",
        help="include the internal risk-v2 shadow distribution",
    )
    parser.add_argument(
        "--backfill-risk-shadow",
        action="store_true",
        help="evaluate missing metadata events before showing the shadow report",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = EventStore(DEFAULT_DATABASE)
    store.initialize()
    report = store.security_report(args.hours)
    if args.backfill_risk_shadow:
        store.backfill_shadow_risk()
    if args.risk_shadow or args.backfill_risk_shadow:
        report["risk_v2_shadow"] = store.shadow_risk_report(args.hours)
    if args.as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(render_human(report), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
