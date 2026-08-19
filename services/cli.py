"""
Nexora Command-Line Interface (Blueprint Pillar 12).

Operator-facing CLI for audit ledger verification, pipeline health checks and
scan report exports. Designed to work headlessly in CI and operator terminals.
"""

import argparse
import asyncio
import json
import os
import sys
from typing import Any, Dict, List, Optional

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from services.audit.ledger import AuditLedger
from services.ingestion.rescan_verifier import RescanVerifier


def _run(coro):
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
    return asyncio.get_event_loop().run_until_complete(coro)


def _print_json(payload: Dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, default=str))


def _session_factory():
    url = os.environ.get("NEXORA_CLI_DB_URL", "sqlite+aiosqlite:///nexora.db")
    engine = create_async_engine(url)
    return async_sessionmaker(engine, expire_on_commit=False), engine


def cmd_audit_verify(args) -> int:
    """Verify the audit ledger hash chain."""
    factory, engine = _session_factory()

    async def _verify():
        async with factory() as session:
            return await AuditLedger.verify_chain(session)

    result = _run(_verify())
    engine.sync_engine.dispose()
    _print_json(result)
    return 0 if result.get("valid") else 1


def cmd_scan_report(args) -> int:
    """Export a synthetic scan report or verify a provided JSON report."""
    items = json.loads(args.items_json) if args.items_json else []
    result = {
        "command": "scan report",
        "asset": args.asset,
        "finding_count": len(items),
        "items": items,
    }
    _print_json(result)
    return 0


def cmd_rescan_verify(args) -> int:
    """Verify remediation by comparing pre/post scan finding lists."""

    class _StaticScanner:
        def __init__(self, after: List[Dict[str, str]]):
            self.after = after

        async def fetch_remote_scan(self, asset_identifier: str, credentials: Dict[str, Any]):
            return self.after

    before = json.loads(args.before_json) if args.before_json else []
    after = json.loads(args.after_json) if args.after_json else []
    target = json.loads(args.target_cves) if args.target_cves else []
    verifier = RescanVerifier(retry_attempts=args.retries)
    outcome = _run(verifier.verify(_StaticScanner(after), args.asset, {}, target, before))
    _print_json(outcome)
    return 0 if outcome.get("verified") else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nexora", description="Nexora control plane CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="Audit ledger operations")
    audit_sub = audit.add_subparsers(dest="subcommand", required=True)
    verify = audit_sub.add_parser("verify", help="Verify the audit hash chain")
    verify.set_defaults(func=cmd_audit_verify)

    scan = sub.add_parser("scan", help="Scan report operations")
    scan_sub = scan.add_subparsers(dest="subcommand", required=True)
    report = scan_sub.add_parser("report", help="Export a scan report")
    report.add_argument("--asset", required=True, help="Asset identifier")
    report.add_argument("--items-json", help="JSON array of findings")
    report.set_defaults(func=cmd_scan_report)

    rescan = scan_sub.add_parser("rescan-verify", help="Verify remediation via rescan")
    rescan.add_argument("--asset", required=True, help="Asset identifier")
    rescan.add_argument("--before-json", help="JSON array of pre-patch findings")
    rescan.add_argument("--after-json", help="JSON array of post-patch findings")
    rescan.add_argument("--target-cves", help="JSON array of target CVE ids")
    rescan.add_argument("--retries", type=int, default=3)
    rescan.set_defaults(func=cmd_rescan_verify)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
