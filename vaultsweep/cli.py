import argparse
import sys

from vaultsweep import __version__
from vaultsweep.models import Severity
from vaultsweep.reporter import exit_code_for_report, format_json, format_text
from vaultsweep.rules import list_rules
from vaultsweep.scanner import scan_path

SEVERITY_CHOICES = [s.value for s in Severity]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vaultsweep",
        description="Stellar-aware secrets scanner — BreachDirect / Stellar Wave 7",
    )
    p.add_argument("--version", action="version", version=f"VaultSweep {__version__}")

    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a file or directory for secrets")
    scan.add_argument("target", help="Path to scan")
    scan.add_argument(
        "--format", choices=["text", "json"], default="text", help="Output format"
    )
    scan.add_argument(
        "--fail-on",
        choices=SEVERITY_CHOICES,
        default=None,
        help="Exit 1 if findings at or above this severity (for CI)",
    )
    scan.add_argument(
        "--only",
        default=None,
        help="Comma-separated rule IDs to run (e.g. STELLAR-001,MNEMONIC-001)",
    )

    sub.add_parser("rules", help="List all detection rules")
    return p


def cmd_scan(args: argparse.Namespace) -> int:
    only_rules: set[str] | None = None
    if args.only:
        only_rules = {token.strip() for token in args.only.split(",") if token.strip()}

    try:
        report = scan_path(args.target, only_rules=only_rules)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    output = format_json(report) if args.format == "json" else format_text(report)
    print(output)

    threshold = Severity(args.fail_on) if args.fail_on else None
    return exit_code_for_report(report, threshold)


def cmd_rules() -> int:
    print(f"VaultSweep v{__version__} — {len(list_rules())} rules\n")
    for meta in list_rules():
        print(f"  {meta.rule_id:12} [{meta.severity.value:8}] {meta.name}")
        print(f"               {meta.description}")
        print()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "rules":
        return cmd_rules()
    return 1


if __name__ == "__main__":
    sys.exit(main())
