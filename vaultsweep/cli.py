import argparse
import stat
import sys
from pathlib import Path

from vaultsweep import __version__
from vaultsweep.models import Severity
from vaultsweep.reporter import exit_code_for_report, format_json, format_text
from vaultsweep.rules import list_rules
from vaultsweep.scanner import DEFAULT_BASELINE_FILENAME, scan_path, write_baseline

SEVERITY_CHOICES = [s.value for s in Severity]

PRE_COMMIT_HOOK_HEADER = "# Managed by VaultSweep pre-commit hook"


def render_pre_commit_hook(fail_on: str = "critical") -> str:
    return (
        "#!/usr/bin/env sh\n"
        f"{PRE_COMMIT_HOOK_HEADER}\n"
        "set -e\n\n"
        "if command -v vaultsweep >/dev/null 2>&1; then\n"
        f'    exec vaultsweep scan . --fail-on "{fail_on}"\n'
        "elif [ -x .venv/bin/vaultsweep ]; then\n"
        f'    exec .venv/bin/vaultsweep scan . --fail-on "{fail_on}"\n'
        "else\n"
        f'    exec python3 -m vaultsweep scan . --fail-on "{fail_on}"\n'
        "fi\n"
    )


def install_pre_commit_hook(
    repo_root: str | Path = ".",
    fail_on: str = "critical",
    force: bool = False,
) -> Path:
    root = Path(repo_root).resolve()
    git_dir = root / ".git"
    if not git_dir.is_dir():
        raise FileNotFoundError(f"Not a git repository (missing .git): {root}")

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    if hook_path.exists() and not force:
        existing = hook_path.read_text(encoding="utf-8", errors="replace")
        if PRE_COMMIT_HOOK_HEADER not in existing:
            raise FileExistsError(
                f"Existing pre-commit hook at {hook_path} was not created by VaultSweep "
                "(use --force to overwrite)"
            )

    hook_path.write_text(render_pre_commit_hook(fail_on=fail_on), encoding="utf-8")
    current_mode = hook_path.stat().st_mode
    hook_path.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return hook_path


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
        "--baseline",
        default=None,
        help=f"Path to baseline file (defaults to <target>/{DEFAULT_BASELINE_FILENAME} if present)",
    )

    for hook_cmd in ("install-hook", "pre-commit"):
        hook = sub.add_parser(hook_cmd, help="Install VaultSweep git pre-commit hook")
        hook.add_argument(
            "--path",
            default=".",
            help="Repository root containing .git (default: current directory)",
        )
        hook.add_argument(
            "--fail-on",
            choices=SEVERITY_CHOICES,
            default="critical",
            help="Minimum severity that blocks a commit (default: critical)",
        )
        hook.add_argument(
            "--force",
            action="store_true",
            help="Overwrite an existing third-party pre-commit hook",
        )

    baseline = sub.add_parser(
        "baseline", help="Generate a .vaultsweep-baseline file from current findings"
    )
    baseline.add_argument("target", nargs="?", default=".", help="Path to scan (default: .)")
    baseline.add_argument(
        "--output",
        default=DEFAULT_BASELINE_FILENAME,
        help=f"Output baseline file path (default: {DEFAULT_BASELINE_FILENAME})",
    )

    sub.add_parser("rules", help="List all detection rules")
    return p


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        report = scan_path(args.target, baseline_path=args.baseline)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    output = format_json(report) if args.format == "json" else format_text(report)
    print(output)

    threshold = Severity(args.fail_on) if args.fail_on else None
    return exit_code_for_report(report, threshold)


def cmd_install_hook(args: argparse.Namespace) -> int:
    try:
        hook_path = install_pre_commit_hook(
            repo_root=args.path,
            fail_on=args.fail_on,
            force=args.force,
        )
    except (FileNotFoundError, FileExistsError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"Installed VaultSweep pre-commit hook at {hook_path} (--fail-on {args.fail_on})")
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    try:
        report = scan_path(args.target, baseline_path=Path("/dev/null"))
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    dest = write_baseline(report, args.output)
    print(f"Wrote {len(report.findings)} baseline finding(s) to {dest}")
    return 0


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
    if args.command in ("install-hook", "pre-commit"):
        return cmd_install_hook(args)
    if args.command == "baseline":
        return cmd_baseline(args)
    if args.command == "rules":
        return cmd_rules()
    return 1


if __name__ == "__main__":
    sys.exit(main())
