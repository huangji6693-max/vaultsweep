import os
from pathlib import Path

from vaultsweep import __version__
from vaultsweep.models import SEVERITY_ORDER, Finding, ScanReport, Severity
from vaultsweep.rules import ALL_RULES
from vaultsweep.rules.base import Rule
from vaultsweep.wasm import extract_wasm_strings

# Directories and extensions to skip
SKIP_DIRS = frozenset({
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    "target",
    ".cargo",
})

SCAN_EXTENSIONS = frozenset({
    ".rs", ".toml", ".yaml", ".yml", ".json", ".env", ".env.example",
    ".py", ".js", ".ts", ".tsx", ".jsx", ".sh", ".md", ".txt", ".cfg",
    ".ini", ".properties", ".sql", ".wasm",
})

BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip",
    ".tar", ".gz", ".db", ".sqlite",
})


def _select_rules(only_rules: set[str] | None = None) -> list[Rule]:
    if not only_rules:
        return list(ALL_RULES)
    normalized = {r.strip().upper() for r in only_rules if r.strip()}
    return [rule for rule in ALL_RULES if rule.meta.rule_id.upper() in normalized]


def _should_scan(path: Path) -> bool:
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return False
    if path.suffix.lower() in SCAN_EXTENSIONS:
        return True
    # Extensionless config files
    if path.name in (".env", ".env.local", "config", "Makefile"):
        return True
    return False


def collect_files(target: Path) -> list[Path]:
    files: list[Path] = []
    if target.is_file():
        if _should_scan(target):
            files.append(target)
        return files

    for root, dirs, filenames in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in filenames:
            p = Path(root) / name
            if _should_scan(p):
                files.append(p)
    return sorted(files)


def scan_file(
    file_path: Path,
    base: Path,
    rules: list[Rule] | None = None,
) -> list[Finding]:
    active_rules = rules if rules is not None else ALL_RULES
    rel = str(file_path.relative_to(base)) if file_path.is_relative_to(base) else str(file_path)
    findings: list[Finding] = []

    if file_path.suffix.lower() == ".wasm":
        for line_no, text in extract_wasm_strings(file_path):
            for rule in active_rules:
                findings.extend(rule.scan_line(rel, line_no, text))
        return findings

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    for line_no, line in enumerate(content.splitlines(), start=1):
        for rule in active_rules:
            findings.extend(rule.scan_line(rel, line_no, line))
    return findings


def scan_path(
    target: str | Path,
    only_rules: set[str] | None = None,
) -> ScanReport:
    path = Path(target).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Target not found: {target}")

    active_rules = _select_rules(only_rules)
    base = path if path.is_dir() else path.parent
    files = collect_files(path)
    all_findings: list[Finding] = []

    for f in files:
        all_findings.extend(scan_file(f, base, rules=active_rules))

    all_findings.sort(
        key=lambda x: (
            SEVERITY_ORDER[x.severity],
            x.file,
            x.line,
            x.rule_id,
        )
    )

    report = ScanReport(tool="VaultSweep", version=__version__, target=str(path))
    report.findings = all_findings
    report.files_scanned = len(files)
    report.rules_run = len(active_rules)
    return report


def exceeds_threshold(findings: list[Finding], threshold: Severity) -> bool:
    threshold_rank = SEVERITY_ORDER[threshold]
    return any(SEVERITY_ORDER[f.severity] <= threshold_rank for f in findings)
