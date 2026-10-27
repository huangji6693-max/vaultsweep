import os
from pathlib import Path

from vaultsweep import __version__
from vaultsweep.git_diff import run_git_diff
from vaultsweep.models import SEVERITY_ORDER, Finding, ScanReport, Severity
from vaultsweep.rules import ALL_RULES

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
    ".ini", ".properties", ".sql", ".go", ".sol",
})

BINARY_EXTENSIONS = frozenset({
    ".wasm", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip",
    ".tar", ".gz", ".db", ".sqlite",
})


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


def scan_lines(rel_path: str, numbered_lines: list[tuple[int, str]]) -> list[Finding]:
    findings: list[Finding] = []
    for line_no, line in numbered_lines:
        if not line or len(line) < 6:
            continue
        for rule in ALL_RULES:
            findings.extend(rule.scan_line(rel_path, line_no, line))
    return findings


def scan_file(file_path: Path, base: Path) -> list[Finding]:
    rel = str(file_path.relative_to(base)) if file_path.is_relative_to(base) else str(file_path)
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    numbered = list(enumerate(content.splitlines(), start=1))
    return scan_lines(rel, numbered)


def scan_path(
    target: str | Path,
    staged: bool = False,
    diff_ref: str | None = None,
) -> ScanReport:
    path = Path(target).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Target not found: {target}")

    all_findings: list[Finding] = []

    if staged or diff_ref is not None:
        base = path if path.is_dir() else path.parent
        diff_map = run_git_diff(base, staged=staged, diff_ref=diff_ref)
        scanned_count = 0
        for rel_file, numbered_lines in sorted(diff_map.items()):
            if not _should_scan(Path(rel_file)):
                continue
            scanned_count += 1
            all_findings.extend(scan_lines(rel_file, numbered_lines))
        files_scanned = scanned_count
    else:
        base = path if path.is_dir() else path.parent
        files = collect_files(path)
        for f in files:
            all_findings.extend(scan_file(f, base))
        files_scanned = len(files)

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
    report.files_scanned = files_scanned
    report.rules_run = len(ALL_RULES)
    return report


def exceeds_threshold(findings: list[Finding], threshold: Severity) -> bool:
    threshold_rank = SEVERITY_ORDER[threshold]
    return any(SEVERITY_ORDER[f.severity] <= threshold_rank for f in findings)
