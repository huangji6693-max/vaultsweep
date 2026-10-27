import re
import shutil
import subprocess  # nosec B404
from pathlib import Path

_DIFF_FILE_RE = re.compile(r"^\+\+\+\s+b/(.+)$")
_DIFF_HUNK_RE = re.compile(r"^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@")


def parse_unified_diff_added_lines(diff_text: str) -> dict[str, list[tuple[int, str]]]:
    """Parse `git diff --unified=0` output into `{rel_file: [(line_no, line_text), ...]}`.

    Only added/modified lines (`+` lines inside hunks, excluding `+++` file headers)
    are returned so staged and branch-diff scans inspect exclusively newly introduced
    or modified lines.
    """
    changes: dict[str, list[tuple[int, str]]] = {}
    current_file: str | None = None
    current_line_no: int | None = None

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("+++ "):
            m_file = _DIFF_FILE_RE.match(raw_line)
            if m_file:
                current_file = m_file.group(1)
                changes.setdefault(current_file, [])
            else:
                # e.g. +++ /dev/null (deleted file)
                current_file = None
            current_line_no = None
            continue

        if raw_line.startswith("@@ "):
            m_hunk = _DIFF_HUNK_RE.match(raw_line)
            if m_hunk:
                current_line_no = int(m_hunk.group(1))
            continue

        if current_file is None or current_line_no is None:
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            changes[current_file].append((current_line_no, raw_line[1:]))
            current_line_no += 1
        elif not raw_line.startswith("-") and not raw_line.startswith("\\"):
            current_line_no += 1

    return {k: v for k, v in changes.items() if v}


def run_git_diff(
    repo_root: str | Path,
    staged: bool = False,
    diff_ref: str | None = None,
) -> dict[str, list[tuple[int, str]]]:
    """Execute `git diff` on `repo_root` and return added/modified lines per file."""
    root = Path(repo_root).resolve()
    git_bin = shutil.which("git") or "git"

    cmd = [git_bin, "-C", str(root), "diff", "--unified=0", "--no-color"]
    if staged:
        cmd.append("--cached")
    elif diff_ref:
        cmd.append(diff_ref)

    proc = subprocess.run(  # nosec B603
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.strip() or "git diff failed"
        raise RuntimeError(f"git diff error in {root}: {stderr}")

    return parse_unified_diff_added_lines(proc.stdout)
