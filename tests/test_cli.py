import subprocess
from pathlib import Path

from vaultsweep.cli import main


def test_rules_command():
    assert main(["rules"]) == 0


def test_scan_clean_json(capsys):
    code = main(["scan", "fixtures/clean-repo", "--format", "json"])
    assert code == 0
    out = capsys.readouterr().out
    assert '"tool": "VaultSweep"' in out


def test_scan_leaky_fail_on_high():
    code = main(["scan", "fixtures/leaky-repo", "--fail-on", "high"])
    assert code == 1


def test_install_hook_and_precommit_blocks_critical(tmp_path: Path):
    git_dir = tmp_path / ".git" / "hooks"
    git_dir.mkdir(parents=True)

    code = main(["install-hook", "--path", str(tmp_path), "--fail-on", "critical"])
    assert code == 0

    hook_file = git_dir / "pre-commit"
    assert hook_file.is_file()
    assert hook_file.stat().st_mode & 0o111

    # Write a leaky file with a Stellar secret key and run the hook logic
    leaky = tmp_path / "secrets.env"
    leaky.write_text(
        "STELLAR_SECRET=SCZANGBA5SCTZXW5K3P3AR2R7X5FJCHLL2ULYLMGOSCFW3RXMQ26FICF\n",
        encoding="utf-8",
    )
    assert main(["scan", str(tmp_path), "--fail-on", "critical"]) == 1

    # Execute the generated pre-commit hook inside tmp_path
    proc = subprocess.run(
        ["sh", str(hook_file)],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1


def test_baseline_command_and_suppression(tmp_path: Path):
    leaky = tmp_path / "legacy.env"
    leaky.write_text(
        "STELLAR_SECRET=SCZANGBA5SCTZXW5K3P3AR2R7X5FJCHLL2ULYLMGOSCFW3RXMQ26FICF\n",
        encoding="utf-8",
    )
    baseline_file = tmp_path / ".vaultsweep-baseline"

    assert main(["scan", str(tmp_path), "--fail-on", "high"]) == 1
    assert main(["baseline", str(tmp_path), "--output", str(baseline_file)]) == 0
    assert baseline_file.is_file()

    # With .vaultsweep-baseline present in target directory, legacy finding is suppressed
    assert main(["scan", str(tmp_path), "--fail-on", "high"]) == 0
