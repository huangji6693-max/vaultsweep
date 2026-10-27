import subprocess
import time
from pathlib import Path

from vaultsweep.cli import main
from vaultsweep.rules.multilang import (
    GoCredentialRule,
    JavaPropertiesSecretRule,
    SolidityPrivateKeyRule,
)
from vaultsweep.scanner import scan_path

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
    )


def test_staged_scan_only_inspects_added_or_modified_lines(tmp_path: Path):
    _git(tmp_path, "init", "-b", "main")
    _git(tmp_path, "config", "user.name", "hj")
    _git(tmp_path, "config", "user.email", "huangji6693@gmail.com")

    # Commit an existing secret on line 1 (unmodified in index)
    env_file = tmp_path / "app.env"
    env_file.write_text(
        "OLD_SECRET=SCZANGBA5SCTZXW5K3P3AR2R7X5FJCHLL2ULYLMGOSCFW3RXMQ26FICF\n"
        "SAFE_KEY=hello_world\n",
        encoding="utf-8",
    )
    _git(tmp_path, "add", "app.env")
    _git(tmp_path, "commit", "-m", "initial commit")

    # Stage a benign modification on line 2 only — line 1 is untouched
    env_file.write_text(
        "OLD_SECRET=SCZANGBA5SCTZXW5K3P3AR2R7X5FJCHLL2ULYLMGOSCFW3RXMQ26FICF\n"
        "SAFE_KEY=updated_benign_value\n",
        encoding="utf-8",
    )
    _git(tmp_path, "add", "app.env")

    staged_clean = scan_path(tmp_path, staged=True)
    assert staged_clean.findings == []

    # Now stage a new secret on line 3 — staged scan catches only line 3
    env_file.write_text(
        "OLD_SECRET=SCZANGBA5SCTZXW5K3P3AR2R7X5FJCHLL2ULYLMGOSCFW3RXMQ26FICF\n"
        "SAFE_KEY=updated_benign_value\n"
        "NEW_SECRET=SBZANGBA5SCTZXW5K3P3AR2R7X5FJCHLL2ULYLMGOSCFW3RXMQ26FICF\n",
        encoding="utf-8",
    )
    _git(tmp_path, "add", "app.env")

    staged_leaky = scan_path(tmp_path, staged=True)
    assert len(staged_leaky.findings) == 1
    assert staged_leaky.findings[0].line == 3
    assert staged_leaky.findings[0].rule_id == "STELLAR-001"


def test_diff_branch_scan(tmp_path: Path):
    _git(tmp_path, "init", "-b", "main")
    _git(tmp_path, "config", "user.name", "hj")
    _git(tmp_path, "config", "user.email", "huangji6693@gmail.com")

    cfg = tmp_path / "config.toml"
    cfg.write_text('endpoint = "https://horizon-testnet.stellar.org"\n', encoding="utf-8")
    _git(tmp_path, "add", "config.toml")
    _git(tmp_path, "commit", "-m", "base main")

    _git(tmp_path, "checkout", "-b", "feature/leak")
    cfg.write_text(
        'endpoint = "https://horizon-testnet.stellar.org"\n'
        'seed = "SCZANGBA5SCTZXW5K3P3AR2R7X5FJCHLL2ULYLMGOSCFW3RXMQ26FICF"\n',
        encoding="utf-8",
    )
    _git(tmp_path, "add", "config.toml")
    _git(tmp_path, "commit", "-m", "add seed")

    assert main(["scan", str(tmp_path), "--diff", "main", "--fail-on", "high"]) == 1


def test_multilang_go_java_solidity_rules():
    sol_rule = SolidityPrivateKeyRule()
    sol_line = (
        'uint256 deployerKey = '
        '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;'
    )
    sol_findings = sol_rule.scan_line("Deploy.s.sol", 8, sol_line)
    assert len(sol_findings) == 1
    assert sol_findings[0].rule_id == "SOLIDITY-001"

    go_rule = GoCredentialRule()
    go_line = 'const HorizonSignerSecret = "super_secret_go_credential_value_99"'
    go_findings = go_rule.scan_line("main.go", 14, go_line)
    assert len(go_findings) == 1
    assert go_findings[0].rule_id == "GO-001"

    java_rule = JavaPropertiesSecretRule()
    java_line = "spring.datasource.password=ProdDbSecret2026!"
    java_findings = java_rule.scan_line("application.properties", 4, java_line)
    assert len(java_findings) == 1
    assert java_findings[0].rule_id == "JAVA-001"


def test_monorepo_fixture_rust_and_ts_scanned_in_one_pass():
    report = scan_path(FIXTURES / "monorepo")
    assert report.files_scanned == 2
    files = {f.file for f in report.findings}
    assert "contracts/src/lib.rs" in files
    assert "web/src/config.ts" in files


def test_performance_bulk_file_scan(tmp_path: Path):
    # Verify scanning 1,000 files completes well within budget (< 3s, scaling to 10k < 30s)
    for i in range(1000):
        p = tmp_path / f"mod_{i}.rs"
        p.write_text(f"pub fn compute_{i}(x: u64) -> u64 {{ x + {i} }}\n", encoding="utf-8")

    start = time.monotonic()
    report = scan_path(tmp_path)
    elapsed = time.monotonic() - start
    assert report.files_scanned == 1000
    assert report.findings == []
    assert elapsed < 3.0
