from pathlib import Path

import pytest

from vaultsweep.models import Severity
from vaultsweep.reporter import exit_code_for_report
from vaultsweep.scanner import scan_path, write_baseline

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_leaky_fixture_finds_secrets():
    report = scan_path(FIXTURES / "leaky-repo")
    assert report.summary["findings"] >= 4
    rule_ids = {f.rule_id for f in report.findings}
    assert "STELLAR-001" in rule_ids
    assert "MNEMONIC-001" in rule_ids
    assert "DEFAULT-001" in rule_ids


def test_clean_fixture_no_high_findings():
    report = scan_path(FIXTURES / "clean-repo")
    high_plus = [
        f for f in report.findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    assert len(high_plus) == 0


def test_fail_on_high_exit_code():
    report = scan_path(FIXTURES / "leaky-repo")
    assert exit_code_for_report(report, Severity.HIGH) == 1
    assert exit_code_for_report(report, None) == 0


def test_scan_missing_target():
    with pytest.raises(FileNotFoundError):
        scan_path("/nonexistent/path")


def test_inline_ignore_comment_suppresses_finding(tmp_path: Path):
    f = tmp_path / "ignored.py"
    f.write_text(
        'SEED = "SCZANGBA5SCTZXW5K3P3AR2R7X5FJCHLL2ULYLMGOSCFW3RXMQ26FICF"  # vaultsweep:ignore\n'
        'PASS = "password = \'changeme123\'"  # vaultsweep:ignore DEFAULT-001\n',
        encoding="utf-8",
    )
    report = scan_path(tmp_path)
    assert report.findings == []


def test_baseline_suppresses_known_findings_only(tmp_path: Path):
    f = tmp_path / "app.env"
    f.write_text(
        "SECRET_A=SCZANGBA5SCTZXW5K3P3AR2R7X5FJCHLL2ULYLMGOSCFW3RXMQ26FICF\n",
        encoding="utf-8",
    )
    initial = scan_path(tmp_path)
    assert len(initial.findings) == 1

    baseline_path = tmp_path / ".vaultsweep-baseline"
    write_baseline(initial, baseline_path)

    # Known finding is suppressed
    after_baseline = scan_path(tmp_path)
    assert after_baseline.findings == []

    # Adding a new secret on line 2 still triggers a finding
    f.write_text(
        "SECRET_A=SCZANGBA5SCTZXW5K3P3AR2R7X5FJCHLL2ULYLMGOSCFW3RXMQ26FICF\n"
        "SECRET_B=SBZANGBA5SCTZXW5K3P3AR2R7X5FJCHLL2ULYLMGOSCFW3RXMQ26FICF\n",
        encoding="utf-8",
    )
    with_new_leak = scan_path(tmp_path)
    assert len(with_new_leak.findings) == 1
    assert with_new_leak.findings[0].line == 2
