from pathlib import Path

from vaultsweep.cli import main
from vaultsweep.rules.entropy import HighEntropySecretRule
from vaultsweep.rules.stellar_advanced import (
    StellarFederationAddressRule,
    StellarMuxedAccountRule,
)
from vaultsweep.scanner import scan_path
from vaultsweep.wasm import WASM_MAGIC, extract_wasm_strings

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_entropy_catches_32_plus_char_random_assignment():
    rule = HighEntropySecretRule()
    line = 'WEBHOOK_SIGNING_SECRET = "x9K2mP7qR4vL8nZ1cW5bY3jT6hF0dG8sA4eU"'
    findings = rule.scan_line("config.py", 12, line)
    assert len(findings) == 1
    assert findings[0].rule_id == "ENTROPY-001"


def test_entropy_false_positive_tuning_suite():
    rule = HighEntropySecretRule()
    benign_lines = [
        # UUIDs, env substitutions, public keys, low-entropy words, placeholders
        'REQUEST_KEY = "550e8400-e29b-41d4-a716-446655440000"',
        "STELLAR_SECRET=${STELLAR_SECRET_KEY}",
        'PUBLIC_KEY = "GBFXEPGCJ5K6P2UV22VLOS5ERAPZFF7AABLMZCKXGD3KTGXECDSNNFXW"',
        'TOKEN_NAME = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"',
        'SECRET_KEY = "example_placeholder_value_not_a_real_secret_key_12345"',
    ]
    for idx, line in enumerate(benign_lines, start=1):
        assert rule.scan_line("clean.py", idx, line) == []

    # Clean fixture repo false-positive rate must remain 0% (< 5%)
    report = scan_path(FIXTURES / "clean-repo")
    assert len(report.findings) == 0


def test_stellar_muxed_and_federation_rules():
    muxed_rule = StellarMuxedAccountRule()
    muxed_addr = "M" + "B234567" * 9 + "BCDEF"
    assert len(muxed_addr) == 69
    muxed_findings = muxed_rule.scan_line("payment.rs", 5, f'const DEST: &str = "{muxed_addr}";')
    assert len(muxed_findings) == 1
    assert muxed_findings[0].rule_id == "STELLAR-002"

    fed_rule = StellarFederationAddressRule()
    fed_findings = fed_rule.scan_line("stellar.toml", 3, 'federation_id = "treasury*anchor.org"')
    assert len(fed_findings) == 1
    assert fed_findings[0].rule_id == "STELLAR-003"


def test_wasm_fixture_with_embedded_secret_detected(tmp_path: Path):
    wasm_file = tmp_path / "soroban_contract.wasm"
    embedded_payload = (
        WASM_MAGIC
        + b"\x00\x20\x00\x00"
        + b"ADMIN_SEED=SCZANGBA5SCTZXW5K3P3AR2R7X5FJCHLL2ULYLMGOSCFW3RXMQ26FICF\x00"
    )
    wasm_file.write_bytes(embedded_payload)

    extracted = extract_wasm_strings(wasm_file)
    assert len(extracted) == 1

    report = scan_path(wasm_file)
    rule_ids = {f.rule_id for f in report.findings}
    assert "STELLAR-001" in rule_ids


def test_cli_only_rule_filter(capsys):
    code = main(
        [
            "scan",
            "fixtures/leaky-repo",
            "--only",
            "STELLAR-001,MNEMONIC-001",
            "--format",
            "json",
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert '"STELLAR-001"' in out
    assert '"MNEMONIC-001"' in out
    assert '"DEFAULT-001"' not in out
