# VaultSweep

**Stellar-aware secrets scanner for repos and CI**

[![CI](https://github.com/BreachDirect/vaultsweep/actions/workflows/ci.yml/badge.svg)](https://github.com/BreachDirect/vaultsweep/actions/workflows/ci.yml)

VaultSweep helps [Stellar Wave 7](https://www.drips.network/wave/stellar) contributors catch leaked secret keys, mnemonics, API tokens, and default credentials before they merge — with Stellar-specific detection that generic scanners miss.

**Organisation:** [BreachDirect](https://github.com/BreachDirect) · **Siblings:** [RytScan](https://github.com/BreachDirect/RytScan) · [ShieldScan](https://github.com/BreachDirect/shieldscan)

📄 [Product Requirements](docs/prd.md) · 🏗 [Architecture](docs/architecture.md)

## Why VaultSweep?

| Wave need | VaultSweep coverage |
|---|---|
| [#29 Secure key storage](https://www.drips.network/wave/stellar/issues/58fe0db0-83e4-41eb-9456-a99e2d53355a) | Stellar `S...` secret keys, mnemonics, plaintext config |
| `make security-ci` on PRs | `--fail-on high` exit code for pipelines |
| Stellar RPC / Horizon hygiene | Embedded credentials in URLs |
| Contributor onboarding | Leaky + clean fixture repos |

## Quick Start

```bash
git clone https://github.com/BreachDirect/vaultsweep.git
cd vaultsweep
make install-dev

# Scan a directory
vaultsweep scan ./my-repo

# JSON for CI
vaultsweep scan . --format json --fail-on high

# Scan only git staged additions/modifications
vaultsweep scan . --staged --fail-on high

# Scan changed lines compared to main branch in CI pull requests
vaultsweep scan . --diff main --fail-on high

# List rules
vaultsweep rules
```

## Built-in Rules (Phase 1)

| Rule ID | Severity | Detects |
|---|---|---|
| `STELLAR-001` | Critical | Stellar secret key (`S` + 55 base32 chars) |
| `MNEMONIC-001` | Critical | BIP39 mnemonic (12+ words) |
| `API-001`–`API-005` | Critical–Medium | Anthropic, GitHub, AWS, generic API keys |
| `DEFAULT-001` | High | Default credentials (`changeme`, `password`, …) |
| `RPC-001` | High | RPC URLs with embedded auth |

## Development

```bash
make install-dev
make test
make ci
make scan-leaky    # demo — should find secrets
make scan-clean    # demo — should pass
```

## Project Structure

```
vaultsweep/
├── vaultsweep/          # Python package
│   ├── cli.py           # vaultsweep binary
│   ├── scanner.py       # file walker
│   ├── rules/           # detection rules
│   └── reporter.py      # output formats
├── fixtures/
│   ├── leaky-repo/      # intentional test secrets
│   └── clean-repo/      # no high/critical findings
├── docs/
└── tests/
```

## Ethics

Fixture secrets are **synthetic test vectors only**. If VaultSweep finds a real credential in your repo, rotate it immediately — never commit live keys.

## Author

Michael Victory Osisienimo — [BreachDirect](https://github.com/BreachDirect)
