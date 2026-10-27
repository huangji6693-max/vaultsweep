# BreachDirect / VaultSweep GitHub Action

Gate pull requests and pushes against leaked Stellar `S...` secret keys, BIP39 mnemonics, embedded RPC credentials, and API tokens.

## Usage in Stellar Wave Repositories

### Standard PR Gate (`--fail-on high`)

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  vaultsweep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: VaultSweep Secret Scan
        uses: BreachDirect/vaultsweep@main
        with:
          target: "."
          fail-on: "high"
          format: "text"
```

### Incremental Adoption with `.vaultsweep-baseline`

Generate a baseline for known legacy test vectors:

```bash
vaultsweep baseline . --output .vaultsweep-baseline
```

Then configure the action to respect `.vaultsweep-baseline`:

```yaml
      - name: VaultSweep Secret Scan (with baseline)
        uses: BreachDirect/vaultsweep@main
        with:
          target: "."
          fail-on: "high"
          baseline: ".vaultsweep-baseline"
```

### Inline Suppression (`# vaultsweep:ignore`)

Suppress intentional synthetic test secrets on specific lines:

```python
TEST_SEED = "SCZANGBA5SCTZXW5K3P3AR2R7X5FJCHLL2ULYLMGOSCFW3RXMQ26FICF"  # vaultsweep:ignore
# Or scope to a single rule ID:
TEST_PASS = "password = 'changeme123'"  # vaultsweep:ignore DEFAULT-001
```
