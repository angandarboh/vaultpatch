# vaultpatch

> CLI tool to bulk-rotate and audit secrets across multiple HashiCorp Vault namespaces.

---

## Installation

```bash
pip install vaultpatch
```

Or install from source:

```bash
git clone https://github.com/yourorg/vaultpatch.git && cd vaultpatch && pip install .
```

---

## Usage

Authenticate using your Vault token and target one or more namespaces:

```bash
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="s.xxxxxxxxxxxxxxxx"

# Audit secrets across namespaces
vaultpatch audit --namespaces team-a,team-b --path secret/

# Bulk-rotate secrets matching a pattern
vaultpatch rotate --namespaces team-a,team-b --path secret/db --pattern "password"

# Dry-run to preview changes before rotating
vaultpatch rotate --namespaces team-a --path secret/api --dry-run
```

### Common Options

| Flag | Description |
|------|-------------|
| `--namespaces` | Comma-separated list of Vault namespaces |
| `--path` | Secret engine mount path |
| `--pattern` | Key pattern to match for rotation |
| `--dry-run` | Preview changes without applying them |
| `--output` | Output format: `table`, `json`, or `csv` |

---

## Requirements

- Python 3.8+
- HashiCorp Vault 1.9+
- `hvac` Python client

---

## License

This project is licensed under the [MIT License](LICENSE).