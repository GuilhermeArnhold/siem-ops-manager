# siem-ops-manager

## Overview

`siem-ops-manager` is a Python tool (work in progress) for SIEM operations and KPI tracking. The current codebase includes a Cortex XSIAM collector that authenticates to the Advanced API, retrieves incidents for the current month, aggregates high-level KPIs (cases, alerts, MITRE tactics/techniques), and returns tenant metadata. Broader capabilities for XSIAM and other SIEMs—query execution, additional KPIs, and automations—are planned and will be added over time.

## Current capabilities

- Authenticates to the Cortex XSIAM Advanced API using nonce, timestamp, and SHA256 signature.
- Paginates incident retrieval for the current month (10 pages of 100 items by default).
- Consolidates KPIs: case count, total alert count, top 10 MITRE tactics, and top 10 MITRE techniques.
- Pulls tenant metadata from the public endpoint.

## Requirements

- Python **3.10+**.
- Dependencies listed in `pyproject.toml` or `requirements.txt` (`requests` is required).

## Quickstart

1. Clone the repository:
   ```bash
   git clone https://github.com/GuilhermeArnhold/siem-ops-manager.git
   cd siem-ops-manager
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -U pip
   pip install -e .
   # or
   pip install -r requirements.txt
   ```

## Usage

Run the collector directly via the module or the installed entrypoint:

```bash
# Module invocation
python -m siem_ops_manager

# Entrypoint (configured in pyproject.toml)
siem-ops-manager
```

You will be prompted for:
- **Tenant name**: the prefix before `.xdr` in the Cortex XSIAM URL.
- **API Key ID** and **API Key**: tenant credentials (do not share or store them in plaintext).

Expected output (summary):
- Number of cases and alerts for the month.
- Top 10 MITRE tactics and techniques (counted across incidents).
- Tenant info returned by the API.

### Secret handling

- Do not commit keys or tokens; prefer environment variables or a secrets manager.
- Rotate or revoke credentials regularly and scope permissions to the minimum necessary.

## Code structure

- `src/siem_ops_manager/cortex_xdr.py`: main implementation with authentication, pagination, and KPI calculations.
- `src/siem_ops_manager/__main__.py`: enables running via `python -m siem_ops_manager`.

## Roadmap

- Extend integrations to XSIAM and other SIEMs for queries, richer KPIs, and automations.
- Add automated tests and non-interactive configuration options.

## License

Distributed under the [MIT License](LICENSE).
