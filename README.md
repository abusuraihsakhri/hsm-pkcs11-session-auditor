# HSM PKCS#11 Session Auditor

> **Domain:** Hardware Security / Cryptographic Key Management
> **Standard:** OASIS PKCS#11 Cryptographic Token Interface

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB.svg?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688.svg?logo=fastapi&logoColor=white)
![Audit Trail](https://img.shields.io/badge/Audit-HMAC--SHA256_Tamper--Evident-brightgreen.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)

</div>

---

## Overview

HSM PKCS#11 Session Auditor is a security-focused Python application that audits OASIS PKCS#11 Cryptoki function streams (C_Initialize, C_GenerateKey, C_Sign), enforcing multi-party M-of-N quorum and providing tamper-evident HMAC-SHA256 audit trails.

---

## Key Features

- **Multi-Agent Audit Coordination**: Three specialized sub-agents (PKCS11FunctionAuditorAgent, KeyUsageAttributeEnforcerAgent, QuorumAuthenticationAgent) evaluate cryptographic sessions
- **Tamper-Evident Audit Trail**: HMAC-SHA256 chained cryptographic signatures with integrity verification
- **Input Validation**: Rejects NaN, infinity, and empty identifiers
- **PHI Outbound Guard**: Regex-based detection of sensitive data (SSN, MRN, phone, email)
- **FastAPI REST API**: OpenAPI endpoints for audit operations
- **Prometheus Metrics**: Operational telemetry export
- **Enrichment Suite**: Domain-specific engines for compliance, side-channel resistance, NIST standards

---

## Installation

```bash
pip install -e .
```

Or with Docker:
```bash
docker build -t hsm-pkcs11-session-auditor .
docker run -p 8000:8000 hsm-pkcs11-session-auditor
```

---

## Usage

### CLI Commands

#### Run a single audit
```bash
python -m hsm_pkcs11_auditor.cli audit --task-id TASK-001 --target KEY-01 --primary 28.5 --secondary 14.2 --critical --status DISCORDANT
```

#### Batch process CSV records
```bash
python -m hsm_pkcs11_auditor.cli batch -i sample.csv -o results.csv
```

#### Verify audit trail integrity
```bash
python -m hsm_pkcs11_auditor.cli verify-audit
```

#### Query the supervisory chat
```bash
python -m hsm_pkcs11_auditor.cli chat "What standard is applied?"
```

#### Launch REST server
```bash
python -m hsm_pkcs11_auditor.cli serve --host 127.0.0.1 --port 8000
```

### CSV Input Format

```csv
task_id,target_identifier,primary_metric,secondary_metric,is_critical_flag,status_descriptor
TASK-001,TARGET-01,28.4,14.2,True,DISCORDANT
TASK-002,TARGET-02,12.0,4.1,False,NOMINAL
```

### REST API Endpoints

| Endpoint | Method | Description |
|:---------|:-------|:------------|
| `/health` | GET | Health check |
| `/api/audit` | POST | Submit audit task |
| `/api/chat` | POST | Query system status |
| `/metrics` | GET | Prometheus metrics |

---

## Security

- **Audit Secret Key**: Configure via `AUDIT_SECRET_KEY` environment variable. If not set, a random key is generated at startup.
- **Input Sanitization**: All metric values are validated as finite numbers; identifiers are stripped and checked for emptiness.
- **PHI Detection**: Outbound data is inspected for SSNs, MRNs, phone numbers, emails, and patient identifiers.
- **HMAC Verification**: Audit trail integrity is verified using both chain linkage and HMAC-SHA256 signature validation.

---

## Testing

```bash
pytest -v
```

Run with coverage:
```bash
pytest -v --cov=hsm_pkcs11_auditor --cov=agents
```

---

## Architecture

```
hsm_pkcs11_auditor/     # Core HSM audit package
├── models.py           # Data models (FrontierPayload, ExecutionStatus)
├── engine.py           # Domain evaluation engine
├── agents.py           # Multi-agent coordination + HMAC audit trail
├── server.py           # FastAPI REST server
└── cli.py              # Command-line interface

agents/                 # Enterprise supervisor system
├── models.py           # Pydantic schemas + validation
├── base.py             # PHI guard + HMAC audit trail
├── workers.py          # Specialized evaluation workers
├── supervisor.py       # Supervisor orchestrator
├── api.py              # FastAPI endpoints
├── metrics.py          # Prometheus exporter
├── learning.py         # Bayesian calibration engine
└── streamer.py         # WebSocket telemetry

enrichment.py           # Domain enrichment engines
tests/                  # Pytest test suite
```

---

## License

MIT License - see [LICENSE](LICENSE) for details.
