# HSM PKCS#11 Session Auditor

A Python command-line and API project for **heuristic classification of telemetry records** associated with hardware-security operations. It compares numeric inputs against fixed thresholds, flags selected descriptor words, and maintains an in-memory HMAC-SHA256-linked event history.

**Scope:** Despite the repository name, the code does **not** communicate with an HSM, import a PKCS#11 driver, parse Cryptoki function traces, authenticate operators, enforce M-of-N authorization, check key custody, or certify PKCS#11/NIST compliance. The rules are illustrative, not validated security controls.

## Browser demonstration

The self-contained [browser evaluator](web/) reproduces the core package's three classification rules: primary metric >25, secondary metric >10 or a critical flag, and anomaly keywords in the descriptor. It performs local JavaScript calculations, does not call an API, and can export a JSON result. It deliberately does not generate an audit signature or pretend to contact an HSM.

To view locally:

```bash
python -m http.server 8080 --directory web
# Visit http://127.0.0.1:8080/
```

A GitHub Pages deployment workflow is supplied, but a public live-app URL should only be advertised after a successful deployment and verification.

## Python installation

Python 3.10–3.12 is exercised by CI. Runtime code targets Python 3.9+.

```bash
python -m pip install -e ".[dev]"
pytest -q
node --test web/test-app.cjs
```

For a lightweight core CLI installation without server dependencies, use `python -m pip install -e .`.

## CLI usage

```bash
python -m hsm_pkcs11_auditor.cli audit --task-id T1 --target KEY-01 --primary 28.5 --secondary 14.2 --status DISCORDANT
python -m hsm_pkcs11_auditor.cli batch -i sample.csv -o results.csv
python -m hsm_pkcs11_auditor.cli verify-audit
python -m hsm_pkcs11_auditor.cli serve --host 127.0.0.1 --port 8000
```

The package CLI uses thresholds 25 and 10. The legacy `python cli.py` path uses a separate supervisor with thresholds 25 and 12; both paths remain available for compatibility. CSV critical flags accept `true/false`, `1/0`, `yes/no` and `on/off` (case-insensitive); unrecognized values fail rather than being silently treated as true.

Audit verification checks the **current process's** in-memory HMAC chain; a new CLI invocation starts a new process and does not verify past invocations. No trail is persisted, independently timestamped, or protected against an attacker with full process access.

## Local REST API and Docker

The root service is available through `python cli.py serve --host 127.0.0.1 --port 8000` or Docker Compose. The core package's `serve` command uses a smaller API. Both require the `HSM_API_TOKEN` environment variable and the `X-API-Key` request header for audit/chat operations; unconfigured endpoints return HTTP 503 and invalid keys return HTTP 401.

To start the legacy API with Docker:

```bash
cp .env.example .env
# Set independent, randomly generated AUDIT_SECRET_KEY and HSM_API_TOKEN values in .env.
docker compose up --build
```

The Compose configuration binds `127.0.0.1:8000` on the host. The `/health` endpoint is public. Authenticated endpoints include `POST /api/audit`, `POST /api/chat`, `GET /api/audit/logs` and `GET /metrics` (JSON counters, **not** Prometheus exposition format). FastAPI serves generated API documentation at `/docs`.

The legacy server's `AUDIT_SECRET_KEY` and core package's `HSM_AUDIT_SECRET_KEY` are distinct configuration variables. Without a configured signing secret, each starts with a randomly generated ephemeral secret. Previously committed sample deployment credentials must be considered compromised and **must never be reused**.

## Data handling and limitations

Browser calculations remain in the tab; no network request, analytics, or browser storage is used by the evaluator. Python API operations maintain task results and audit metadata in volatile server memory. The regular-expression identifier guard is **not** a validated PHI detection or HIPAA de-identification system; avoid supplying sensitive personal data, cryptographic private keys, or production HSM credentials.

The project includes no actual PKCS#11 device integration, durable tamper-evident storage, real provider-backed language model, or independently validated hardware security testing. A production security audit requires dedicated integration, authorization, storage, and device-level tests.

## Repository

- `hsm_pkcs11_auditor/`: core rules, coordinator, CLI, API
- `agents/` and `cli.py`: legacy supervisor, CLI, REST API
- `web/`: dependency-free local browser demonstration
- `tests/`: Python regressions; `web/test-app.cjs`: JavaScript regressions
- `.github/workflows/`: CI and GitHub Pages publishing

**License:** [MIT](LICENSE). **Browser support:** current Chrome, Firefox, Safari and Edge with standard JavaScript support.
