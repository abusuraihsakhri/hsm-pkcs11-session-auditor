"""Ensure protected routes are inaccessible without explicit credentials."""
import pytest

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient
from agents.api import app as enterprise_app
from hsm_pkcs11_auditor.server import create_app

PAYLOAD = {
    "task_id": "T1",
    "target_identifier": "KEY-01",
    "primary_metric": 1.0,
    "secondary_metric": 1.0,
    "status_descriptor": "NOMINAL",
}


@pytest.mark.parametrize("factory", [lambda: enterprise_app, create_app])
def test_api_requires_configured_token(factory, monkeypatch):
    monkeypatch.delenv("HSM_API_TOKEN", raising=False)
    client = TestClient(factory())
    assert client.get("/health").status_code == 200
    assert client.post("/api/audit", json=PAYLOAD).status_code == 503
    monkeypatch.setenv("HSM_API_TOKEN", "test-only-token")
    assert client.post("/api/audit", json=PAYLOAD).status_code == 401
    assert client.post("/api/audit", json=PAYLOAD, headers={"X-API-Key": "test-only-token"}).status_code == 200


def test_audit_logs_protected(monkeypatch):
    monkeypatch.setenv("HSM_API_TOKEN", "test-only-token")
    client = TestClient(enterprise_app)
    assert client.get("/api/audit/logs").status_code == 401
    assert client.get("/metrics").status_code == 401
    assert client.get("/api/audit/logs", headers={"X-API-Key": "test-only-token"}).status_code == 200


def test_sensitive_identifier_rejected_without_exposing_value(monkeypatch):
    monkeypatch.setenv("HSM_API_TOKEN", "test-only-token")
    client = TestClient(enterprise_app)
    response = client.post("/api/audit", json={**PAYLOAD, "task_id": "secret@example.com"},
        headers={"X-API-Key": "test-only-token"})
    assert response.status_code == 422
    assert "secret@example.com" not in response.text
    response = client.post("/api/chat", json={"query": "secret@example.com"},
        headers={"X-API-Key": "test-only-token"})
    assert response.status_code == 422
    assert "secret@example.com" not in response.text
