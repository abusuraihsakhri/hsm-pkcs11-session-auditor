"""
FastAPI REST API Server for Hsm Pkcs11 Session Auditor.
"""
import os
import hmac
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from .base import AuditLogger, PHIGuard
from .models import SystemTaskPayload, ConsensusDossier
from .supervisor import SystemSupervisor

supervisor = SystemSupervisor(model_provider="mock")

app = FastAPI(
    title="Hsm Pkcs11 Session Auditor API",
    description="Heuristic telemetry classification; not a PKCS#11 or HSM interface",
    version="3.0.0-ENTERPRISE",
)


def require_api_token(x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")):
    """Deny protected operations unless explicitly configured with a bearer secret."""
    token = os.getenv("HSM_API_TOKEN")
    if not token:
        raise HTTPException(status_code=503, detail="HSM_API_TOKEN is not configured")
    if not x_api_key or not hmac.compare_digest(x_api_key, token):
        raise HTTPException(status_code=401, detail="Invalid API key")


class ChatRequest(BaseModel):
    query: str


@app.get("/health")
def health():
    return {"status": "HEALTHY", "service": "hsm-pkcs11-session-auditor", "domain": "Hardware security telemetry", "standard": "Illustrative rules (not validated compliance)", "version": "3.0.0-ENTERPRISE"}


@app.get("/metrics", dependencies=[Depends(require_api_token)])
def metrics():
    return {
        "dossiers_processed_total": len(supervisor.dossier_registry),
        "audit_blocks_total": len(AuditLogger.get_trail()),
        "system_status": "NOMINAL_OPTIMAL"
    }


@app.post("/api/audit", dependencies=[Depends(require_api_token)])
def api_audit(payload: SystemTaskPayload):
    dossier = supervisor.process_task(payload)
    return dossier.to_dict()


@app.post("/api/chat", dependencies=[Depends(require_api_token)])
def api_chat(req: ChatRequest):
    try:
        ans = supervisor.query_supervisory_chat(req.query)
        return {"response": ans}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/audit/logs", dependencies=[Depends(require_api_token)])
def api_audit_logs():
    return {"audit_trail": AuditLogger.get_trail(), "verified": AuditLogger.verify_integrity()}
