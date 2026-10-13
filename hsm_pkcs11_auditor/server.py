"""
FastAPI REST API Server for Hardware Security Module (HSM) PKCS#11 Session & Key Custody Agent.
"""
import os
import hmac
from typing import Dict, Any, Optional
from .models import FrontierPayload
from .agents import HSMSessionCoordinator

coordinator = HSMSessionCoordinator()


def create_app():
    try:
        from fastapi import FastAPI, Depends, Header, HTTPException
        from pydantic import BaseModel

        app = FastAPI(
            title="Hardware Security Module (HSM) PKCS#11 Session & Key Custody Agent",
            description="Audits OASIS PKCS#11 Cryptoki function streams (C_Initialize, C_GenerateKey, C_Sign), enforcing multi-party M-of-N quorum.",
            version="2.0.0-FRONTIER",
        )

        def require_api_token(x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")):
            token = os.getenv("HSM_API_TOKEN")
            if not token:
                raise HTTPException(status_code=503, detail="HSM_API_TOKEN is not configured")
            if not x_api_key or not hmac.compare_digest(x_api_key, token):
                raise HTTPException(status_code=401, detail="Invalid API key")

        class TaskRequest(BaseModel):
            task_id: str = "TASK-2026-001"
            target_identifier: str = "TARGET-BIO-KEY"
            primary_metric: float = 28.5
            secondary_metric: float = 14.2
            status_descriptor: str = "DISCORDANT_ANOMALY"
            is_critical_flag: bool = True
            attributes: Dict[str, Any] = {}

        class ChatRequest(BaseModel):
            query: str

        @app.get("/health")
        def health():
            return {"status": "HEALTHY", "system": "hsm-pkcs11-session-auditor", "domain": "Hardware Security", "version": "2.0.0-FRONTIER"}

        @app.post("/api/audit", dependencies=[Depends(require_api_token)])
        def api_audit(req: TaskRequest):
            payload = FrontierPayload(
                task_id=req.task_id,
                target_identifier=req.target_identifier,
                primary_metric=req.primary_metric,
                secondary_metric=req.secondary_metric,
                status_descriptor=req.status_descriptor,
                is_critical_flag=req.is_critical_flag,
                attributes=req.attributes,
            )
            return coordinator.process(payload)

        @app.post("/api/chat", dependencies=[Depends(require_api_token)])
        def api_chat(req: ChatRequest):
            return {"response": coordinator.query_supervisory_chat(req.query)}

        return app
    except ImportError:
        return None
