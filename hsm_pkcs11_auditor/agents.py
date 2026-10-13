"""
Distributed Component Coordination & Executive Hierarchy for Hardware Security Module (HSM) PKCS#11 Session & Key Custody Agent.
Domain: Hardware Security
"""
import uuid
import hmac
import hashlib
import os
import secrets
import threading
import time
from typing import Dict, Any, List, Optional
from .models import FrontierPayload, AgentTelemetryAlert, ExecutionStatus
from .engine import FrontierDomainEngine


class PKCS11FunctionAuditorAgent:
    """Specialized Sub-Agent 1: Primary Parameter & Integrity Auditor."""
    def audit(self, payload: FrontierPayload) -> List[AgentTelemetryAlert]:
        alerts = []
        res = FrontierDomainEngine.evaluate_primary_parameter(payload.primary_metric)
        if res:
            alerts.append(AgentTelemetryAlert(
                alert_id=str(uuid.uuid4())[:8],
                origin_agent="PKCS11FunctionAuditorAgent",
                status=ExecutionStatus.ELEVATED_RISK,
                summary=res["summary"],
                technical_details=res["details"],
                actionable_remediation=res["remediation"],
            ))
        return alerts


class KeyUsageAttributeEnforcerAgent:
    """Specialized Sub-Agent 2: Critical Kinetics & Security Safeguard."""
    def audit(self, payload: FrontierPayload) -> List[AgentTelemetryAlert]:
        alerts = []
        res = FrontierDomainEngine.evaluate_secondary_kinetics(payload.secondary_metric, payload.is_critical_flag)
        if res:
            alerts.append(AgentTelemetryAlert(
                alert_id=str(uuid.uuid4())[:8],
                origin_agent="KeyUsageAttributeEnforcerAgent",
                status=ExecutionStatus.CRITICAL_INTERVENTION if payload.is_critical_flag else ExecutionStatus.ELEVATED_RISK,
                summary=res["summary"],
                technical_details=res["details"],
                actionable_remediation=res["remediation"],
            ))
        return alerts


class QuorumAuthenticationAgent:
    """Specialized Sub-Agent 3: Protocol Conformance & Anomaly Triager."""
    def audit(self, payload: FrontierPayload) -> List[AgentTelemetryAlert]:
        alerts = []
        res = FrontierDomainEngine.audit_specification_conformance(payload.status_descriptor, payload.attributes)
        if res:
            alerts.append(AgentTelemetryAlert(
                alert_id=str(uuid.uuid4())[:8],
                origin_agent="QuorumAuthenticationAgent",
                status=ExecutionStatus.ELEVATED_RISK,
                summary=res["summary"],
                technical_details=res["details"],
                actionable_remediation=res["remediation"],
            ))
        return alerts


class HMACAuditTrail:
    """Tamper-evident HMAC-SHA256 audit trail for HSM operations."""
    def __init__(self, secret_key: Optional[str] = None):
        resolved = secret_key or os.getenv("HSM_AUDIT_SECRET_KEY")
        if not resolved:
            resolved = secrets.token_hex(32)
        self.secret_key = resolved.encode("utf-8") if isinstance(resolved, str) else resolved
        self._chain: List[Dict[str, Any]] = []
        self._lock = threading.RLock()

    def record(self, event_type: str, details: Dict[str, Any]) -> Dict[str, Any]:
        import json
        from datetime import datetime, timezone
        payload_str = json.dumps(details, sort_keys=True)
        payload_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
        with self._lock:
            audit_id = f"HSM-AUDIT-{int(time.time()*1000)}-{len(self._chain)+1}"
            ts = datetime.now(timezone.utc).isoformat()
            prev_hash = self._chain[-1]["current_hash"] if self._chain else "HSM_GENESIS_0000000000000000"
            sign_string = f"{audit_id}|{ts}|{event_type}|{payload_hash}|{prev_hash}"
            signature = hmac.new(self.secret_key, sign_string.encode("utf-8"), hashlib.sha256).hexdigest()
            entry = {
                "audit_id": audit_id,
                "timestamp": ts,
                "event_type": event_type,
                "payload_hash": payload_hash,
                "prev_hash": prev_hash,
                "current_hash": signature,
            }
            self._chain.append(entry)
            return entry

    def verify_integrity(self) -> bool:
        with self._lock:
            for i, entry in enumerate(self._chain):
                prev = self._chain[i-1]["current_hash"] if i > 0 else "HSM_GENESIS_0000000000000000"
                if entry["prev_hash"] != prev:
                    return False
                sign_string = f"{entry['audit_id']}|{entry['timestamp']}|{entry['event_type']}|{entry['payload_hash']}|{entry['prev_hash']}"
                expected = hmac.new(self.secret_key, sign_string.encode("utf-8"), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(entry["current_hash"], expected):
                    return False
            return True

    def get_trail(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [entry.copy() for entry in self._chain]


_GLOBAL_HSM_AUDIT = HMACAuditTrail()


class HSMSessionCoordinator:
    """Executive Coordinator & Air-Gapped Supervisory Intelligence."""
    def __init__(self):
        self.sub_1 = PKCS11FunctionAuditorAgent()
        self.sub_2 = KeyUsageAttributeEnforcerAgent()
        self.sub_3 = QuorumAuthenticationAgent()
        self.execution_ledger: Dict[str, Dict[str, Any]] = {}
        self.audit_trail = _GLOBAL_HSM_AUDIT

    def process(self, payload: FrontierPayload) -> Dict[str, Any]:
        all_alerts: List[AgentTelemetryAlert] = []
        all_alerts.extend(self.sub_1.audit(payload))
        all_alerts.extend(self.sub_2.audit(payload))
        all_alerts.extend(self.sub_3.audit(payload))

        crit_count = sum(1 for a in all_alerts if a.status == ExecutionStatus.CRITICAL_INTERVENTION)
        warn_count = sum(1 for a in all_alerts if a.status == ExecutionStatus.ELEVATED_RISK)

        if crit_count > 0:
            status = ExecutionStatus.CRITICAL_INTERVENTION
        elif warn_count > 0:
            status = ExecutionStatus.ELEVATED_RISK
        else:
            status = ExecutionStatus.NOMINAL

        dossier = {
            "system": "hsm-pkcs11-session-auditor",
            "domain": "Hardware Security",
            "task_id": payload.task_id,
            "target_identifier": payload.target_identifier,
            "overall_status": status.value,
            "total_alerts": len(all_alerts),
            "critical_count": crit_count,
            "warning_count": warn_count,
            "alerts": [a.to_dict() for a in all_alerts],
            "standard_specification": "OASIS PKCS#11 Cryptographic Token Interface",
            "consensus_summary": f"Consensus evaluation completed across 3 sub-agents with status [{status.value}].",
        }

        audit_entry = self.audit_trail.record("HSM_SESSION_AUDIT", {
            "task_id": payload.task_id,
            "overall_status": status.value,
            "total_alerts": len(all_alerts),
        })
        dossier["audit_hash"] = audit_entry["current_hash"]

        self.execution_ledger[payload.task_id] = dossier
        return dossier

    def query_supervisory_chat(self, query: str) -> str:
        q = query.strip().lower()
        if "status" in q or "ledger" in q:
            return f"Hardware Security Module (HSM) PKCS#11 Session & Key Custody Agent currently managing {len(self.execution_ledger)} execution tasks in air-gapped memory."
        elif "standard" in q or "spec" in q:
            return "This demonstration references the OASIS PKCS#11 Cryptographic Token Interface but implements only heuristic telemetry rules, not PKCS#11 conformance checks."
        else:
            return "Local telemetry threshold evaluator ready; no HSM or PKCS#11 device is connected."
