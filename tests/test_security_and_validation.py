"""
Tests for security fixes and input validation.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import math
from agents.base import AuditTrail, PHIGuard, SecurityException
from agents.models import SystemTaskPayload
from hsm_pkcs11_auditor.models import FrontierPayload
from hsm_pkcs11_auditor.agents import HSMSessionCoordinator, HMACAuditTrail
from hsm_pkcs11_auditor.cli import main as hsm_main


class TestAuditTrailSecurity:
    def test_audit_trail_generates_random_key_when_no_secret(self):
        """AuditTrail should generate a random key when no secret is provided."""
        trail = AuditTrail(secret_key=None)
        # Ensure no env var interferes
        import os
        original = os.environ.pop("AUDIT_SECRET_KEY", None)
        try:
            trail2 = AuditTrail()
            assert len(trail2.secret_key) > 0
        finally:
            if original is not None:
                os.environ["AUDIT_SECRET_KEY"] = original

    def test_audit_trail_verify_integrity_with_hmac(self):
        """verify_integrity should verify both chain linkage and HMAC signatures."""
        trail = AuditTrail(secret_key="test-secret-key")
        trail.log("test_actor", "test_tier", "TEST_EVENT", {"data": "value1"})
        trail.log("test_actor", "test_tier", "TEST_EVENT", {"data": "value2"})
        trail.log("test_actor", "test_tier", "TEST_EVENT", {"data": "value3"})
        assert trail.verify_integrity() is True

    def test_audit_trail_detects_tampering(self):
        """verify_integrity should detect tampered entries."""
        trail = AuditTrail(secret_key="test-secret-key")
        trail.log("test_actor", "test_tier", "TEST_EVENT", {"data": "value1"})
        trail.log("test_actor", "test_tier", "TEST_EVENT", {"data": "value2"})
        # Tamper with the first entry
        trail.logs[0]["payload_hash"] = "tampered_hash"
        assert trail.verify_integrity() is False

    def test_audit_trail_empty_is_valid(self):
        """An empty audit trail should verify as valid."""
        trail = AuditTrail(secret_key="test-secret-key")
        assert trail.verify_integrity() is True


class TestInputValidation:
    def test_system_task_payload_rejects_nan(self):
        """SystemTaskPayload should reject NaN metric values."""
        with pytest.raises(ValueError, match="finite"):
            SystemTaskPayload(
                task_id="T1",
                target_identifier="KEY-01",
                primary_metric=float("nan"),
                secondary_metric=1.0,
            )

    def test_system_task_payload_rejects_infinity(self):
        """SystemTaskPayload should reject infinite metric values."""
        with pytest.raises(ValueError, match="finite"):
            SystemTaskPayload(
                task_id="T1",
                target_identifier="KEY-01",
                primary_metric=float("inf"),
                secondary_metric=1.0,
            )

    def test_system_task_payload_rejects_empty_task_id(self):
        """SystemTaskPayload should reject empty task_id."""
        with pytest.raises(ValueError, match="empty or whitespace"):
            SystemTaskPayload(
                task_id="   ",
                target_identifier="KEY-01",
                primary_metric=1.0,
                secondary_metric=1.0,
            )

    def test_frontier_payload_rejects_nan(self):
        """FrontierPayload should reject NaN metric values."""
        with pytest.raises(ValueError, match="finite"):
            FrontierPayload(
                task_id="T1",
                target_identifier="KEY-01",
                primary_metric=float("nan"),
                secondary_metric=1.0,
                status_descriptor="NOMINAL",
            )

    def test_frontier_payload_rejects_infinity(self):
        """FrontierPayload should reject infinite metric values."""
        with pytest.raises(ValueError, match="finite"):
            FrontierPayload(
                task_id="T1",
                target_identifier="KEY-01",
                primary_metric=1.0,
                secondary_metric=float("-inf"),
                status_descriptor="NOMINAL",
            )

    def test_frontier_payload_rejects_empty_identifiers(self):
        """FrontierPayload should reject empty identifiers."""
        with pytest.raises(ValueError, match="empty or whitespace"):
            FrontierPayload(
                task_id="",
                target_identifier="KEY-01",
                primary_metric=1.0,
                secondary_metric=1.0,
                status_descriptor="NOMINAL",
            )


class TestHSMCoordinatorAudit:
    def test_coordinator_produces_audit_hash(self):
        """HSMSessionCoordinator should produce audit hash in dossier."""
        coord = HSMSessionCoordinator()
        payload = FrontierPayload(
            task_id="AUDIT-TEST-01",
            target_identifier="KEY-01",
            primary_metric=12.0,
            secondary_metric=4.0,
            status_descriptor="NOMINAL",
        )
        dossier = coord.process(payload)
        assert "audit_hash" in dossier
        assert len(dossier["audit_hash"]) > 0

    def test_coordinator_audit_trail_verifies(self):
        """HSMSessionCoordinator audit trail should verify integrity."""
        coord = HSMSessionCoordinator()
        payload = FrontierPayload(
            task_id="AUDIT-TEST-02",
            target_identifier="KEY-02",
            primary_metric=12.0,
            secondary_metric=4.0,
            status_descriptor="NOMINAL",
        )
        coord.process(payload)
        assert coord.audit_trail.verify_integrity() is True

    def test_hsm_audit_trail_detects_tampering(self):
        """HMACAuditTrail should detect tampered entries."""
        trail = HMACAuditTrail(secret_key="test-key")
        trail.record("TEST_EVENT", {"data": "value1"})
        trail.record("TEST_EVENT", {"data": "value2"})
        # Tamper with entry
        trail._chain[0]["payload_hash"] = "tampered"
        assert trail.verify_integrity() is False


class TestHSMCLI:
    def test_hsm_verify_audit_command(self):
        """HSM CLI verify-audit command should work."""
        coord = HSMSessionCoordinator()
        payload = FrontierPayload(
            task_id="CLI-AUDIT-01",
            target_identifier="KEY-01",
            primary_metric=12.0,
            secondary_metric=4.0,
            status_descriptor="NOMINAL",
        )
        coord.process(payload)
        assert hsm_main(["verify-audit"]) == 0

    def test_hsm_audit_command(self):
        """HSM CLI audit command should work."""
        assert hsm_main(["audit", "--task-id", "HSM-CLI-01"]) == 0
