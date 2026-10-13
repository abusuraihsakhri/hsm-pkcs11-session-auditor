"""Verify concurrent audit append ordering and failed action records."""
from concurrent.futures import ThreadPoolExecutor
import pytest
from agents.base import AuditTrail, ActionExecutor, AuditLogger
from hsm_pkcs11_auditor.agents import HMACAuditTrail


@pytest.mark.parametrize("trail,emit", [
    (AuditTrail("key"), lambda t, i: t.log("actor", "test", "EVENT", {"number": i})),
    (HMACAuditTrail("key"), lambda t, i: t.record("EVENT", {"number": i})),
])
def test_concurrent_audit_entries_keep_chain_valid(trail, emit):
    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(lambda i: emit(trail, i), range(100)))
    entries = trail.get_trail()
    assert len(entries) == 100
    assert len({entry["audit_id"] for entry in entries}) == 100
    assert trail.verify_integrity() is True


def test_failed_action_is_logged_without_sensitive_exception_text():
    def fail():
        raise ValueError("sensitive identifier information")
    with pytest.raises(ValueError):
        ActionExecutor.execute_with_audit("actor", "test", "FAILURE_TEST", fail)
    assert AuditLogger.get_trail()[-1]["event_type"] == "FAILURE_TEST"
    assert AuditLogger.verify_integrity()
