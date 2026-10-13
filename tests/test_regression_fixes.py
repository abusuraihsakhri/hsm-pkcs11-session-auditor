"""Regression tests for CSV boolean parsing and audit snapshot safety."""
import csv
import pytest
from hsm_pkcs11_auditor.parsing import parse_bool
from hsm_pkcs11_auditor.agents import HMACAuditTrail
from agents.base import AuditTrail
from cli import main as enterprise_cli
from hsm_pkcs11_auditor.cli import main as core_cli


@pytest.mark.parametrize("value,expected", [
    ("True", True), ("true", True), ("1", True), ("yes", True),
    ("FALSE", False), ("False", False), ("0", False), ("", False),
    (None, False), (False, False), (True, True),
])
def test_parse_bool(value, expected):
    assert parse_bool(value) is expected


def test_parse_bool_rejects_invalid():
    with pytest.raises(ValueError, match="Invalid boolean"):
        parse_bool("sometimes")


@pytest.mark.parametrize("cli", [core_cli, enterprise_cli])
def test_batch_false_is_not_critical(cli, tmp_path):
    source = tmp_path / "input.csv"
    output = tmp_path / "output.csv"
    source.write_text(
        "task_id,target_identifier,primary_metric,secondary_metric,is_critical_flag,status_descriptor\n"
        "T1,KEY-01,1,1,False,NOMINAL\n"
        "T2,KEY-02,1,1,True,NOMINAL\n", encoding="utf-8"
    )
    assert cli(["batch", "-i", str(source), "-o", str(output)]) == 0
    with output.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    field = "overall_status" if cli is core_cli else "overall_urgency"
    assert rows[0][field] not in {"CRITICAL_INTERVENTION_REQUIRED", "CRITICAL_STAT_PANIC"}
    assert rows[1][field] in {"CRITICAL_INTERVENTION_REQUIRED", "CRITICAL_STAT_PANIC"}


@pytest.mark.parametrize("trail,record", [
    (AuditTrail(secret_key="test-key"), lambda t: t.log("a", "b", "c", {"ok": True})),
    (HMACAuditTrail(secret_key="test-key"), lambda t: t.record("c", {"ok": True})),
])
def test_trail_snapshot_is_not_mutable(trail, record):
    record(trail)
    snapshot = trail.get_trail()
    snapshot[0]["payload_hash"] = "changed"
    assert trail.verify_integrity()
