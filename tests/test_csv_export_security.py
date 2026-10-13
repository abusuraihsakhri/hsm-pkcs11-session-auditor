"""Spreadsheet formula injection regression for both CSV CLIs."""
import csv
import pytest
from cli import main as enterprise_cli
from hsm_pkcs11_auditor.cli import main as core_cli
from hsm_pkcs11_auditor.parsing import safe_spreadsheet_cell

@pytest.mark.parametrize("input_value", ["=2+2", "+cmd", "-SUM(1,2)", "@formula", "  =1+1"])
def test_formula_like_cells_are_escaped(input_value):
    assert safe_spreadsheet_cell(input_value).startswith("'")

@pytest.mark.parametrize("input_value", ["-2.5", "+3.5", "42"])
def test_numeric_cells_are_preserved(input_value):
    assert safe_spreadsheet_cell(input_value) == input_value

@pytest.mark.parametrize("cli", [core_cli, enterprise_cli])
def test_batch_does_not_export_formula_identifiers(cli, tmp_path):
    source = tmp_path / "in.csv"
    output = tmp_path / "out.csv"
    source.write_text(
        "task_id,target_identifier,primary_metric,secondary_metric,is_critical_flag,status_descriptor\n"
        'T1,=2+2,1,1,False,NOMINAL\n', encoding="utf-8"
    )
    assert cli(["batch", "-i", str(source), "-o", str(output)]) == 0
    with output.open(newline="", encoding="utf-8") as stream:
        row = next(csv.DictReader(stream))
    assert row["target_identifier"] == "'=2+2"
