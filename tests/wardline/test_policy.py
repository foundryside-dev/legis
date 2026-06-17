from legis.wardline.governor import WardlineCellPolicy
from legis.wardline.ingest import WardlineSeverity, active_defects
from legis.wardline.policy import resolve_cell


def _finding(sev: str):
    return active_defects({"findings": [
        {"rule_id": "R", "message": "m", "severity": sev, "kind": "defect",
         "fingerprint": "fp", "qualname": "q", "properties": {}, "suppression_state": "active"}
    ]})[0]


def test_at_or_above_fail_on_gets_the_gate_cell():
    assert resolve_cell(
        _finding("ERROR"),
        fail_on=WardlineSeverity.ERROR,
        gate_cell=WardlineCellPolicy.BLOCK_ESCALATE,
    ) is WardlineCellPolicy.BLOCK_ESCALATE
    assert resolve_cell(
        _finding("CRITICAL"),
        fail_on=WardlineSeverity.ERROR,
        gate_cell=WardlineCellPolicy.BLOCK_ESCALATE,
    ) is WardlineCellPolicy.BLOCK_ESCALATE


def test_below_fail_on_is_surface_only():
    assert resolve_cell(
        _finding("WARN"),
        fail_on=WardlineSeverity.ERROR,
        gate_cell=WardlineCellPolicy.BLOCK_ESCALATE,
    ) is WardlineCellPolicy.SURFACE_ONLY
