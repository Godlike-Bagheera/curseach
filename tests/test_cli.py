"""CLI: exit-code гейт по уровню (--fail-on)."""

from scripts.cli import gate_findings

_F = [{"level": "CRITICAL"}, {"level": "HIGH"}, {"level": "MEDIUM"}, {"level": "LOW"}]


def test_gate_critical():
    assert len(gate_findings(_F, "critical")) == 1


def test_gate_high():
    assert len(gate_findings(_F, "high")) == 2


def test_gate_low():
    assert len(gate_findings(_F, "low")) == 4


def test_gate_none():
    assert gate_findings(_F, "none") == []
