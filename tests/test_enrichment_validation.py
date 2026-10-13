"""Enrichment demonstrators reject nonfinite values and invalid thresholds."""
import pytest
from enrichment import ThresholdEngine

@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_values_rejected(value):
    engine = ThresholdEngine()
    with pytest.raises(ValueError, match="finite"):
        engine.evaluate(value, 1)
    with pytest.raises(ValueError, match="finite"):
        engine.evaluate(1, value)

@pytest.mark.parametrize("threshold", [0, -1, float("nan")])
def test_invalid_threshold(threshold):
    with pytest.raises(ValueError, match="finite positive"):
        ThresholdEngine(threshold=threshold)
