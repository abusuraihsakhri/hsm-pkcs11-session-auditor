"""Unimplemented model providers must not masquerade as real integrations."""
import pytest
from agents.llm_factory import LLMFactory

def test_mock_does_not_claim_verification():
    response = LLMFactory.create("mock").invoke("check standard")
    assert "No hardware or standards verification performed" in response

@pytest.mark.parametrize("name", ["openai", "ollama", "claude", "unknown"])
def test_unsupported_provider_fails_closed(name):
    with pytest.raises(NotImplementedError):
        LLMFactory.create(name)
