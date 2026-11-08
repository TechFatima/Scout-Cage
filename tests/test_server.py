import pytest
from pydantic import ValidationError

from server import Sample


def test_goal_defaults_to_empty_string():
    assert Sample(code="print(1)").goal == ""


def test_goal_accepts_500_characters():
    assert len(Sample(code="print(1)", goal="x" * 500).goal) == 500


def test_goal_rejects_more_than_500_characters():
    with pytest.raises(ValidationError):
        Sample(code="print(1)", goal="x" * 501)