from datetime import datetime, timezone

import pytest
from dateutil.parser import parse
from freezegun import freeze_time

from vexipy.statement import Statement
from vexipy.status import StatusLabel
from vexipy.vulnerability import Vulnerability


def create_minimal_statement(time_input=None) -> Statement:
    obj = {
        "vulnerability": Vulnerability(name="CVE-2014-123456"),
        "status": "under_investigation",
    }
    if time_input:
        obj["timestamp"] = time_input
    return Statement(**obj)


@freeze_time("2025-01-14")
def test_statement_creation_default_timestamp():
    assert create_minimal_statement().timestamp == datetime(
        year=2025, month=1, day=14, tzinfo=timezone.utc
    )


reference_time = datetime(
    year=2025, month=1, day=14, hour=2, minute=1, second=0, tzinfo=timezone.utc
)
testdata = [
    reference_time,
    reference_time.timestamp(),
    reference_time.isoformat(),
]


@pytest.mark.parametrize("time_input", testdata)
def test_statement_creation_with_time_passed(time_input):
    assert create_minimal_statement(time_input).timestamp == reference_time


@freeze_time("2025-01-14")
def test_statement_update_with_timestamp():
    s = create_minimal_statement()
    s = s.update(status="fixed", timestamp="2026-01-14")
    assert s.status == StatusLabel.FIXED
    assert s.timestamp == parse("2026-01-14")


@freeze_time("2026-01-14")
def test_statement_update_without_timestamp():
    s = create_minimal_statement("2025-01-14")
    s = s.update(status="fixed")
    assert s.status == StatusLabel.FIXED
    assert s.timestamp == datetime.now(timezone.utc)
