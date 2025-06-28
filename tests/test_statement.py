from datetime import datetime, timezone

import pytest
from freezegun import freeze_time

from py_vex.statement import Statement
from py_vex.vulnerability import Vulnerability


@freeze_time("2025-01-14")
def test_statement_creation_default_timestamp():
    s = Statement(
        vulnerability=Vulnerability(name="CVE-2014-123456"),
        status="fixed",
    )
    assert s.timestamp == datetime(year=2025, month=1, day=14, tzinfo=timezone.utc)


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
    s = Statement(
        vulnerability=Vulnerability(name="CVE-2014-123456"),
        status="fixed",
        timestamp=time_input,
    )
    assert s.timestamp == reference_time
