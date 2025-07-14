from datetime import datetime, timezone

import pytest
from freezegun import freeze_time
from hypothesis import HealthCheck, given, settings
from hypothesis_jsonschema import from_schema

from py_vex import Document
from py_vex.statement import Statement
from py_vex.vulnerability import Vulnerability

from conftest import UPSTREAM_SCHEMA_REFS


@pytest.mark.parametrize("version", UPSTREAM_SCHEMA_REFS.keys())
def test_document_instantiation_with_schema(external_schemas, version):
    schema = external_schemas[version]

    @given(from_schema(schema))
    @settings(suppress_health_check=(HealthCheck.too_slow,))
    def test_instantiation(data):
        assert Document(**data)

    test_instantiation()


@freeze_time("2025-01-14")
def test_document_creation_default_timestamp():
    d = Document(
        context="https://openvex.dev/ns/v0.2.0",
        id="https://openvex.dev/docs/example/vex-9fb3463de1b57",
        author="Wolfi J Inkinson",
        version="1",
        statements=[
            Statement(
                vulnerability=Vulnerability(name="CVE-2014-123456"),
                status="fixed",
            )
        ],
    )
    assert d.timestamp == datetime(year=2025, month=1, day=14, tzinfo=timezone.utc)


reference_time = datetime(
    year=2025, month=1, day=14, hour=2, minute=1, second=0, tzinfo=timezone.utc
)
testdata = [
    reference_time,
    reference_time.timestamp(),
    reference_time.isoformat(),
]


@pytest.mark.parametrize("time_input", testdata)
def test_document_creation_with_time_passed(time_input):
    d = Document(
        context="https://openvex.dev/ns/v0.2.0",
        id="https://openvex.dev/docs/example/vex-9fb3463de1b57",
        author="Wolfi J Inkinson",
        version="1",
        statements=[
            Statement(
                vulnerability=Vulnerability(name="CVE-2014-123456"),
                status="fixed",
            )
        ],
        timestamp=time_input,
    )
    assert d.timestamp == reference_time
