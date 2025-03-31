import pytest
from hypothesis import given, HealthCheck, settings
from hypothesis_jsonschema import from_schema

from py_vex import Document

from conftest import UPSTREAM_SCHEMA_REFS


@pytest.mark.parametrize("version", UPSTREAM_SCHEMA_REFS.keys())
def test_document_instantiation_with_schema(external_schemas, version):
    schema = external_schemas[version]

    @given(from_schema(schema))
    @settings(suppress_health_check=(HealthCheck.too_slow,))
    def test_instantiation(data):
        assert Document(**data)

    test_instantiation()
