import pytest
import requests

UPSTREAM_SCHEMA_REFS = {
    # TODO Map to OpenVEX release tag
    "main": "https://raw.githubusercontent.com/openvex/spec/refs/heads/main/openvex_json_schema.json",
}


@pytest.fixture(scope="session")
def external_schemas():
    """Fetches schemas from GitHub"""
    schemas = {}
    for version, url in UPSTREAM_SCHEMA_REFS.items():
        response = requests.get(url)
        response.raise_for_status()
        schemas[version] = response.json()
    return schemas
