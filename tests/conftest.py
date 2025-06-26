import pytest
import requests

UPSTREAM_SCHEMA_REFS = {
    # There's no release with the SCHEMA doc yet
    # TODO Only map to OpenVEX release tags
    # Also, there's a bug in the upstream schema
    # so use the downstream version
    # "main": "https://raw.githubusercontent.com/openvex/spec/refs/heads/main/openvex_json_schema.json",
    "downstream_main": "https://raw.githubusercontent.com/colin-pm/spec/refs/heads/schema_fixes/openvex_json_schema.json",
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
