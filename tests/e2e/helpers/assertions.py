"""Assertion helpers for Auths E2E tests."""

import json
import re
from pathlib import Path

import jsonschema


def validate_json_schema(data: dict, schema_name: str) -> None:
    """Validate data against a JSON Schema from the schemas/ directory."""
    schemas_dir = Path(__file__).resolve().parent.parent.parent.parent / "schemas"
    schema_path = schemas_dir / schema_name
    if not schema_path.exists():
        raise FileNotFoundError(f"Schema not found: {schema_path}")

    with open(schema_path) as f:
        schema = json.load(f)

    jsonschema.validate(instance=data, schema=schema)


DID_KERI_PATTERN = re.compile(r"^did:keri:E[A-Za-z0-9_-]+$")
DID_KEY_PATTERN = re.compile(r"^did:key:z6Mk[A-Za-z0-9]+$")


def assert_did_format(did: str) -> None:
    """Validate that a DID string matches expected format."""
    assert DID_KERI_PATTERN.match(did) or DID_KEY_PATTERN.match(did), (
        f"Invalid DID format: {did!r}. "
        f"Expected did:keri:E... or did:key:z6Mk..."
    )
