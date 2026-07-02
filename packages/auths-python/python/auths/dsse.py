"""Generic DSSE — DSSE-wrap an in-toto Statement with an agent identity, verify offline.

The signing/verification logic lives in the Rust SDK (`auths_sdk::workflows::dsse`);
this is a thin, Pythonic wrapper. The in-toto *predicate* is entirely the caller's —
e.g. a ``recurve.dev/verdict/v1`` code-correctness verdict.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Union

from auths._native import dsse_sign_statement as _dsse_sign_statement
from auths._native import dsse_verify_statement as _dsse_verify_statement

PathLike = Union[str, "Path"]

# The DSSE payload type for an in-toto Statement (RFC / in-toto attestation spec).
INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
# The in-toto Statement schema type.
INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"


def intoto_statement(subject: list[dict[str, Any]], predicate_type: str, predicate: dict[str, Any]) -> str:
    """Build a canonical in-toto Statement JSON string.

    Args:
        subject: The statement subjects (``[{"name": ..., "digest": {"sha256": ...}}]``).
        predicate_type: The predicate type URI (e.g. ``recurve.dev/verdict/v1``).
        predicate: The predicate payload (the claim being attested).

    Returns:
        The in-toto Statement as a compact, sorted-key JSON string.
    """
    statement = {
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": subject,
        "predicateType": predicate_type,
        "predicate": predicate,
    }
    return json.dumps(statement, sort_keys=True, separators=(",", ":"))


def sign_statement(
    statement_json: str,
    key_alias: str,
    keyid_did: str,
    repo_path: PathLike,
    passphrase: str | None = None,
) -> str:
    """DSSE-sign an in-toto Statement with an agent identity's key.

    Args:
        statement_json: The complete in-toto Statement to wrap and sign.
        key_alias: Keychain alias of the agent's signing key.
        keyid_did: The agent's ``did:keri:`` (recorded as the signature keyid).
        repo_path: Path to the agent's auths keychain/repo.
        passphrase: Optional passphrase (else ``AUTHS_PASSPHRASE``).

    Returns:
        The DSSE envelope as a JSON string.
    """
    return _dsse_sign_statement(statement_json, key_alias, keyid_did, str(repo_path), passphrase)


def verify_statement(envelope_json: str, public_key_hex: str) -> dict[str, Any]:
    """Verify a DSSE-wrapped in-toto Statement offline against a pinned key.

    Args:
        envelope_json: The DSSE envelope from :func:`sign_statement`.
        public_key_hex: The agent's verkey, hex-encoded.

    Returns:
        The verified in-toto Statement (parsed dict).

    Raises:
        ValueError: if no signature verifies against the key (forged/absent/wrong key).
    """
    return json.loads(_dsse_verify_statement(envelope_json, public_key_hex))
