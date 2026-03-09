from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

from auths._native import (
    add_witness as _add_witness,
    list_witnesses as _list_witnesses,
    remove_witness as _remove_witness,
)
from auths._client import _map_error
from auths._errors import AuthsError


@dataclass
class Witness:
    """A configured witness endpoint."""

    url: str
    did: Optional[str]
    label: Optional[str]


class WitnessService:
    """Resource service for witness configuration."""

    def __init__(self, client):
        self._client = client

    def add(
        self,
        url: str,
        label: str | None = None,
        repo_path: str | None = None,
    ) -> Witness:
        """Add a witness URL to the identity configuration.

        Args:
            url: Witness server URL (e.g. "http://127.0.0.1:3333").
            label: Optional human-readable label.

        Usage:
            w = client.witnesses.add("https://witness.example.com")
        """
        rp = repo_path or self._client.repo_path
        try:
            url_out, did, lbl = _add_witness(url, rp, label)
            return Witness(url=url_out, did=did, label=lbl)
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=AuthsError) from exc

    def remove(
        self,
        url: str,
        repo_path: str | None = None,
    ) -> None:
        """Remove a witness URL from configuration.

        Usage:
            client.witnesses.remove("https://witness.example.com")
        """
        rp = repo_path or self._client.repo_path
        try:
            _remove_witness(url, rp)
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=AuthsError) from exc

    def list(
        self,
        repo_path: str | None = None,
    ) -> list[Witness]:
        """List all configured witnesses.

        Usage:
            witnesses = client.witnesses.list()
        """
        rp = repo_path or self._client.repo_path
        try:
            raw = _list_witnesses(rp)
            data = json.loads(raw)
            return [
                Witness(
                    url=w["url"],
                    did=w.get("did"),
                    label=w.get("label"),
                )
                for w in data
            ]
        except (ValueError, RuntimeError) as exc:
            raise _map_error(exc, default_cls=AuthsError) from exc
