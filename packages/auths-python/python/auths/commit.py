"""Git commit signing — SSHSIG PEM output."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CommitSigningResult:
    """Result of signing git commit/tag data.

    The `.signature_pem` is a valid SSHSIG PEM block that can be used with
    `git verify-commit` or written to a signature file.
    """

    signature_pem: str
    method: str
    namespace: str

    def __repr__(self) -> str:
        pem_preview = self.signature_pem[:40] + "..." if len(self.signature_pem) > 40 else self.signature_pem
        return (
            f"CommitSigningResult(method='{self.method}', "
            f"pem='{pem_preview}')"
        )
