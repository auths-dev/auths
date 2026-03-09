"""Auths error hierarchy. All errors inherit from AuthsError."""


class AuthsError(Exception):
    """Base error for all Auths SDK operations."""

    def __init__(self, message: str, code: str, **context):
        self.message = message
        self.code = code
        self.context = context
        super().__init__(message)

    def __repr__(self):
        return f"{type(self).__name__}(code={self.code!r}, message={self.message!r})"


class VerificationError(AuthsError):
    """Attestation or chain verification failed.

    Codes: invalid_signature, expired_attestation, revoked_device,
    broken_chain, missing_attestation, unknown_signer.
    """


class CryptoError(AuthsError):
    """Cryptographic operation failed (bad key, signing error).

    Codes: invalid_key, signing_failed, key_not_found.
    """


class KeychainError(AuthsError):
    """Keychain access failed.

    Codes: keychain_locked, key_not_found, permission_denied.
    """


class StorageError(AuthsError):
    """Git storage operation failed.

    Codes: repo_not_found, ref_conflict, corrupt_data, duplicate_attestation.
    """


class NetworkError(AuthsError):
    """Network operation failed (token exchange, registry sync).

    Codes: connection_failed, timeout, server_error, auth_failed.
    """

    def __init__(self, message: str, code: str, should_retry: bool = False, **context):
        self.should_retry = should_retry
        super().__init__(message, code, **context)


class IdentityError(AuthsError):
    """Identity lifecycle operation failed.

    Codes: identity_exists, identity_not_found, invalid_did.
    """


class OrgError(AuthsError):
    """Organization operation failed.

    Codes: org_error, admin_not_found, member_not_found,
    already_revoked, invalid_capability, invalid_role.
    """


class PairingError(AuthsError):
    """Device pairing operation failed.

    Codes: pairing_error, timeout, connection_failed, session_expired.
    """

    def __init__(self, message: str, code: str, should_retry: bool = False, **context):
        self.should_retry = should_retry
        super().__init__(message, code, **context)
