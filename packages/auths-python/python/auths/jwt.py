"""JWT validation for Auths OIDC tokens.

Requires PyJWT: pip install auths-python[jwt]
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger("auths.jwt")


@dataclass
class AuthsClaims:
    """Validated claims from an Auths OIDC token."""

    sub: str
    """Subject claim — the signer's DID."""
    keri_prefix: str
    """KERI prefix of the identity."""
    capabilities: list[str]
    """Capabilities granted by this token."""
    iss: str
    """Issuer claim — the OIDC bridge URL."""
    aud: str
    """Audience claim — the service this token is intended for."""
    exp: int
    """Expiration time as Unix timestamp."""
    iat: int
    """Issued-at time as Unix timestamp."""
    jti: str
    """Unique JWT ID for replay prevention."""
    signer_type: str | None = None
    """Signer classification: `"Human"`, `"Agent"`, or `"Workload"`."""
    delegated_by: str | None = None
    """DID of the delegating identity, if this is a delegated token."""
    witness_quorum: dict | None = None
    """Witness quorum metadata, if witness-backed."""
    github_actor: str | None = None
    """GitHub username, present for GitHub Actions OIDC tokens."""
    github_repository: str | None = None
    """GitHub repository (owner/repo), present for GitHub Actions OIDC tokens."""

    def has_capability(self, cap: str) -> bool:
        """Check if token grants a specific capability."""
        return cap in self.capabilities

    def has_any_capability(self, caps: list[str]) -> bool:
        """Check if token grants any of the listed capabilities."""
        return any(c in self.capabilities for c in caps)

    def has_all_capabilities(self, caps: list[str]) -> bool:
        """Check if token grants all of the listed capabilities."""
        return all(c in self.capabilities for c in caps)

    @property
    def is_agent(self) -> bool:
        return self.signer_type == "Agent"

    @property
    def is_human(self) -> bool:
        return self.signer_type == "Human"

    @property
    def is_delegated(self) -> bool:
        return self.delegated_by is not None

    def __repr__(self) -> str:
        caps = ", ".join(self.capabilities[:3])
        if len(self.capabilities) > 3:
            caps += f" +{len(self.capabilities) - 3}"
        sub_short = self.sub[:25] if len(self.sub) > 25 else self.sub
        return (
            f"AuthsClaims(sub='{sub_short}...', "
            f"caps=[{caps}], type={self.signer_type})"
        )


class AuthsJWKSClient:
    """JWKS client with automatic key caching for Auths OIDC token validation.

    Args:
        jwks_url: The OIDC bridge's JWKS endpoint.
        cache_ttl: How long to cache JWKS keys, in seconds (default: 300).

    Examples:
        >>> jwks = AuthsJWKSClient("https://bridge.example.com/.well-known/jwks.json")
        >>> claims = jwks.verify_token(token, audience="my-service")
    """

    def __init__(self, jwks_url: str, *, cache_ttl: int = 300):
        try:
            import jwt as pyjwt
            from jwt import PyJWKClient
        except ImportError:
            raise ImportError(
                "PyJWT is required for JWT validation. "
                "Install it with: pip install auths-python[jwt]"
            )

        from auths._errors import NetworkError

        self._pyjwt = pyjwt
        self._NetworkError = NetworkError
        self._client = PyJWKClient(jwks_url, cache_jwk_set=True, lifespan=cache_ttl)
        self._jwks_url = jwks_url
        logger.debug("Initialized JWKS client for %s (cache_ttl=%ds)", jwks_url, cache_ttl)

    def verify_token(
        self,
        token: str,
        *,
        audience: str,
        issuer: str | None = None,
        leeway: int = 60,
    ) -> AuthsClaims:
        """Verify an Auths OIDC token and extract claims.

        Args:
            token: Raw JWT bearer token string.
            audience: Expected audience claim.
            issuer: Expected issuer claim (optional, verified if set).
            leeway: Clock skew tolerance in seconds (default: 60).

        Returns:
            AuthsClaims with the validated token claims.

        Raises:
            VerificationError: If the token is expired, has wrong audience/issuer, or invalid signature.
            NetworkError: If JWKS keys cannot be fetched.

        Examples:
            >>> claims = jwks.verify_token(bearer_token, audience="my-service")
            >>> if claims.has_capability("read"):
            ...     allow_access()
        """
        from auths._errors import VerificationError

        try:
            signing_key = self._client.get_signing_key_from_jwt(token)
        except Exception as e:
            logger.warning("JWKS fetch failed for %s: %s", self._jwks_url, e)
            raise self._NetworkError(
                f"Failed to fetch JWKS from {self._jwks_url}: {e}",
                code="jwks_fetch_failed",
                should_retry=True,
            )

        try:
            options = {"verify_aud": True, "verify_exp": True}
            if issuer:
                options["verify_iss"] = True

            decoded = self._pyjwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "ES256", "EdDSA"],
                audience=audience,
                issuer=issuer,
                leeway=leeway,
                options=options,
            )
        except self._pyjwt.ExpiredSignatureError:
            raise VerificationError(
                "Token expired. Request a new token from the OIDC bridge.",
                code="token_expired",
            )
        except self._pyjwt.InvalidAudienceError:
            raise VerificationError(
                f"Token audience does not match expected '{audience}'. "
                "Ensure the token was issued for this service.",
                code="invalid_audience",
            )
        except self._pyjwt.InvalidIssuerError:
            raise VerificationError(
                f"Token issuer does not match expected '{issuer}'. "
                "Check the OIDC bridge URL configuration.",
                code="invalid_issuer",
            )
        except self._pyjwt.InvalidSignatureError:
            raise VerificationError(
                "Token signature is invalid. The token may have been tampered with "
                "or the JWKS keys may have rotated. Try refreshing the JWKS cache.",
                code="invalid_signature",
            )
        except self._pyjwt.DecodeError as e:
            raise VerificationError(
                f"Token decode failed: {e}. Ensure the token is a valid JWT string.",
                code="decode_error",
            )

        logger.debug(
            "Token verified: sub=%s, caps=%s",
            decoded.get("sub"),
            decoded.get("capabilities"),
        )

        return AuthsClaims(
            sub=decoded["sub"],
            keri_prefix=decoded.get("keri_prefix", ""),
            capabilities=decoded.get("capabilities", []),
            iss=decoded.get("iss", ""),
            aud=decoded.get("aud", ""),
            exp=decoded.get("exp", 0),
            iat=decoded.get("iat", 0),
            jti=decoded.get("jti", ""),
            signer_type=decoded.get("signer_type"),
            delegated_by=decoded.get("delegated_by"),
            witness_quorum=decoded.get("witness_quorum"),
            github_actor=decoded.get("github_actor"),
            github_repository=decoded.get("github_repository"),
        )


def verify_token(
    token: str,
    *,
    jwks_url: str,
    audience: str,
    issuer: str | None = None,
    leeway: int = 60,
) -> AuthsClaims:
    """Verify an Auths OIDC token (one-shot, no JWKS caching).

    For production use, prefer `AuthsJWKSClient` which caches JWKS keys.

    Args:
        token: Raw JWT bearer token string.
        jwks_url: URL to fetch JSON Web Key Set.
        audience: Expected audience claim.
        issuer: Expected issuer claim (optional).
        leeway: Clock skew tolerance in seconds (default: 60).

    Returns:
        AuthsClaims with the validated token claims.

    Raises:
        VerificationError: If the token is invalid.
        NetworkError: If JWKS keys cannot be fetched.

    Examples:
        >>> from auths.jwt import verify_token
        >>> claims = verify_token(token, jwks_url="...", audience="my-service")
    """
    client = AuthsJWKSClient(jwks_url)
    return client.verify_token(token, audience=audience, issuer=issuer, leeway=leeway)
