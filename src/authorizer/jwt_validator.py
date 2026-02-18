"""JWT Token Validator for AWS Cognito Access Tokens.

Fetches the JSON Web Key Set (JWKS) from Cognito, caches public keys for
6 hours, and verifies token signature, expiration, issuer, and token_use.
"""

import json
import logging
import time
from typing import Any

import jwt
import requests
from jwt.algorithms import RSAAlgorithm

logger = logging.getLogger()

# ---------------------------------------------------------------------------
# Module-level JWKS cache (persists across invocations within a container)
# ---------------------------------------------------------------------------
_jwks_cache: dict[str, Any] = {}
_jwks_cache_timestamp: float = 0.0
JWKS_CACHE_TTL: int = 21_600  # 6 hours in seconds


class JWTValidator:
    """Validates Cognito-issued JWT access tokens using RS256."""

    def __init__(self, user_pool_id: str, region: str) -> None:
        self.user_pool_id = user_pool_id
        self.region = region
        self.issuer = (
            f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"
        )
        self.jwks_url = f"{self.issuer}/.well-known/jwks.json"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def validate_token(self, token: str) -> dict | None:
        """Validate a JWT token and return its decoded claims.

        Checks:
            1. Signature against Cognito JWKS public key (RS256).
            2. ``exp`` – token must not be expired.
            3. ``iss`` – must match the expected Cognito User Pool issuer.
            4. ``token_use`` – must be ``"access"``.

        Args:
            token: Raw JWT string (without the ``Bearer`` prefix).

        Returns:
            Decoded claims ``dict`` on success, ``None`` on any failure.
        """
        try:
            # Decode header to retrieve the key-id (kid)
            unverified_header = jwt.get_unverified_header(token)
            kid: str | None = unverified_header.get("kid")
            if not kid:
                logger.warning("Token header missing 'kid'")
                return None

            # Look up the matching public key
            public_key = self._get_public_key(kid)
            if not public_key:
                logger.warning("No matching public key for kid=%s", kid)
                return None

            # Decode + verify
            claims: dict = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                issuer=self.issuer,
                options={
                    "verify_exp": True,
                    "verify_iss": True,
                    # Cognito access tokens do NOT contain an ``aud`` claim
                    "verify_aud": False,
                },
            )

            # Ensure the token is an access token
            if claims.get("token_use") != "access":
                logger.warning(
                    "Unexpected token_use=%s (expected 'access')",
                    claims.get("token_use"),
                )
                return None

            return claims

        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return None
        except jwt.InvalidIssuerError:
            logger.warning("Token issuer mismatch")
            return None
        except jwt.InvalidTokenError as exc:
            logger.warning("Invalid token: %s", exc)
            return None
        except Exception as exc:
            logger.error(
                json.dumps({"message": "Token validation error", "error": str(exc)})
            )
            return None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------
    def _get_public_key(self, kid: str) -> Any:
        """Return the public key for the given *kid*, refreshing the cache
        once if the key is not found (handles key rotation)."""
        keys = self._get_jwks()
        public_key = keys.get(kid)

        if public_key is None:
            logger.info("kid=%s not in cache – forcing JWKS refresh", kid)
            self._invalidate_cache()
            keys = self._get_jwks()
            public_key = keys.get(kid)

        return public_key

    def _get_jwks(self) -> dict[str, Any]:
        """Fetch JWKS from Cognito and cache the resulting public keys.

        Returns the cached dict ``{kid: public_key}`` if still within the
        TTL window; otherwise fetches fresh keys from the well-known endpoint.
        """
        global _jwks_cache, _jwks_cache_timestamp  # noqa: PLW0603

        now = time.time()
        if _jwks_cache and (now - _jwks_cache_timestamp) < JWKS_CACHE_TTL:
            return _jwks_cache

        try:
            response = requests.get(self.jwks_url, timeout=5)
            response.raise_for_status()
            jwks = response.json()

            keys: dict[str, Any] = {}
            for key_data in jwks.get("keys", []):
                kid = key_data["kid"]
                public_key = RSAAlgorithm.from_jwk(json.dumps(key_data))
                keys[kid] = public_key

            _jwks_cache = keys
            _jwks_cache_timestamp = time.time()

            logger.info(
                json.dumps(
                    {"message": "JWKS keys fetched and cached", "key_count": len(keys)}
                )
            )
            return keys

        except Exception as exc:
            logger.error(
                json.dumps(
                    {
                        "message": "Failed to fetch JWKS",
                        "error": str(exc),
                        "url": self.jwks_url,
                    }
                )
            )
            # Fall back to stale cache when the endpoint is unreachable
            if _jwks_cache:
                logger.warning("Returning stale JWKS cache after fetch failure")
                return _jwks_cache
            raise

    @staticmethod
    def _invalidate_cache() -> None:
        """Force the next ``_get_jwks`` call to fetch fresh keys."""
        global _jwks_cache_timestamp  # noqa: PLW0603
        _jwks_cache_timestamp = 0.0
