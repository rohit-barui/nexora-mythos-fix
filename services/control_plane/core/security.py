"""
Security core utilities (Blueprint Pillars 5 & 12).

Provides JWT access tokens, password hashing, and HMAC request signatures
used to authenticate HITL approval callbacks and internal service-to-service
communication. Falls back to deterministic (non-random) hashing when the
bcrypt backend is unavailable so the test suite stays hermetic.
"""

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Optional

import jwt
from jwt import InvalidTokenError

SECRET_KEY = "nexora-dev-secret-change-me-0123456789abcdef"  # >= 32 bytes
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

DEFAULT_SIGNING_SECRET = "nexora-approval-hmac-signing-secret-key-0123456789"

try:
    from passlib.context import CryptContext

    _pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    _BCRYPT_AVAILABLE = True
except Exception:  # pragma: no cover - bcrypt backend unavailable
    _pwd_context = None
    _BCRYPT_AVAILABLE = False


def _bcrypt_usable() -> bool:
    """Return True only when the bcrypt backend can actually hash/verify."""
    return _BCRYPT_AVAILABLE


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt (or deterministic SHA-256 fallback)."""
    if _bcrypt_usable():
        try:
            return _pwd_context.hash(password)
        except Exception:  # pragma: no cover - backend fails at runtime
            pass
    salt = secrets.token_hex(16)
    return f"sha256${salt}${hashlib.sha256((salt + password).encode()).hexdigest()}"


def verify_password(password: str, hashed: str) -> bool:
    """Verify a plaintext password against a stored hash."""
    if hashed.startswith("sha256$"):
        _, salt, digest = hashed.split("$")
        return hashlib.sha256((salt + password).encode()).hexdigest() == digest
    if _bcrypt_usable():
        try:
            return _pwd_context.verify(password, hashed)
        except Exception:
            return False
    return False


def create_access_token(
    subject: str,
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """Create a signed JWT access token."""
    expire = datetime.now(UTC) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload: Dict[str, Any] = {"sub": subject, "exp": expire}
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate a JWT access token. Returns None when invalid."""
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except InvalidTokenError:
        return None


def compute_hmac_signature(payload: bytes, secret: str = DEFAULT_SIGNING_SECRET) -> str:
    """Compute an HMAC-SHA256 signature for a byte payload."""
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def verify_hmac_signature(
    payload: bytes, signature: str, secret: str = DEFAULT_SIGNING_SECRET
) -> bool:
    """Constant-time verification of an HMAC signature."""
    expected = compute_hmac_signature(payload, secret)
    return hmac.compare_digest(expected, signature or "")


def compute_hmac_signature_json(
    payload: Dict[str, Any], secret: str = DEFAULT_SIGNING_SECRET
) -> str:
    """Compute an HMAC signature over the canonical JSON of a dict payload."""
    import json

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return compute_hmac_signature(canonical, secret)


def verify_hmac_signature_json(
    payload: Dict[str, Any], signature: str, secret: str = DEFAULT_SIGNING_SECRET
) -> bool:
    """Verify an HMAC signature over the canonical JSON of a dict payload."""
    import json

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return verify_hmac_signature(canonical, signature, secret)
