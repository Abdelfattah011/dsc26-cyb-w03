"""Password storage for Bayyina's local break-glass accounts. Rules: README.md, "What to build", part 3."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

CURRENT_N = 2**14
CURRENT_R = 8
CURRENT_P = 5
SALT_LEN = 16
DKLEN = 32
MAX_MEM = 64 * 1024 * 1024


def _urlsafe_b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _urlsafe_b64decode(data: str) -> bytes | None:
    try:
        padding = 4 - (len(data) % 4)
        if padding < 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data.encode("ascii"))
    except Exception:
        return None


def hash_password(password: str) -> str:
    """scrypt$<n>$<r>$<p>$<salt>$<hash> with n=2**14, r=8, p=5, a 16-byte random salt, dklen=32."""
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    
    normalized = password
    if not (8 <= len(normalized) <= 128):
        raise ValueError("Password length must be between 8 and 128 characters.")

    salt = os.urandom(SALT_LEN)
    derived = hashlib.scrypt(
        normalized.encode("utf-8"),
        salt=salt,
        n=CURRENT_N,
        r=CURRENT_R,
        p=CURRENT_P,
        dklen=DKLEN,
        maxmem=MAX_MEM
    )

    salt_b64 = _urlsafe_b64encode(salt)
    hash_b64 = _urlsafe_b64encode(derived)

    return f"scrypt${CURRENT_N}${CURRENT_R}${CURRENT_P}${salt_b64}${hash_b64}"


def verify_password(password: str, stored: str) -> bool:
    """True only if `password` matches `stored`. Never raises: anything malformed is False."""
    if not isinstance(password, str) or not isinstance(stored, str):
        return False

    try:
        parts = stored.split("$")
        if len(parts) != 6 or parts[0] != "scrypt":
            return False

        n = int(parts[1])
        r = int(parts[2])
        p = int(parts[3])
        salt_b64 = parts[4]
        hash_b64 = parts[5]

        # Validate bounds before calling scrypt to prevent DoS/memory exhaustion
        if not (n & (n - 1) == 0 and 2 <= n <= 2**20):
            return False
        if not (1 <= r <= 32):
            return False
        if not (1 <= p <= 16):
            return False

        salt = _urlsafe_b64decode(salt_b64)
        stored_hash = _urlsafe_b64decode(hash_b64)

        if salt is None or len(salt) < 16 or stored_hash is None or len(stored_hash) != 32:
            return False

        normalized = password
        if not (8 <= len(normalized) <= 128):
            return False

        derived = hashlib.scrypt(
            normalized.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=DKLEN,
            maxmem=MAX_MEM
        )

        return hmac.compare_digest(derived, stored_hash)
    except Exception:
        return False


def needs_rehash(stored: str) -> bool:
    """True if `stored` cannot be parsed or any of n, r, p is below the current values."""
    if not isinstance(stored, str):
        return True

    try:
        parts = stored.split("$")
        if len(parts) != 6 or parts[0] != "scrypt":
            return True

        n = int(parts[1])
        r = int(parts[2])
        p = int(parts[3])

        if n < CURRENT_N or r < CURRENT_R or p < CURRENT_P:
            return True

        return False
    except Exception:
        return True
