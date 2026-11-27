"""Password hashing, session tokens and encryption of stored target credentials."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from functools import lru_cache

from cryptography.fernet import Fernet

from .config import data_dir


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$")
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1)
    except ValueError:
        return False
    return hmac.compare_digest(actual.hex(), digest)


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@lru_cache(maxsize=4)
def _cipher(key_path: str) -> Fernet:
    if not os.path.exists(key_path):
        with open(key_path, "xb") as handle:
            handle.write(Fernet.generate_key())
    with open(key_path, "rb") as handle:
        return Fernet(handle.read())


def encrypt_json(value) -> str:
    cipher = _cipher(str(data_dir() / "secret.key"))
    return cipher.encrypt(json.dumps(value).encode()).decode()


def decrypt_json(token: str):
    cipher = _cipher(str(data_dir() / "secret.key"))
    return json.loads(cipher.decrypt(token.encode()))
