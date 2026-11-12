"""Security helpers: password hashing, JWT tokens and vault encryption.

Vault format (base64 of): salt(16) | nonce(16) | tag(16) | ciphertext
The AES-256 key is derived from the user's master password with PBKDF2-HMAC-SHA256.
The master password is never stored; the server only sees it while handling a request.
"""
import base64
import os
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

PBKDF2_ITERATIONS = 600_000  # OWASP recommendation for PBKDF2-HMAC-SHA256
JWT_ALGORITHM = "HS256"
TOKEN_LIFETIME = timedelta(hours=8)


# ---------- passwords ----------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False


# ---------- JWT ----------
def create_token(secret: str, user_id: int, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": str(user_id), "role": role, "iat": now, "exp": now + TOKEN_LIFETIME}
    return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)


def decode_token(secret: str, token: str) -> dict:
    """Raises jwt.PyJWTError if the token is invalid or expired."""
    return jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])


# ---------- vault encryption ----------
def _derive_key(master_password: str, salt: bytes) -> bytes:
    return PBKDF2(
        master_password.encode("utf-8"), salt, dkLen=32,
        count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256,
    )


def encrypt_secret(secret: str, master_password: str) -> str:
    salt = get_random_bytes(16)
    cipher = AES.new(_derive_key(master_password, salt), AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(secret.encode("utf-8"))
    return base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode("ascii")


def decrypt_secret(payload: str, master_password: str) -> str:
    """Raises ValueError if the master password is wrong or the data was modified."""
    raw = base64.b64decode(payload)
    salt, nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:48], raw[48:]
    cipher = AES.new(_derive_key(master_password, salt), AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")


# ---------- dead man's switch: hybrid RSA + AES ----------
def wrap_for_recipient(data: str, public_key_pem: bytes) -> str:
    """Encrypt data for the holder of the private key (RSA-OAEP wraps a random AES key)."""
    session_key = get_random_bytes(32)
    cipher = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode("utf-8"))
    wrapped_key = PKCS1_OAEP.new(RSA.import_key(public_key_pem), hashAlgo=SHA256).encrypt(session_key)
    return base64.b64encode(wrapped_key + cipher.nonce + tag + ciphertext).decode("ascii")


def unwrap_with_private_key(payload: str, private_key_pem: bytes) -> str:
    key = RSA.import_key(private_key_pem)
    raw = base64.b64decode(payload)
    k = key.size_in_bytes()
    wrapped_key, nonce, tag, ciphertext = raw[:k], raw[k:k + 16], raw[k + 16:k + 32], raw[k + 32:]
    session_key = PKCS1_OAEP.new(key, hashAlgo=SHA256).decrypt(wrapped_key)
    return AES.new(session_key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ciphertext, tag).decode("utf-8")


def require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value
