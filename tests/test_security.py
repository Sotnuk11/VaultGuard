import jwt
import pytest
from Crypto.PublicKey import RSA

import security


def test_password_hash_roundtrip():
    hashed = security.hash_password("correct horse battery")
    assert hashed != "correct horse battery"
    assert security.verify_password("correct horse battery", hashed)
    assert not security.verify_password("wrong", hashed)


def test_verify_password_rejects_garbage_hash():
    assert not security.verify_password("x", "not-a-bcrypt-hash")


def test_encrypt_decrypt_roundtrip():
    payload = security.encrypt_secret("Server_Password_999!", "master-password-1")
    assert "Server_Password" not in payload
    assert security.decrypt_secret(payload, "master-password-1") == "Server_Password_999!"


def test_wrong_master_password_fails():
    payload = security.encrypt_secret("secret", "master-password-1")
    with pytest.raises(ValueError):
        security.decrypt_secret(payload, "master-password-2")


def test_tampered_ciphertext_fails():
    payload = security.encrypt_secret("secret", "master-password-1")
    flipped = payload[:-4] + ("AAAA" if not payload.endswith("AAAA") else "BBBB")
    with pytest.raises(Exception):
        security.decrypt_secret(flipped, "master-password-1")


def test_same_secret_encrypts_differently():
    a = security.encrypt_secret("secret", "master-password-1")
    b = security.encrypt_secret("secret", "master-password-1")
    assert a != b  # random salt and nonce


def test_jwt_roundtrip_and_wrong_secret():
    secret = "s" * 40
    token = security.create_token(secret, 7, "admin")
    data = security.decode_token(secret, token)
    assert data["sub"] == "7" and data["role"] == "admin"
    with pytest.raises(jwt.PyJWTError):
        security.decode_token("x" * 40, token)


def test_hybrid_rsa_wrap_roundtrip():
    key = RSA.generate(2048)
    long_text = "x" * 500  # longer than a plain RSA-OAEP block allows
    wrapped = security.wrap_for_recipient(long_text, key.publickey().export_key())
    assert security.unwrap_with_private_key(wrapped, key.export_key()) == long_text
