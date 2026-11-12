"""Generate an RSA key pair for the dead man's switch recipient.

Give recipient_public.pem to the server (RECIPIENT_PUBLIC_KEY_PATH).
The recipient keeps recipient_private.pem offline. Never commit either file (*.pem is git-ignored).
"""
from pathlib import Path

from Crypto.PublicKey import RSA

OUT = Path("keys")
OUT.mkdir(exist_ok=True)
key = RSA.generate(3072)
(OUT / "recipient_private.pem").write_bytes(key.export_key())
(OUT / "recipient_public.pem").write_bytes(key.publickey().export_key())
print(f"Created {OUT / 'recipient_private.pem'} (keep secret) and {OUT / 'recipient_public.pem'}")
