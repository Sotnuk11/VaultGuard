"""Dead man's switch watcher.

Runs as a separate process. If the admin has not sent a heartbeat (POST /api/iamhere)
for TIMEOUT_MINUTES, it emails the vault ciphertext to a trusted recipient.
The payload is encrypted with the recipient's RSA public key (hybrid RSA-OAEP + AES-GCM),
so only the holder of the matching private key can read it. All secrets come from the environment.
"""
import os
import smtplib
import time
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText

from dotenv import load_dotenv
from sqlalchemy import create_engine, text

import security

load_dotenv()

DATABASE_URL = security.require_env("DATABASE_URL")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = security.require_env("SMTP_USER")
SMTP_PASSWORD = security.require_env("SMTP_PASSWORD")  # use an app password, never the account password
RECIPIENT_EMAIL = security.require_env("RECIPIENT_EMAIL")
RECIPIENT_PUBLIC_KEY_PATH = security.require_env("RECIPIENT_PUBLIC_KEY_PATH")
TIMEOUT_MINUTES = int(os.getenv("TIMEOUT_MINUTES", "1440"))  # default: 24 hours
POLL_SECONDS = int(os.getenv("POLL_SECONDS", "60"))

engine = create_engine(DATABASE_URL, pool_pre_ping=True)


def build_message(items) -> MIMEText:
    with open(RECIPIENT_PUBLIC_KEY_PATH, "rb") as f:
        public_key = f.read()
    lines = [
        f"The VaultGuard administrator has been inactive for more than {TIMEOUT_MINUTES} minutes.",
        "Each block below is encrypted for you. Decrypt it with your private key (security.unwrap_with_private_key).",
        "The vault data inside is still protected by the owner's master password.",
        "",
    ]
    for name, encrypted in items:
        lines += [f"Item: {name}", security.wrap_for_recipient(encrypted, public_key), "-" * 40]
    msg = MIMEText("\n".join(lines), "plain", "utf-8")
    msg["Subject"] = "VaultGuard: emergency protocol activated"
    msg["From"] = SMTP_USER
    msg["To"] = RECIPIENT_EMAIL
    return msg


def send(msg: MIMEText) -> None:
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)


def check_once() -> bool:
    """Returns True once the emergency email has been sent."""
    with engine.connect() as conn:
        row = conn.execute(text("SELECT last_active FROM users WHERE role = 'admin' ORDER BY last_active DESC LIMIT 1")).fetchone()
        if not row or not row[0]:
            return False
        idle = datetime.now(timezone.utc).replace(tzinfo=None) - row[0]
        if idle <= timedelta(minutes=TIMEOUT_MINUTES):
            print(f"[{datetime.now():%H:%M:%S}] Admin active, idle for {idle}")
            return False
        items = conn.execute(text("SELECT server_name, encrypted_data FROM vault_items")).fetchall()
        if not items:
            print("Vault is empty, nothing to send.")
            return False
        send(build_message(items))
        print("Emergency email sent. Stopping so it is not sent twice.")
        return True


if __name__ == "__main__":
    print("VaultGuard checker started.")
    while True:
        try:
            if check_once():
                break
        except Exception as exc:  # keep watching after transient DB/SMTP errors
            print(f"Check failed: {exc}")
        time.sleep(POLL_SECONDS)
