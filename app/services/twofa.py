"""Gestion du 2FA par email (OTP).

- État persistant par utilisateur dans la table `vdi_user_2fa` (email + enabled).
- Génération / vérification des codes OTP. Le code n'est jamais stocké en clair :
  on conserve uniquement son HMAC (clé = SECRET_KEY) dans la session signée.
"""
import hmac
import hashlib
import logging
import re
import secrets

from ..config import settings
from ..database import db_cursor

log = logging.getLogger("vdi-orchestrator")

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ── État persistant ─────────────────────────────────────

def get_status(username: str) -> dict:
    """Retourne {enabled, email} pour un utilisateur (enabled=False si absent)."""
    with db_cursor(dict_rows=True) as (conn, cur):
        cur.execute(
            "SELECT email, enabled FROM vdi_user_2fa WHERE username = %s",
            (username,),
        )
        row = cur.fetchone()
    if not row:
        return {"enabled": False, "email": None}
    return {"enabled": bool(row["enabled"]), "email": row["email"]}


def is_enabled(username: str) -> bool:
    return get_status(username)["enabled"]


def enable(username: str, email: str):
    """Active (ou réactive) le 2FA avec l'email vérifié."""
    with db_cursor() as (conn, cur):
        cur.execute("""
            INSERT INTO vdi_user_2fa (username, email, enabled, updated_at)
            VALUES (%s, %s, true, CURRENT_TIMESTAMP)
            ON CONFLICT (username) DO UPDATE
                SET email = EXCLUDED.email, enabled = true, updated_at = CURRENT_TIMESTAMP
        """, (username, email))
    log.info(f"2FA activé pour {username}")


def disable(username: str):
    with db_cursor() as (conn, cur):
        cur.execute("""
            UPDATE vdi_user_2fa SET enabled = false, updated_at = CURRENT_TIMESTAMP
            WHERE username = %s
        """, (username,))
    log.info(f"2FA désactivé pour {username}")


# ── Codes OTP ───────────────────────────────────────────

def valid_email(email: str) -> bool:
    return bool(email and _EMAIL_RE.match(email.strip()))


def generate_code() -> str:
    """Code OTP à 6 chiffres."""
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_code(code: str) -> str:
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        code.strip().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_code(code: str, code_hash: str) -> bool:
    if not code or not code_hash:
        return False
    return hmac.compare_digest(hash_code(code), code_hash)


def mask_email(email: str) -> str:
    """Masque un email pour l'affichage : aissatou@gmail.com -> ai***@gmail.com."""
    if not email or "@" not in email:
        return "***"
    local, domain = email.rsplit("@", 1)
    if len(local) <= 2:
        masked = local[0] + "***"
    else:
        masked = local[:2] + "***"
    return f"{masked}@{domain}"
