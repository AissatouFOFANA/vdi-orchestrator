"""Accès direct à la DB Guacamole : auth, users, groupes, connexions, historique."""
import base64
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Optional

import httpx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from ..config import settings
from ..database import get_db

log = logging.getLogger("vdi-orchestrator")


def ping() -> bool:
    try:
        conn = get_db()
        conn.close()
        return True
    except Exception as e:
        log.warning(f"Guacamole DB ping failed: {e}")
        return False


def authenticate_user(username: str, password: str) -> bool:
    """Vérifie SHA256(password + UPPER(HEX(salt))) == password_hash."""
    if not username or not password:
        return False
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT u.password_hash, u.password_salt, u.disabled
            FROM guacamole_user u
            JOIN guacamole_entity e ON u.entity_id = e.entity_id
            WHERE e.name = %s AND e.type = 'USER'
        """, (username,))
        row = cur.fetchone()
        if not row:
            return False
        pwd_hash, salt, disabled = row
        if disabled:
            return False
        if pwd_hash is None or salt is None:
            return False
        salt_hex = bytes(salt).hex().upper()
        computed = hashlib.sha256((password + salt_hex).encode("utf-8")).digest()
        return computed == bytes(pwd_hash)
    finally:
        conn.close()


def get_user_groups(username: str) -> list[str]:
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT ge.name
            FROM guacamole_entity ue
            JOIN guacamole_user_group_member m ON m.member_entity_id = ue.entity_id
            JOIN guacamole_user_group ug ON ug.user_group_id = m.user_group_id
            JOIN guacamole_entity ge ON ge.entity_id = ug.entity_id
            WHERE ue.name = %s AND ue.type = 'USER'
        """, (username,))
        return [r[0] for r in cur.fetchall()]
    finally:
        conn.close()


def is_admin(username: str) -> bool:
    if username == "guacadmin":
        return True
    if username in settings.EXTRA_ADMINS:
        return True
    # Vérification supplémentaire : les permissions système ADMINISTER
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT 1 FROM guacamole_system_permission sp
            JOIN guacamole_entity e ON sp.entity_id = e.entity_id
            WHERE e.name = %s AND e.type = 'USER' AND sp.permission = 'ADMINISTER'
            LIMIT 1
        """, (username,))
        return cur.fetchone() is not None
    except Exception:
        return False
    finally:
        conn.close()


def _hash_password(password: str) -> tuple[bytes, bytes]:
    """Retourne (password_hash, salt) au format attendu par Guacamole."""
    salt = os.urandom(32)
    salt_hex = salt.hex().upper()
    pwd_hash = hashlib.sha256((password + salt_hex).encode("utf-8")).digest()
    return pwd_hash, salt


def change_password(username: str, old_password: str, new_password: str) -> bool:
    """Change le mot de passe d'un utilisateur Guacamole."""
    if not authenticate_user(username, old_password):
        return False
    conn = get_db()
    try:
        cur = conn.cursor()
        new_hash, new_salt = _hash_password(new_password)
        cur.execute("""
            UPDATE guacamole_user
            SET password_hash = %s, password_salt = %s
            WHERE entity_id = (
                SELECT entity_id FROM guacamole_entity
                WHERE name = %s AND type = 'USER'
            )
        """, (new_hash, new_salt, username))
        conn.commit()
        log.info(f"Password changed for user {username}")
        return True
    except Exception as e:
        conn.rollback()
        log.error(f"Password change failed for {username}: {e}")
        return False
    finally:
        conn.close()


def list_users() -> list[dict]:
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT e.name, u.disabled, u.full_name, u.email_address,
                   EXISTS(
                       SELECT 1 FROM guacamole_system_permission sp
                       WHERE sp.entity_id = e.entity_id AND sp.permission = 'ADMINISTER'
                   ) AS is_admin,
                   COALESCE(array_agg(ge.name) FILTER (WHERE ge.name IS NOT NULL), '{}')
            FROM guacamole_entity e
            JOIN guacamole_user u ON u.entity_id = e.entity_id
            LEFT JOIN guacamole_user_group_member m ON m.member_entity_id = e.entity_id
            LEFT JOIN guacamole_user_group ug ON ug.user_group_id = m.user_group_id
            LEFT JOIN guacamole_entity ge ON ge.entity_id = ug.entity_id
            WHERE e.type = 'USER'
            GROUP BY e.name, u.disabled, u.full_name, u.email_address, e.entity_id
            ORDER BY e.name
        """)
        return [
            {
                "username": r[0],
                "disabled": r[1],
                "full_name": r[2],
                "email": r[3],
                "is_admin": bool(r[4]) or r[0] == "guacadmin" or r[0] in settings.EXTRA_ADMINS,
                "groups": list(r[5]),
            }
            for r in cur.fetchall()
        ]
    finally:
        conn.close()


def user_exists(username: str) -> bool:
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT 1 FROM guacamole_entity WHERE name = %s AND type = 'USER'",
            (username,),
        )
        return cur.fetchone() is not None
    finally:
        conn.close()


# ── Gestion des utilisateurs (écriture) ─────────────────

def create_user(username: str, password: str, disabled: bool = False,
                full_name: Optional[str] = None, email: Optional[str] = None):
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT 1 FROM guacamole_entity WHERE name = %s AND type = 'USER'",
            (username,),
        )
        if cur.fetchone():
            raise ValueError("Utilisateur déjà existant")
        cur.execute(
            "INSERT INTO guacamole_entity (name, type) VALUES (%s, 'USER') RETURNING entity_id",
            (username,),
        )
        entity_id = cur.fetchone()[0]
        pwd_hash, salt = _hash_password(password)
        cur.execute("""
            INSERT INTO guacamole_user
                (entity_id, password_hash, password_salt, password_date,
                 disabled, full_name, email_address)
            VALUES (%s, %s, %s, CURRENT_TIMESTAMP, %s, %s, %s)
        """, (entity_id, pwd_hash, salt, disabled, full_name, email))
        conn.commit()
        log.info(f"User created: {username}")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def delete_user(username: str):
    conn = get_db()
    try:
        cur = conn.cursor()
        # La suppression de l'entité cascade vers user, permissions et memberships.
        cur.execute(
            "DELETE FROM guacamole_entity WHERE name = %s AND type = 'USER'",
            (username,),
        )
        conn.commit()
        log.info(f"User deleted: {username}")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def set_user_password(username: str, new_password: str):
    """Réinitialise le mot de passe (admin, sans ancien mot de passe)."""
    pwd_hash, salt = _hash_password(new_password)
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE guacamole_user
            SET password_hash = %s, password_salt = %s, password_date = CURRENT_TIMESTAMP
            WHERE entity_id = (
                SELECT entity_id FROM guacamole_entity
                WHERE name = %s AND type = 'USER'
            )
        """, (pwd_hash, salt, username))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def set_user_disabled(username: str, disabled: bool):
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE guacamole_user SET disabled = %s
            WHERE entity_id = (
                SELECT entity_id FROM guacamole_entity
                WHERE name = %s AND type = 'USER'
            )
        """, (disabled, username))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def set_user_profile(username: str, full_name: Optional[str], email: Optional[str]):
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE guacamole_user SET full_name = %s, email_address = %s
            WHERE entity_id = (
                SELECT entity_id FROM guacamole_entity
                WHERE name = %s AND type = 'USER'
            )
        """, (full_name, email, username))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def set_user_admin(username: str, is_admin: bool):
    """Accorde ou retire la permission système ADMINISTER."""
    conn = get_db()
    try:
        cur = conn.cursor()
        if is_admin:
            cur.execute("""
                INSERT INTO guacamole_system_permission (entity_id, permission)
                SELECT entity_id, 'ADMINISTER'
                FROM guacamole_entity WHERE name = %s AND type = 'USER'
                ON CONFLICT DO NOTHING
            """, (username,))
        else:
            cur.execute("""
                DELETE FROM guacamole_system_permission
                WHERE permission = 'ADMINISTER' AND entity_id = (
                    SELECT entity_id FROM guacamole_entity
                    WHERE name = %s AND type = 'USER'
                )
            """, (username,))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def set_user_groups(username: str, groups: list[str]):
    """Remplace l'appartenance aux groupes de l'utilisateur."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT entity_id FROM guacamole_entity WHERE name = %s AND type = 'USER'",
            (username,),
        )
        row = cur.fetchone()
        if not row:
            raise ValueError("Utilisateur introuvable")
        uid = row[0]
        cur.execute("DELETE FROM guacamole_user_group_member WHERE member_entity_id = %s", (uid,))
        for g in groups:
            cur.execute("""
                INSERT INTO guacamole_user_group_member (user_group_id, member_entity_id)
                SELECT ug.user_group_id, %s
                FROM guacamole_user_group ug
                JOIN guacamole_entity e ON e.entity_id = ug.entity_id
                WHERE e.name = %s AND e.type = 'USER_GROUP'
                ON CONFLICT DO NOTHING
            """, (uid, g))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Gestion des groupes ─────────────────────────────────

def create_group(name: str):
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT 1 FROM guacamole_entity WHERE name = %s AND type = 'USER_GROUP'",
            (name,),
        )
        if cur.fetchone():
            raise ValueError("Groupe déjà existant")
        cur.execute(
            "INSERT INTO guacamole_entity (name, type) VALUES (%s, 'USER_GROUP') RETURNING entity_id",
            (name,),
        )
        eid = cur.fetchone()[0]
        cur.execute("INSERT INTO guacamole_user_group (entity_id) VALUES (%s)", (eid,))
        conn.commit()
        log.info(f"Group created: {name}")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def delete_group(name: str):
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM guacamole_entity WHERE name = %s AND type = 'USER_GROUP'",
            (name,),
        )
        conn.commit()
        log.info(f"Group deleted: {name}")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def list_groups() -> list[str]:
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT e.name FROM guacamole_entity e
            JOIN guacamole_user_group ug ON ug.entity_id = e.entity_id
            WHERE e.type = 'USER_GROUP'
            ORDER BY e.name
        """)
        return [r[0] for r in cur.fetchall()]
    finally:
        conn.close()


def create_connection(name: str, protocol: str, hostname: str, port: int,
                      username: str = "", password: str = "") -> int:
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO guacamole_connection
                (connection_name, protocol, max_connections, max_connections_per_user)
            VALUES (%s, %s, 1, 1)
            RETURNING connection_id
        """, (name, protocol))
        cid = cur.fetchone()[0]

        params = {
            "hostname": hostname,
            "port": str(port),
            "ignore-cert": "true",
            "security": "any",
            "resize-method": "display-update",
        }
        if username:
            params["username"] = username
        if password:
            params["password"] = password
        for k, v in params.items():
            cur.execute("""
                INSERT INTO guacamole_connection_parameter
                    (connection_id, parameter_name, parameter_value)
                VALUES (%s, %s, %s)
            """, (cid, k, v))
        conn.commit()
        log.info(f"Guacamole connection {cid} created ({name})")
        return cid
    finally:
        conn.close()


def grant_connection_permission(connection_id: int, username: str):
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission)
            SELECT entity_id, %s, 'READ'
            FROM guacamole_entity WHERE name = %s AND type = 'USER'
            ON CONFLICT DO NOTHING
        """, (connection_id, username))
        conn.commit()
    finally:
        conn.close()


def delete_connection(connection_id: int):
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM guacamole_connection_parameter WHERE connection_id = %s", (connection_id,))
        cur.execute("DELETE FROM guacamole_connection_permission WHERE connection_id = %s", (connection_id,))
        cur.execute("DELETE FROM guacamole_connection WHERE connection_id = %s", (connection_id,))
        conn.commit()
        log.info(f"Guacamole connection {connection_id} deleted")
    except Exception as e:
        conn.rollback()
        log.warning(f"Delete connection {connection_id} failed: {e}")
    finally:
        conn.close()


def _dump_history_for_debug(connection_id: int, username: str = None):
    """Log les entrées d'historique pour debug (appelé seulement en DEBUG)."""
    if not log.isEnabledFor(logging.DEBUG):
        return
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT history_id, connection_id, username, start_date, end_date
            FROM guacamole_connection_history
            WHERE connection_id = %s OR username = %s
            ORDER BY start_date DESC LIMIT 5
        """, (connection_id, username))
        rows = cur.fetchall()
        for r in rows:
            log.debug(f"  history: id={r[0]} conn_id={r[1]} user={r[2]} start={r[3]} end={r[4]}")
        if not rows:
            log.debug(f"  Aucun historique pour conn_id={connection_id} ou user={username}")
    finally:
        conn.close()


def session_state(connection_id: int, username: str = None,
                   clone_created_at=None) -> dict:
    """Retourne {has_history, active, last_end}.

    Vérifie d'abord par connection_id (connexions DB classiques).
    Si aucun historique trouvé et qu'un username est fourni, vérifie aussi
    les sessions de l'utilisateur démarrées après la création du clone
    (couvre les connexions éphémères auth-json).
    """
    conn = get_db()
    try:
        cur = conn.cursor()
        # 1. Check par connection_id (connexion DB)
        cur.execute("""
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE end_date IS NULL) AS active,
                MAX(end_date) AS last_end
            FROM guacamole_connection_history
            WHERE connection_id = %s
        """, (connection_id,))
        total, active, last_end = cur.fetchone()

        if total > 0:
            return {
                "has_history": True,
                "active": active > 0,
                "last_end": last_end,
            }

        # 2. Fallback : check par username (connexions auth-json éphémères)
        if username:
            since = clone_created_at or "1970-01-01"
            cur.execute("""
                SELECT
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE end_date IS NULL) AS active,
                    MAX(end_date) AS last_end
                FROM guacamole_connection_history
                WHERE username = %s AND start_date >= %s
            """, (username, since))
            total2, active2, last_end2 = cur.fetchone()
            if total2 > 0:
                return {
                    "has_history": True,
                    "active": active2 > 0,
                    "last_end": last_end2,
                }

        _dump_history_for_debug(connection_id, username)
        return {
            "has_history": False,
            "active": False,
            "last_end": None,
        }
    finally:
        conn.close()


def guac_client_url(connection_id: int) -> str:
    """Deep link vers Guacamole pour cette connexion."""
    token = base64.b64encode(f"{connection_id}\0c\0postgresql".encode()).decode()
    return f"{settings.GUAC_URL}/#/client/{token}"


# ── guacamole-auth-json (SSO) ──────────────────────────

def _encrypt_auth_json(payload: dict) -> str:
    """Signe (HMAC-SHA256) puis chiffre (AES-128-CBC) pour guacamole-auth-json."""
    key = bytes.fromhex(settings.GUAC_JSON_SECRET)
    json_bytes = json.dumps(payload).encode("utf-8")
    # 1. HMAC-SHA256 du JSON
    signature = hmac.new(key, json_bytes, hashlib.sha256).digest()
    # 2. Concaténer signature (32 bytes) + JSON, puis chiffrer
    iv = b'\x00' * 16
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(signature + json_bytes, AES.block_size))
    return base64.b64encode(encrypted).decode()


def get_guac_auth_token(username: str, connection_name: str,
                        protocol: str, params: dict,
                        expires_in: int = 300) -> str:
    """Génère un blob auth-json chiffré, le POST à Guacamole, retourne l'authToken."""
    payload = {
        "username": username,
        "expires": str(int((time.time() + expires_in) * 1000)),
        "connections": {
            connection_name: {
                "protocol": protocol,
                "parameters": params,
            }
        },
    }
    blob = _encrypt_auth_json(payload)
    resp = httpx.post(
        f"{settings.GUAC_URL}/api/tokens",
        data={"data": blob},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["authToken"]


def guac_sso_url(username: str, connection_name: str,
                 protocol: str, params: dict) -> str:
    """Retourne une URL Guacamole avec authentification intégrée (auth-json)."""
    auth_token = get_guac_auth_token(username, connection_name, protocol, params)
    client_id = base64.b64encode(f"{connection_name}\0c\0json".encode()).decode()
    return f"{settings.GUAC_URL}/#/client/{client_id}?token={auth_token}"
