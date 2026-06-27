"""Configuration — variables d'environnement."""
import os
import secrets


class Settings:
    PROXMOX_HOST = os.getenv("PROXMOX_HOST", "192.168.80.10")
    PROXMOX_PORT = os.getenv("PROXMOX_PORT", "8006")
    PROXMOX_USER = os.getenv("PROXMOX_USER", "root@pam")
    PROXMOX_PASSWORD = os.getenv("PROXMOX_PASSWORD", "changeme")
    PROXMOX_NODE = os.getenv("PROXMOX_NODE", "proxmox")
    PROXMOX_VERIFY_SSL = False

    GUAC_DB_HOST = os.getenv("GUAC_DB_HOST", "guac-db")
    GUAC_DB_PORT = int(os.getenv("GUAC_DB_PORT", "5432"))
    GUAC_DB_NAME = os.getenv("GUAC_DB_NAME", "guacamole_db")
    GUAC_DB_USER = os.getenv("GUAC_DB_USER", "guacamole_user")
    GUAC_DB_PASSWORD = os.getenv("GUAC_DB_PASSWORD", "GuacDB_S3cur3_2025")
    GUAC_URL = os.getenv("GUAC_URL", "http://guacamole:8080/guacamole")

    CLONE_POOL_START_ID = int(os.getenv("CLONE_POOL_START_ID", "500"))
    CLONE_POOL_END_ID = int(os.getenv("CLONE_POOL_END_ID", "550"))
    CLONE_NAME_PREFIX = os.getenv("CLONE_NAME_PREFIX", "vdi-")
    POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "3"))
    POLL_TIMEOUT = int(os.getenv("POLL_TIMEOUT", "120"))

    MONITOR_INTERVAL = int(os.getenv("MONITOR_INTERVAL", "15"))
    UNUSED_TIMEOUT = int(os.getenv("UNUSED_TIMEOUT", "300"))
    MAX_CLONE_LIFETIME = int(os.getenv("MAX_CLONE_LIFETIME", "14400"))
    ORPHAN_SCAN_INTERVAL = int(os.getenv("ORPHAN_SCAN_INTERVAL", "120"))

    SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
    EXTRA_ADMINS = [u.strip() for u in os.getenv("EXTRA_ADMINS", "").split(",") if u.strip()]

    GUAC_JSON_SECRET = os.getenv("GUAC_JSON_SECRET", "")

    BACKUP_ENABLED = os.getenv("BACKUP_ENABLED", "true").lower() in ("true", "1", "yes")
    BACKUP_DIR = os.getenv("BACKUP_DIR", "/srv/backups")
    BACKUP_MAX_SIZE_MB = int(os.getenv("BACKUP_MAX_SIZE_MB", "500"))
    BACKUP_VM_USER = os.getenv("BACKUP_VM_USER", "etudiant")

    # ── 2FA par email (OTP) ──
    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    # Mot de passe d'application Gmail (les espaces sont ignorés).
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").replace(" ", "")
    SMTP_FROM = os.getenv("SMTP_FROM", "") or os.getenv("SMTP_USER", "")
    SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "VDI Orchestrator")
    TWOFA_CODE_TTL = int(os.getenv("TWOFA_CODE_TTL", "300"))
    TWOFA_MAX_ATTEMPTS = int(os.getenv("TWOFA_MAX_ATTEMPTS", "5"))

    @property
    def SMTP_CONFIGURED(self) -> bool:
        return bool(self.SMTP_HOST and self.SMTP_USER and self.SMTP_PASSWORD)


settings = Settings()
