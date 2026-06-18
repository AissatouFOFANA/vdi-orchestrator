"""Connexion PostgreSQL + bootstrap des tables VDI dans la DB Guacamole."""
import logging
from contextlib import contextmanager

import psycopg2
import psycopg2.extras

from .config import settings

log = logging.getLogger("vdi-orchestrator")


VDI_SCHEMA = """
CREATE TABLE IF NOT EXISTS vdi_template (
    id SERIAL PRIMARY KEY,
    template_vmid INTEGER NOT NULL,
    group_name VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    protocol VARCHAR(10) NOT NULL DEFAULT 'rdp',
    port INTEGER NOT NULL DEFAULT 3389,
    default_username VARCHAR(255),
    default_password VARCHAR(255),
    cores INTEGER NOT NULL DEFAULT 2,
    memory INTEGER NOT NULL DEFAULT 2048,
    cores_min INTEGER NOT NULL DEFAULT 1,
    cores_max INTEGER NOT NULL DEFAULT 8,
    memory_min INTEGER NOT NULL DEFAULT 1024,
    memory_max INTEGER NOT NULL DEFAULT 16384,
    max_clones INTEGER NOT NULL DEFAULT 5,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE vdi_template ADD COLUMN IF NOT EXISTS cores_min INTEGER NOT NULL DEFAULT 1;
ALTER TABLE vdi_template ADD COLUMN IF NOT EXISTS cores_max INTEGER NOT NULL DEFAULT 8;
ALTER TABLE vdi_template ADD COLUMN IF NOT EXISTS memory_min INTEGER NOT NULL DEFAULT 1024;
ALTER TABLE vdi_template ADD COLUMN IF NOT EXISTS memory_max INTEGER NOT NULL DEFAULT 16384;

CREATE TABLE IF NOT EXISTS vdi_template_group (
    id SERIAL PRIMARY KEY,
    template_id INTEGER REFERENCES vdi_template(id) ON DELETE CASCADE,
    guacamole_group_name VARCHAR(255) NOT NULL,
    UNIQUE(template_id, guacamole_group_name)
);

CREATE TABLE IF NOT EXISTS vdi_clone (
    id SERIAL PRIMARY KEY,
    vmid INTEGER NOT NULL UNIQUE,
    template_id INTEGER REFERENCES vdi_template(id),
    clone_name VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    guac_connection_id INTEGER,
    status VARCHAR(50) NOT NULL DEFAULT 'creating',
    cores INTEGER,
    memory INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    connected_at TIMESTAMP,
    last_activity TIMESTAMP
);

ALTER TABLE vdi_clone ADD COLUMN IF NOT EXISTS cores INTEGER;
ALTER TABLE vdi_clone ADD COLUMN IF NOT EXISTS memory INTEGER;
ALTER TABLE vdi_clone ADD COLUMN IF NOT EXISTS persistent BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS idx_vdi_clone_username ON vdi_clone(username);
CREATE INDEX IF NOT EXISTS idx_vdi_clone_status ON vdi_clone(status);

CREATE TABLE IF NOT EXISTS vdi_session_log (
    id SERIAL PRIMARY KEY,
    vmid INTEGER NOT NULL,
    template_id INTEGER,
    template_name VARCHAR(255),
    username VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    created_at TIMESTAMP NOT NULL,
    destroyed_at TIMESTAMP,
    duration_seconds INTEGER,
    destroy_reason VARCHAR(50)
);

CREATE INDEX IF NOT EXISTS idx_vdi_session_log_username ON vdi_session_log(username);
CREATE INDEX IF NOT EXISTS idx_vdi_session_log_created ON vdi_session_log(created_at);
"""


def get_db():
    return psycopg2.connect(
        host=settings.GUAC_DB_HOST,
        port=settings.GUAC_DB_PORT,
        dbname=settings.GUAC_DB_NAME,
        user=settings.GUAC_DB_USER,
        password=settings.GUAC_DB_PASSWORD,
    )


@contextmanager
def db_cursor(dict_rows: bool = False):
    conn = get_db()
    try:
        factory = psycopg2.extras.RealDictCursor if dict_rows else None
        cur = conn.cursor(cursor_factory=factory) if factory else conn.cursor()
        yield conn, cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_schema():
    with db_cursor() as (conn, cur):
        cur.execute(VDI_SCHEMA)
    log.info("VDI schema ready")


def seed_default_template():
    with db_cursor() as (conn, cur):
        cur.execute("SELECT COUNT(*) FROM vdi_template")
        count = cur.fetchone()[0]
        if count == 0:
            cur.execute("""
                INSERT INTO vdi_template
                    (template_vmid, group_name, display_name, protocol, port,
                     cores, memory, cores_min, cores_max, memory_min, memory_max, max_clones)
                VALUES (100, 'default', 'Desktop Linux Mint', 'rdp', 3389,
                        2, 2048, 1, 8, 1024, 16384, 5)
            """)
            log.info("Seeded default template (VMID 100)")
