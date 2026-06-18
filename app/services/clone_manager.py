"""Cycle de vie des clones VDI."""
import asyncio
import logging
from datetime import datetime
from typing import Optional

from fastapi import HTTPException

from ..config import settings
from ..database import db_cursor
from . import proxmox, guacamole, backup

log = logging.getLogger("vdi-orchestrator")

# Verrou par (user, template_id) pour bloquer les doubles clics
_locks: dict[tuple[str, int], asyncio.Lock] = {}


def _lock_for(user: str, template_id: int) -> asyncio.Lock:
    key = (user, template_id)
    if key not in _locks:
        _locks[key] = asyncio.Lock()
    return _locks[key]


def fetch_template(template_id: int) -> Optional[dict]:
    with db_cursor(dict_rows=True) as (conn, cur):
        cur.execute("SELECT * FROM vdi_template WHERE id = %s", (template_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def fetch_clone_by_vmid(vmid: int) -> Optional[dict]:
    with db_cursor(dict_rows=True) as (conn, cur):
        cur.execute("""
            SELECT c.*, t.display_name AS template_name
            FROM vdi_clone c
            LEFT JOIN vdi_template t ON t.id = c.template_id
            WHERE c.vmid = %s
        """, (vmid,))
        row = cur.fetchone()
        return dict(row) if row else None


def list_clones(username: Optional[str] = None) -> list[dict]:
    with db_cursor(dict_rows=True) as (conn, cur):
        if username:
            cur.execute("""
                SELECT c.*, t.display_name AS template_name
                FROM vdi_clone c LEFT JOIN vdi_template t ON t.id = c.template_id
                WHERE c.username = %s ORDER BY c.created_at DESC
            """, (username,))
        else:
            cur.execute("""
                SELECT c.*, t.display_name AS template_name
                FROM vdi_clone c LEFT JOIN vdi_template t ON t.id = c.template_id
                ORDER BY c.created_at DESC
            """)
        return [dict(r) for r in cur.fetchall()]


def count_clones_for_template(template_id: int) -> int:
    with db_cursor() as (conn, cur):
        cur.execute("SELECT COUNT(*) FROM vdi_clone WHERE template_id = %s", (template_id,))
        return cur.fetchone()[0]


def existing_clone_for(username: str, template_id: int) -> Optional[dict]:
    with db_cursor(dict_rows=True) as (conn, cur):
        cur.execute("""
            SELECT * FROM vdi_clone
            WHERE username = %s AND template_id = %s
            LIMIT 1
        """, (username, template_id))
        row = cur.fetchone()
        return dict(row) if row else None


def _update_clone_status(vmid: int, status: str, **fields):
    sets = ["status = %s"]
    vals = [status]
    for k, v in fields.items():
        sets.append(f"{k} = %s")
        vals.append(v)
    vals.append(vmid)
    with db_cursor() as (conn, cur):
        cur.execute(f"UPDATE vdi_clone SET {', '.join(sets)} WHERE vmid = %s", vals)


def _insert_session_log(clone: dict, reason: str):
    with db_cursor() as (conn, cur):
        created = clone.get("created_at")
        duration = None
        if created:
            delta = datetime.utcnow() - (created if isinstance(created, datetime) else datetime.fromisoformat(str(created)))
            duration = int(delta.total_seconds())
        cur.execute("""
            INSERT INTO vdi_session_log
                (vmid, template_id, template_name, username, ip_address,
                 created_at, destroyed_at, duration_seconds, destroy_reason)
            VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP, %s, %s)
        """, (
            clone["vmid"], clone.get("template_id"), clone.get("template_name"),
            clone["username"], clone.get("ip_address"),
            clone["created_at"], duration, reason,
        ))


def _clamp_resources(template: dict, cores: Optional[int], memory: Optional[int]) -> tuple[int, int]:
    """Clamp les ressources demandées dans la plage admin du template."""
    c_min = template.get("cores_min") or 1
    c_max = template.get("cores_max") or template["cores"]
    m_min = template.get("memory_min") or 128
    m_max = template.get("memory_max") or template["memory"]

    c = cores if cores is not None else template["cores"]
    m = memory if memory is not None else template["memory"]

    c = max(c_min, min(c_max, int(c)))
    m = max(m_min, min(m_max, int(m)))
    return c, m


async def request_clone(username: str, template_id: int,
                        cores: Optional[int] = None,
                        memory: Optional[int] = None,
                        persistent: bool = False) -> dict:
    template = fetch_template(template_id)
    if not template or not template["enabled"]:
        raise HTTPException(404, "Template introuvable ou désactivé")

    async with _lock_for(username, template_id):
        existing = existing_clone_for(username, template_id)
        if existing and existing["status"] not in ("error",):
            clone = fetch_clone_by_vmid(existing["vmid"])
            if clone and clone.get("guac_connection_id"):
                clone["guac_url"] = guacamole.guac_client_url(clone["guac_connection_id"])
            return clone or existing

        current = count_clones_for_template(template_id)
        if current >= template["max_clones"]:
            raise HTTPException(409, f"Nombre maximum de clones atteint ({template['max_clones']})")

        chosen_cores, chosen_memory = _clamp_resources(template, cores, memory)

        # Réservation VMID : on insère la ligne vdi_clone avec un VMID libre.
        # L'UNIQUE constraint sur vmid sert de verrou DB.
        new_vmid = None
        for _ in range(5):
            with db_cursor() as (conn, cur):
                cur.execute("SELECT vmid FROM vdi_clone")
                used = {r[0] for r in cur.fetchall()}
            candidate = await proxmox.find_free_vmid(used_extra=used)
            clone_name = f"{settings.CLONE_NAME_PREFIX}{template['group_name']}-{candidate}"
            try:
                with db_cursor() as (conn, cur):
                    cur.execute("""
                        INSERT INTO vdi_clone
                            (vmid, template_id, clone_name, username, status, cores, memory, persistent)
                        VALUES (%s, %s, %s, %s, 'creating', %s, %s, %s)
                    """, (candidate, template_id, clone_name, username,
                          chosen_cores, chosen_memory, persistent))
                new_vmid = candidate
                break
            except Exception as e:
                log.warning(f"VMID {candidate} déjà réservé, retry: {e}")
                continue

        if new_vmid is None:
            raise HTTPException(503, "Impossible de réserver un VMID")

        clone_name = f"{settings.CLONE_NAME_PREFIX}{template['group_name']}-{new_vmid}"

        try:
            log.info(
                f"Creating clone {clone_name} (vmid={new_vmid}) for {username} "
                f"with {chosen_cores}vCPU / {chosen_memory}Mo"
            )
            await proxmox.create_linked_clone(
                template["template_vmid"], new_vmid, clone_name,
                cores=chosen_cores, memory=chosen_memory,
            )

            _update_clone_status(new_vmid, "waiting_clone")
            await proxmox.wait_for_clone_task(new_vmid)

            _update_clone_status(new_vmid, "starting")
            await proxmox.start_vm(new_vmid)

            _update_clone_status(new_vmid, "waiting_ip")
            ip = await proxmox.wait_for_vm_ip(new_vmid)

            # Restauration du home si un backup existe
            if settings.BACKUP_ENABLED and backup.has_backup(username, template_id):
                _update_clone_status(new_vmid, "restoring_backup", ip_address=ip)
                vm_user = template.get("default_username") or settings.BACKUP_VM_USER
                vm_pass = template.get("default_password") or ""
                try:
                    restored = await backup.restore_home(ip, username, template_id, vm_user, vm_pass)
                    if restored:
                        log.info(f"Backup restored for {username} on clone {new_vmid}")
                    else:
                        log.warning(f"Backup restore failed for {username} on clone {new_vmid}")
                except Exception as e:
                    log.warning(f"Backup restore error for {username}: {e}")

            _update_clone_status(new_vmid, "creating_connection", ip_address=ip)
            conn_id = guacamole.create_connection(
                name=clone_name,
                protocol=template["protocol"],
                hostname=ip,
                port=template["port"],
                username=template.get("default_username") or "",
                password=template.get("default_password") or "",
            )
            guacamole.grant_connection_permission(conn_id, username)

            _update_clone_status(new_vmid, "ready", guac_connection_id=conn_id)
            log.info(f"Clone {clone_name} ready at {ip} (guac_conn={conn_id})")

            clone = fetch_clone_by_vmid(new_vmid)
            if clone:
                clone["guac_url"] = guacamole.guac_client_url(conn_id)
            return clone

        except Exception as e:
            log.error(f"Clone creation failed for {clone_name}: {e}")
            clone = fetch_clone_by_vmid(new_vmid)
            try:
                await proxmox.destroy_vm(new_vmid)
            except Exception:
                pass
            if clone and clone.get("guac_connection_id"):
                guacamole.delete_connection(clone["guac_connection_id"])
            if clone:
                _insert_session_log(clone, "error")
            with db_cursor() as (conn, cur):
                cur.execute("DELETE FROM vdi_clone WHERE vmid = %s", (new_vmid,))
            raise HTTPException(500, f"Clone creation failed: {e}")


async def destroy_clone(vmid: int, reason: str = "manual",
                        do_backup: bool = True) -> dict:
    clone = fetch_clone_by_vmid(vmid)
    if not clone:
        raise HTTPException(404, "Clone introuvable")

    # Sauvegarde du home avant destruction
    if do_backup and settings.BACKUP_ENABLED and clone.get("ip_address") and clone["status"] == "ready":
        _update_clone_status(vmid, "backing_up")
        template = fetch_template(clone["template_id"]) if clone.get("template_id") else None
        vm_user = (template.get("default_username") if template else None) or settings.BACKUP_VM_USER
        vm_pass = (template.get("default_password") if template else None) or ""
        try:
            result = await backup.backup_home(
                clone["ip_address"], clone["username"],
                clone["template_id"], vm_user, vm_pass,
            )
            if result:
                log.info(f"Backup OK avant destruction clone {vmid}: {result['size_mb']} Mo")
            else:
                log.warning(f"Backup echoue pour clone {vmid}, destruction continue")
        except Exception as e:
            log.warning(f"Backup error clone {vmid}: {e}, destruction continue")

    _update_clone_status(vmid, "destroying")

    if clone.get("guac_connection_id"):
        guacamole.delete_connection(clone["guac_connection_id"])

    await proxmox.destroy_vm(vmid)

    _insert_session_log(clone, reason)

    with db_cursor() as (conn, cur):
        cur.execute("DELETE FROM vdi_clone WHERE vmid = %s", (vmid,))

    log.info(f"Clone {vmid} fully destroyed (reason={reason})")
    return {"status": "destroyed", "vmid": vmid}


async def destroy_all_clones(reason: str = "manual") -> list[dict]:
    results = []
    for clone in list_clones():
        try:
            await destroy_clone(clone["vmid"], reason)
            results.append({"vmid": clone["vmid"], "status": "destroyed"})
        except Exception as e:
            results.append({"vmid": clone["vmid"], "status": "error", "error": str(e)})
    return results
