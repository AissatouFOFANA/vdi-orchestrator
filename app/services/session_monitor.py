"""Tâche background : auto-destroy sur déconnexion, timeouts, orphelins."""
import asyncio
import logging
from datetime import datetime, timedelta

from ..config import settings
from ..database import db_cursor
from . import proxmox, guacamole, clone_manager

log = logging.getLogger("vdi-orchestrator")


def _now() -> datetime:
    return datetime.utcnow()


def _as_datetime(value) -> datetime:
    if value is None:
        return _now()
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))


async def _monitor_tick():
    clones = clone_manager.list_clones()
    now = _now()

    for clone in clones:
        vmid = clone["vmid"]
        status = clone["status"]
        created = _as_datetime(clone.get("created_at"))
        age = (now - created).total_seconds()

        if status != "ready":
            # Échec de provisioning bloqué : cleanup après 2x POLL_TIMEOUT
            if age > settings.POLL_TIMEOUT * 2 and status in ("error", "creating", "waiting_clone", "starting", "waiting_ip", "restoring_backup", "creating_connection"):
                log.warning(f"Clone {vmid} bloqué en {status} depuis {int(age)}s, destruction")
                try:
                    await clone_manager.destroy_clone(vmid, reason="error", do_backup=False)
                except Exception as e:
                    log.error(f"Cleanup stuck clone {vmid} failed: {e}")
            continue

        conn_id = clone.get("guac_connection_id")
        if not conn_id:
            continue

        try:
            state = guacamole.session_state(
                conn_id,
                username=clone.get("username"),
                clone_created_at=clone.get("created_at"),
            )
        except Exception as e:
            log.warning(f"session_state({conn_id}) failed: {e}")
            continue

        log.debug(f"Clone {vmid} (user={clone.get('username')}): session_state={state}")

        is_persistent = clone.get("persistent", False)

        if state["active"]:
            with db_cursor() as (conn, cur):
                cur.execute("""
                    UPDATE vdi_clone
                    SET last_activity = CURRENT_TIMESTAMP,
                        connected_at = COALESCE(connected_at, CURRENT_TIMESTAMP)
                    WHERE vmid = %s
                """, (vmid,))
        else:
            if state["has_history"]:
                if is_persistent:
                    log.debug(f"Clone {vmid}: session terminée mais persistant, conservation")
                else:
                    log.info(f"Clone {vmid}: session Guac terminée, destruction auto")
                    try:
                        await clone_manager.destroy_clone(vmid, reason="auto_disconnect")
                    except Exception as e:
                        log.error(f"Auto destroy {vmid} failed: {e}")
                    continue

            if not is_persistent and age > settings.UNUSED_TIMEOUT:
                log.warning(f"Clone {vmid}: jamais utilisé après {int(age)}s, destruction")
                try:
                    await clone_manager.destroy_clone(vmid, reason="unused_timeout", do_backup=False)
                except Exception as e:
                    log.error(f"Unused timeout destroy {vmid} failed: {e}")
                continue

        if age > settings.MAX_CLONE_LIFETIME:
            log.warning(f"Clone {vmid}: durée de vie max atteinte ({int(age)}s)")
            # Si la session est encore active à l'instant du timeout, on ne backup pas :
            # snapshot incohérent risquerait d'écraser un backup propre. L'auto-disconnect
            # normal aura déjà fait un backup sain au précédent disconnect.
            do_backup = not state["active"]
            try:
                await clone_manager.destroy_clone(vmid, reason="timeout", do_backup=do_backup)
            except Exception as e:
                log.error(f"Max lifetime destroy {vmid} failed: {e}")


async def _orphan_sweep():
    try:
        vms = await proxmox.list_vms()
    except Exception as e:
        log.warning(f"Orphan sweep: list_vms failed: {e}")
        return

    with db_cursor() as (conn, cur):
        cur.execute("SELECT vmid FROM vdi_clone")
        tracked = {r[0] for r in cur.fetchall()}

    for vm in vms:
        vmid = vm.get("vmid")
        name = vm.get("name", "")
        if (name.startswith(settings.CLONE_NAME_PREFIX)
                and vm.get("template", 0) == 0
                and vmid not in tracked
                and settings.CLONE_POOL_START_ID <= vmid < settings.CLONE_POOL_END_ID):
            log.warning(f"Clone orphelin {vmid} ({name}), destruction")
            try:
                await proxmox.destroy_vm(vmid)
            except Exception as e:
                log.error(f"Destroy orphan {vmid} failed: {e}")


async def run():
    last_orphan = 0.0
    while True:
        try:
            await _monitor_tick()
        except Exception as e:
            log.error(f"Monitor tick error: {e}")

        now = asyncio.get_event_loop().time()
        if now - last_orphan > settings.ORPHAN_SCAN_INTERVAL:
            try:
                await _orphan_sweep()
            except Exception as e:
                log.error(f"Orphan sweep error: {e}")
            last_orphan = now

        await asyncio.sleep(settings.MONITOR_INTERVAL)
