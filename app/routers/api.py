"""API REST JSON."""
import asyncio
import logging
import time
from typing import Optional

from fastapi import APIRouter, Body, Request, HTTPException
from fastapi.responses import RedirectResponse

from ..config import settings
from ..database import db_cursor
from ..models import TemplateIn, CloneRequest, DestroyRequest
from ..services import proxmox, guacamole, clone_manager, backup, twofa, mailer
from .auth import current_user, require_user, require_admin

log = logging.getLogger("vdi-orchestrator")
router = APIRouter(prefix="/api")


# ── Health (public) ─────────────────────────────────────

@router.get("/health")
async def health():
    proxmox_ok = await proxmox.ping()
    db_ok = guacamole.ping()

    stats = {"active_clones": 0, "templates": 0}
    if db_ok:
        try:
            with db_cursor() as (conn, cur):
                cur.execute("SELECT COUNT(*) FROM vdi_clone")
                stats["active_clones"] = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM vdi_template WHERE enabled = true")
                stats["templates"] = cur.fetchone()[0]
        except Exception:
            pass

    return {
        "status": "ok" if (proxmox_ok and db_ok) else "degraded",
        "proxmox": proxmox_ok,
        "guacamole_db": db_ok,
        **stats,
    }


# ── Templates ───────────────────────────────────────────

def _template_row(row: dict, groups: list[str]) -> dict:
    r = dict(row)
    r["guacamole_groups"] = groups
    return r


@router.get("/templates")
async def api_list_templates(request: Request):
    user = require_user(request)
    with db_cursor(dict_rows=True) as (conn, cur):
        cur.execute("""
            SELECT t.*,
                   COALESCE(array_agg(tg.guacamole_group_name) FILTER (WHERE tg.guacamole_group_name IS NOT NULL), '{}') AS groups
            FROM vdi_template t
            LEFT JOIN vdi_template_group tg ON tg.template_id = t.id
            GROUP BY t.id
            ORDER BY t.display_name
        """)
        rows = [dict(r) for r in cur.fetchall()]
    if not user.get("is_admin"):
        user_groups = set(user["groups"])
        rows = [r for r in rows if not r["groups"] or set(r["groups"]) & user_groups]
    return rows


@router.post("/templates")
async def api_create_template(request: Request, payload: TemplateIn):
    require_admin(request)
    with db_cursor() as (conn, cur):
        cur.execute("""
            INSERT INTO vdi_template
                (template_vmid, group_name, display_name, protocol, port,
                 default_username, default_password, cores, memory,
                 cores_min, cores_max, memory_min, memory_max,
                 max_clones, enabled)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING id
        """, (
            payload.template_vmid, payload.group_name, payload.display_name,
            payload.protocol, payload.port, payload.default_username,
            payload.default_password, payload.cores, payload.memory,
            payload.cores_min, payload.cores_max,
            payload.memory_min, payload.memory_max,
            payload.max_clones, payload.enabled,
        ))
        tid = cur.fetchone()[0]
        for g in payload.guacamole_groups:
            cur.execute("""
                INSERT INTO vdi_template_group (template_id, guacamole_group_name)
                VALUES (%s, %s) ON CONFLICT DO NOTHING
            """, (tid, g))
    return {"id": tid}


@router.put("/templates/{template_id}")
async def api_update_template(template_id: int, request: Request, payload: TemplateIn):
    require_admin(request)
    with db_cursor() as (conn, cur):
        cur.execute("""
            UPDATE vdi_template SET
                template_vmid = %s, group_name = %s, display_name = %s,
                protocol = %s, port = %s, default_username = %s,
                default_password = %s, cores = %s, memory = %s,
                cores_min = %s, cores_max = %s,
                memory_min = %s, memory_max = %s,
                max_clones = %s, enabled = %s
            WHERE id = %s
        """, (
            payload.template_vmid, payload.group_name, payload.display_name,
            payload.protocol, payload.port, payload.default_username,
            payload.default_password, payload.cores, payload.memory,
            payload.cores_min, payload.cores_max,
            payload.memory_min, payload.memory_max,
            payload.max_clones, payload.enabled, template_id,
        ))
        cur.execute("DELETE FROM vdi_template_group WHERE template_id = %s", (template_id,))
        for g in payload.guacamole_groups:
            cur.execute("""
                INSERT INTO vdi_template_group (template_id, guacamole_group_name)
                VALUES (%s, %s) ON CONFLICT DO NOTHING
            """, (template_id, g))
    return {"id": template_id, "status": "updated"}


@router.delete("/templates/{template_id}")
async def api_delete_template(template_id: int, request: Request):
    require_admin(request)
    with db_cursor() as (conn, cur):
        cur.execute("DELETE FROM vdi_template WHERE id = %s", (template_id,))
    return {"status": "deleted"}


@router.get("/proxmox/templates")
async def api_proxmox_templates(request: Request):
    require_admin(request)
    vms = await proxmox.list_templates()
    return [
        {"vmid": vm["vmid"], "name": vm.get("name", "")}
        for vm in vms
    ]


# ── Clones ──────────────────────────────────────────────

@router.get("/clones")
async def api_list_clones(request: Request):
    user = require_user(request)
    username = None if user.get("is_admin") else user["username"]
    clones = clone_manager.list_clones(username=username)
    for c in clones:
        if c.get("guac_connection_id"):
            c["guac_url"] = guacamole.guac_client_url(c["guac_connection_id"])
    return clones


@router.post("/clone/request")
async def api_request_clone(request: Request, payload: CloneRequest):
    user = require_user(request)
    template_id = payload.template_id

    # Vérification d'accès groupe
    with db_cursor(dict_rows=True) as (conn, cur):
        cur.execute("""
            SELECT t.id, t.enabled,
                   COALESCE(array_agg(tg.guacamole_group_name) FILTER (WHERE tg.guacamole_group_name IS NOT NULL), '{}') AS groups
            FROM vdi_template t
            LEFT JOIN vdi_template_group tg ON tg.template_id = t.id
            WHERE t.id = %s GROUP BY t.id
        """, (template_id,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Template introuvable")
    if not row["enabled"]:
        raise HTTPException(403, "Template désactivé")

    allowed = list(row["groups"])
    if not user.get("is_admin") and allowed:
        if not (set(allowed) & set(user["groups"])):
            raise HTTPException(403, "Vous n'avez pas accès à ce template")

    # Seul un admin peut activer le mode persistant
    persistent = payload.persistent if user.get("is_admin") else False

    clone = await clone_manager.request_clone(
        user["username"], template_id,
        cores=payload.cores, memory=payload.memory,
        persistent=persistent,
    )
    return clone


@router.get("/clone/{vmid}/status")
async def api_clone_status(vmid: int, request: Request):
    user = require_user(request)
    clone = clone_manager.fetch_clone_by_vmid(vmid)
    if not clone:
        raise HTTPException(404, "Clone introuvable")
    if not user.get("is_admin") and clone["username"] != user["username"]:
        raise HTTPException(403, "Accès refusé")
    if clone.get("guac_connection_id"):
        clone["guac_url"] = guacamole.guac_client_url(clone["guac_connection_id"])
    return clone


@router.get("/clone/{vmid}/metrics")
async def api_clone_metrics(vmid: int, request: Request):
    """Métriques live d'un clone depuis Proxmox (CPU, RAM, disque, réseau, uptime)."""
    user = require_user(request)
    clone = clone_manager.fetch_clone_by_vmid(vmid)
    if not clone:
        raise HTTPException(404, "Clone introuvable")
    if not user.get("is_admin") and clone["username"] != user["username"]:
        raise HTTPException(403, "Accès refusé")
    if clone["status"] != "ready":
        return {"error": "Clone pas encore prêt", "status": clone["status"]}
    metrics = await proxmox.get_vm_metrics(vmid)
    if not metrics:
        raise HTTPException(502, "Impossible de récupérer les métriques Proxmox")
    metrics["vmid"] = vmid
    metrics["username"] = clone["username"]
    return metrics


@router.get("/connect/{vmid}")
async def api_connect(vmid: int, request: Request):
    """Génère un token auth-json et redirige vers Guacamole avec SSO."""
    user = require_user(request)
    clone = clone_manager.fetch_clone_by_vmid(vmid)
    if not clone:
        raise HTTPException(404, "Clone introuvable")
    if not user.get("is_admin") and clone["username"] != user["username"]:
        raise HTTPException(403, "Accès refusé")
    if clone["status"] != "ready" or not clone.get("guac_connection_id"):
        raise HTTPException(409, "Clone pas encore prêt")

    from ..config import settings
    if not settings.GUAC_JSON_SECRET:
        return RedirectResponse(guacamole.guac_client_url(clone["guac_connection_id"]))

    template = clone_manager.fetch_template(clone["template_id"])
    params = {
        "hostname": clone["ip_address"],
        "port": str(template["port"]),
        "ignore-cert": "true",
        "security": "any",
        "resize-method": "display-update",
    }
    if template.get("default_username"):
        params["username"] = template["default_username"]
    if template.get("default_password"):
        params["password"] = template["default_password"]

    try:
        url = guacamole.guac_sso_url(
            username=user["username"],
            connection_name=clone["clone_name"],
            protocol=template["protocol"],
            params=params,
        )
    except Exception as e:
        log.error(f"SSO token generation failed: {e}")
        url = guacamole.guac_client_url(clone["guac_connection_id"])
    return RedirectResponse(url)


@router.post("/clone/{vmid}/destroy")
async def api_destroy_clone(vmid: int, request: Request,
                            payload: Optional[DestroyRequest] = Body(None)):
    user = require_user(request)
    clone = clone_manager.fetch_clone_by_vmid(vmid)
    if not clone:
        raise HTTPException(404, "Clone introuvable")
    if not user.get("is_admin") and clone["username"] != user["username"]:
        raise HTTPException(403, "Accès refusé")
    do_backup = payload.backup if payload else True
    return await clone_manager.destroy_clone(vmid, reason="manual", do_backup=do_backup)


@router.post("/clones/destroy-all")
async def api_destroy_all(request: Request):
    require_admin(request)
    return await clone_manager.destroy_all_clones(reason="manual")


# ── Profil utilisateur ─────────────────────────────────

@router.post("/profile/password")
async def api_change_password(request: Request,
                              old_password: str = Body(..., embed=True),
                              new_password: str = Body(..., embed=True)):
    user = require_user(request)
    if len(new_password) < 4:
        raise HTTPException(400, "Le mot de passe doit contenir au moins 4 caractères")
    ok = guacamole.change_password(user["username"], old_password, new_password)
    if not ok:
        raise HTTPException(403, "Ancien mot de passe incorrect")
    return {"status": "ok"}


# ── 2FA par email (opt-in par utilisateur) ──────────────

@router.get("/profile/2fa")
async def api_2fa_status(request: Request):
    user = require_user(request)
    status = twofa.get_status(user["username"])
    return {
        "enabled": status["enabled"],
        "email": twofa.mask_email(status["email"]) if status["email"] else None,
        "smtp_configured": settings.SMTP_CONFIGURED,
    }


@router.post("/profile/2fa/setup")
async def api_2fa_setup(request: Request, email: str = Body(..., embed=True)):
    """Étape 1 : envoie un code de vérification à l'email fourni."""
    user = require_user(request)
    if not settings.SMTP_CONFIGURED:
        raise HTTPException(503, "Envoi d'email non configuré sur le serveur")
    email = email.strip()
    if not twofa.valid_email(email):
        raise HTTPException(400, "Adresse email invalide")

    code = twofa.generate_code()
    sent = await asyncio.to_thread(mailer.send_otp, email, code, settings.TWOFA_CODE_TTL)
    if not sent:
        raise HTTPException(502, "Impossible d'envoyer l'email de vérification")

    request.session["2fa_setup"] = {
        "email": email,
        "code_hash": twofa.hash_code(code),
        "exp": time.time() + settings.TWOFA_CODE_TTL,
        "attempts": 0,
    }
    return {"status": "sent", "email": twofa.mask_email(email)}


@router.post("/profile/2fa/confirm")
async def api_2fa_confirm(request: Request, code: str = Body(..., embed=True)):
    """Étape 2 : valide le code et active le 2FA."""
    user = require_user(request)
    setup = request.session.get("2fa_setup")
    if not setup:
        raise HTTPException(400, "Aucune vérification en cours")
    if time.time() > setup["exp"]:
        request.session.pop("2fa_setup", None)
        raise HTTPException(400, "Code expiré, recommencez")

    if not twofa.verify_code(code, setup["code_hash"]):
        setup["attempts"] += 1
        if setup["attempts"] >= settings.TWOFA_MAX_ATTEMPTS:
            request.session.pop("2fa_setup", None)
            raise HTTPException(403, "Trop de tentatives, recommencez")
        request.session["2fa_setup"] = setup
        raise HTTPException(400, "Code invalide")

    twofa.enable(user["username"], setup["email"])
    request.session.pop("2fa_setup", None)
    return {"status": "enabled", "email": twofa.mask_email(setup["email"])}


@router.post("/profile/2fa/disable")
async def api_2fa_disable(request: Request, password: str = Body(..., embed=True)):
    """Désactive le 2FA (confirmation par mot de passe)."""
    user = require_user(request)
    if not guacamole.authenticate_user(user["username"], password):
        raise HTTPException(403, "Mot de passe incorrect")
    twofa.disable(user["username"])
    request.session.pop("2fa_setup", None)
    return {"status": "disabled"}


# ── Sessions / stats (admin) ────────────────────────────

@router.get("/sessions/history")
async def api_history(request: Request, username: Optional[str] = None,
                       template_id: Optional[int] = None, limit: int = 200):
    require_admin(request)
    q = "SELECT * FROM vdi_session_log WHERE 1=1"
    args: list = []
    if username:
        q += " AND username = %s"
        args.append(username)
    if template_id:
        q += " AND template_id = %s"
        args.append(template_id)
    q += " ORDER BY created_at DESC LIMIT %s"
    args.append(limit)
    with db_cursor(dict_rows=True) as (conn, cur):
        cur.execute(q, args)
        return [dict(r) for r in cur.fetchall()]


@router.get("/sessions/stats")
async def api_stats(request: Request):
    require_admin(request)
    with db_cursor() as (conn, cur):
        cur.execute("SELECT COUNT(*) FROM vdi_session_log")
        total = cur.fetchone()[0]
        cur.execute("SELECT AVG(duration_seconds)::INT FROM vdi_session_log WHERE duration_seconds IS NOT NULL")
        avg = cur.fetchone()[0] or 0
        cur.execute("""
            SELECT template_name, COUNT(*) AS c
            FROM vdi_session_log WHERE template_name IS NOT NULL
            GROUP BY template_name ORDER BY c DESC LIMIT 5
        """)
        top = [{"template": r[0], "count": r[1]} for r in cur.fetchall()]
    return {"total_sessions": total, "avg_duration_seconds": avg, "top_templates": top}


# ── Backups ────────────────────────────────────────────

@router.get("/backups")
async def api_list_backups(request: Request, username: Optional[str] = None):
    user = require_user(request)
    if not user.get("is_admin"):
        username = user["username"]
    return backup.list_backups(username=username)


@router.get("/backups/{username}/{template_id}")
async def api_backup_info(username: str, template_id: int, request: Request):
    user = require_user(request)
    if not user.get("is_admin") and user["username"] != username:
        raise HTTPException(403, "Acces refuse")
    info = backup.backup_info(username, template_id)
    if not info:
        raise HTTPException(404, "Aucun backup trouve")
    return info


@router.delete("/backups/{username}/{template_id}")
async def api_delete_backup(username: str, template_id: int, request: Request):
    user = require_user(request)
    if not user.get("is_admin") and user["username"] != username:
        raise HTTPException(403, "Acces refuse")
    if backup.delete_backup(username, template_id):
        return {"status": "deleted"}
    raise HTTPException(404, "Aucun backup trouve")
