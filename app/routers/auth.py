"""Authentification (login/logout + 2FA email) + helpers session."""
import asyncio
import logging
import time

from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from ..config import settings
from ..services import guacamole, twofa, mailer

log = logging.getLogger("vdi-orchestrator")
router = APIRouter()
templates = Jinja2Templates(directory="templates")


def current_user(request: Request) -> dict | None:
    user = request.session.get("user")
    if not user:
        return None
    return user


def require_user(request: Request) -> dict:
    user = current_user(request)
    if not user:
        raise HTTPException(401, "Non authentifié")
    return user


def require_admin(request: Request) -> dict:
    user = require_user(request)
    if not user.get("is_admin"):
        raise HTTPException(403, "Accès administrateur requis")
    return user


def _finalize_login(request: Request, user: dict) -> RedirectResponse:
    """Ouvre la session applicative et redirige selon le rôle."""
    request.session.pop("pending_2fa", None)
    request.session["user"] = user
    log.info(f"Login OK: {user['username']} (admin={user['is_admin']})")
    target = "/admin" if user["is_admin"] else "/"
    return RedirectResponse(target, status_code=303)


async def _send_otp_challenge(request: Request, user: dict, email: str) -> bool:
    """Génère un code, l'envoie par email et stocke le challenge en session."""
    code = twofa.generate_code()
    sent = await asyncio.to_thread(mailer.send_otp, email, code, settings.TWOFA_CODE_TTL)
    if not sent:
        return False
    request.session["pending_2fa"] = {
        "user": user,
        "code_hash": twofa.hash_code(code),
        "exp": time.time() + settings.TWOFA_CODE_TTL,
        "attempts": 0,
        "email_masked": twofa.mask_email(email),
    }
    return True


# ── Login ───────────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if current_user(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    ok = False
    try:
        ok = guacamole.authenticate_user(username, password)
    except Exception as e:
        log.error(f"Auth error: {e}")
    if not ok:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Identifiants invalides"},
            status_code=401,
        )

    user = {
        "username": username,
        "is_admin": guacamole.is_admin(username),
        "groups": guacamole.get_user_groups(username),
    }

    # 2FA activé pour cet utilisateur ?
    status = twofa.get_status(username)
    if status["enabled"] and status["email"]:
        if await _send_otp_challenge(request, user, status["email"]):
            return RedirectResponse("/login/verify", status_code=303)
        return templates.TemplateResponse(
            "login.html",
            {"request": request,
             "error": "Impossible d'envoyer le code de vérification. Réessayez plus tard."},
            status_code=500,
        )

    return _finalize_login(request, user)


# ── Vérification 2FA ────────────────────────────────────

@router.get("/login/verify", response_class=HTMLResponse)
async def verify_page(request: Request):
    pending = request.session.get("pending_2fa")
    if not pending:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        "verify.html",
        {"request": request, "error": None, "email_masked": pending["email_masked"]},
    )


@router.post("/login/verify", response_class=HTMLResponse)
async def verify_submit(request: Request, code: str = Form(...)):
    pending = request.session.get("pending_2fa")
    if not pending:
        return RedirectResponse("/login", status_code=303)

    if time.time() > pending["exp"]:
        request.session.pop("pending_2fa", None)
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Code expiré. Reconnectez-vous."},
            status_code=401,
        )

    if twofa.verify_code(code, pending["code_hash"]):
        return _finalize_login(request, pending["user"])

    pending["attempts"] += 1
    if pending["attempts"] >= settings.TWOFA_MAX_ATTEMPTS:
        request.session.pop("pending_2fa", None)
        return templates.TemplateResponse(
            "login.html",
            {"request": request,
             "error": "Trop de tentatives. Reconnectez-vous."},
            status_code=401,
        )
    request.session["pending_2fa"] = pending
    remaining = settings.TWOFA_MAX_ATTEMPTS - pending["attempts"]
    return templates.TemplateResponse(
        "verify.html",
        {"request": request,
         "error": f"Code invalide. {remaining} tentative(s) restante(s).",
         "email_masked": pending["email_masked"]},
        status_code=401,
    )


@router.post("/login/verify/resend", response_class=HTMLResponse)
async def verify_resend(request: Request):
    pending = request.session.get("pending_2fa")
    if not pending:
        return RedirectResponse("/login", status_code=303)
    user = pending["user"]
    status = twofa.get_status(user["username"])
    if not (status["enabled"] and status["email"]):
        request.session.pop("pending_2fa", None)
        return RedirectResponse("/login", status_code=303)

    sent = await _send_otp_challenge(request, user, status["email"])
    error = None if sent else "Impossible de renvoyer le code."
    return templates.TemplateResponse(
        "verify.html",
        {"request": request,
         "error": error,
         "info": "Un nouveau code a été envoyé." if sent else None,
         "email_masked": twofa.mask_email(status["email"])},
    )


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)
