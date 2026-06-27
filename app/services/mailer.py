"""Envoi d'emails via SMTP (Gmail) — utilisé pour les codes 2FA.

smtplib est bloquant : appeler ces fonctions via `asyncio.to_thread` depuis
les routes async.
"""
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from ..config import settings

log = logging.getLogger("vdi-orchestrator")


def _build_message(to_email: str, subject: str, html_body: str, text_body: str) -> MIMEMultipart:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM}>"
    msg["To"] = to_email
    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))
    return msg


def send_email(to_email: str, subject: str, html_body: str, text_body: str) -> bool:
    """Envoie un email. Retourne True si l'envoi a réussi."""
    if not settings.SMTP_CONFIGURED:
        log.error("SMTP non configuré (SMTP_USER/SMTP_PASSWORD manquants)")
        return False
    msg = _build_message(to_email, subject, html_body, text_body)
    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=20) as server:
            server.ehlo()
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_FROM, [to_email], msg.as_string())
        log.info(f"Email envoyé à {to_email} ({subject})")
        return True
    except Exception as e:
        log.error(f"Échec envoi email à {to_email}: {e}")
        return False


def send_otp(to_email: str, code: str, ttl_seconds: int) -> bool:
    """Envoie un code de vérification 2FA."""
    minutes = max(1, ttl_seconds // 60)
    subject = "Votre code de vérification VDI Orchestrator"
    text_body = (
        f"Votre code de vérification est : {code}\n\n"
        f"Ce code est valable {minutes} minute(s). "
        "Si vous n'êtes pas à l'origine de cette demande, ignorez cet email."
    )
    html_body = f"""\
<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;color:#1e293b">
  <h2 style="color:#3b82f6;margin-bottom:8px">VDI Orchestrator</h2>
  <p>Voici votre code de vérification :</p>
  <div style="font-size:32px;font-weight:700;letter-spacing:8px;background:#f1f5f9;
              padding:18px;text-align:center;border-radius:10px;margin:16px 0">{code}</div>
  <p style="color:#64748b;font-size:13px">
    Ce code est valable {minutes} minute(s).<br>
    Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.
  </p>
</div>"""
    return send_email(to_email, subject, html_body, text_body)
