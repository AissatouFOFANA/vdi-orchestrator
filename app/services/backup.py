"""Sauvegarde et restauration du /home utilisateur des VMs.

Ecriture atomique : chaque backup est d'abord écrit dans un fichier .tmp
puis renommé via os.replace(). En cas d'echec mid-transfert, le backup
précédent (et le .bak avant lui) restent intacts.
"""
import os
import logging
import asyncio
import time
from pathlib import Path
from typing import Optional

import paramiko

from ..config import settings

log = logging.getLogger("vdi-orchestrator")

# Si le nouveau backup est plus petit que ce ratio du précédent,
# on refuse de l'écraser (garde-fou contre un home corrompu/vidé).
MIN_RATIO_VS_PREVIOUS = 0.1
# Taille en dessous de laquelle on considère le tar suspect (octets).
MIN_REASONABLE_SIZE = 1024


def _backup_path(username: str, template_id: int) -> Path:
    """Chemin du fichier backup pour un user+template."""
    d = Path(settings.BACKUP_DIR) / username
    d.mkdir(parents=True, exist_ok=True)
    return d / f"template_{template_id}.tar.gz"


def _ssh_client(ip: str, vm_user: str, vm_password: str,
                retries: int = 1, delay: float = 5) -> paramiko.SSHClient:
    """Connexion SSH avec tentatives de retry (utile au boot de la VM)."""
    last_err = None
    for attempt in range(retries):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=ip, port=22,
                username=vm_user, password=vm_password,
                timeout=15, banner_timeout=15, auth_timeout=15,
            )
            return client
        except Exception as e:
            last_err = e
            if attempt < retries - 1:
                log.debug(f"SSH {ip} attempt {attempt+1}/{retries} failed: {e}, retry in {delay}s")
                time.sleep(delay)
            else:
                raise last_err


def has_backup(username: str, template_id: int) -> bool:
    return _backup_path(username, template_id).exists()


def backup_info(username: str, template_id: int) -> Optional[dict]:
    p = _backup_path(username, template_id)
    if not p.exists():
        return None
    stat = p.stat()
    return {
        "path": str(p),
        "size_bytes": stat.st_size,
        "size_mb": round(stat.st_size / (1024 * 1024), 2),
        "modified": stat.st_mtime,
    }


def _commit_backup(tmp: Path, dest: Path, username: str, template_id: int) -> Optional[dict]:
    """Promote tmp -> dest avec garde-fou taille et rotation .bak.

    Retourne backup_info si commit OK, None si rejeté/échec.
    """
    if not tmp.exists() or tmp.stat().st_size < MIN_REASONABLE_SIZE:
        log.warning(f"Backup tmp trop petit pour {username}/template_{template_id}, rejet")
        tmp.unlink(missing_ok=True)
        return None

    new_size = tmp.stat().st_size

    if dest.exists():
        prev_size = dest.stat().st_size
        if prev_size > 0 and new_size < prev_size * MIN_RATIO_VS_PREVIOUS:
            log.warning(
                f"Backup refusé pour {username}/template_{template_id}: "
                f"nouveau {new_size}o < 10% de l'ancien {prev_size}o "
                f"(probable corruption/home vidé). Ancien backup préservé."
            )
            tmp.unlink(missing_ok=True)
            return None

        # Rotation : ancien -> .bak (écrase le .bak précédent)
        bak = dest.with_suffix(dest.suffix + ".bak")
        try:
            os.replace(str(dest), str(bak))
        except OSError as e:
            log.warning(f"Rotation .bak échouée pour {dest}: {e}")

    # Promotion atomique du nouveau
    os.replace(str(tmp), str(dest))
    return backup_info(username, template_id)


async def backup_home(ip: str, username: str, template_id: int,
                       vm_user: str, vm_password: str) -> Optional[dict]:
    """Sauvegarde /home/{vm_user} depuis la VM vers le stockage local.

    Returns dict avec les infos du backup, ou None en cas d'echec.
    """
    dest = _backup_path(username, template_id)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    remote_tar = "/tmp/_vdi_home_backup.tar.gz"
    max_bytes = settings.BACKUP_MAX_SIZE_MB * 1024 * 1024

    def _do_backup():
        ssh = None
        try:
            ssh = _ssh_client(ip, vm_user, vm_password)

            # Vérifier la taille du home avant de tar
            stdin, stdout, stderr = ssh.exec_command(
                f"du -sb /home/{vm_user} 2>/dev/null | cut -f1"
            )
            size_str = stdout.read().decode().strip()
            if size_str and size_str.isdigit():
                home_size = int(size_str)
                if home_size > max_bytes:
                    log.warning(
                        f"Backup skip: /home/{vm_user} trop volumineux "
                        f"({home_size // (1024*1024)} Mo > {settings.BACKUP_MAX_SIZE_MB} Mo) "
                        f"pour {username}/template_{template_id}"
                    )
                    return None

            # Créer le tar.gz sur la VM (capture stderr pour vrais erreurs)
            stdin, stdout, stderr = ssh.exec_command(
                f"tar czf {remote_tar} -C /home {vm_user}"
            )
            exit_code = stdout.channel.recv_exit_status()
            if exit_code != 0:
                err = stderr.read().decode().strip()
                log.warning(f"Backup tar failed (exit {exit_code}): {err}")
                ssh.exec_command(f"rm -f {remote_tar}")
                return None

            # Vérifier la taille du tar
            stdin, stdout, stderr = ssh.exec_command(f"stat -c%s {remote_tar}")
            tar_size_str = stdout.read().decode().strip()
            if not tar_size_str.isdigit():
                log.warning(f"Backup: stat tar failed pour {username}")
                ssh.exec_command(f"rm -f {remote_tar}")
                return None
            tar_size = int(tar_size_str)
            if tar_size > max_bytes:
                log.warning(f"Backup tar trop volumineux ({tar_size} bytes), skip")
                ssh.exec_command(f"rm -f {remote_tar}")
                return None
            if tar_size < MIN_REASONABLE_SIZE:
                log.warning(f"Backup tar suspect ({tar_size} bytes), skip")
                ssh.exec_command(f"rm -f {remote_tar}")
                return None

            # Nettoyer un .tmp résiduel d'un transfert précédent
            tmp.unlink(missing_ok=True)

            # Télécharger via SFTP vers le .tmp (jamais directement sur dest)
            sftp = ssh.open_sftp()
            try:
                sftp.get(remote_tar, str(tmp))
            finally:
                sftp.close()

            # Nettoyage distant
            ssh.exec_command(f"rm -f {remote_tar}")

            # Vérifier que le tmp local correspond à la taille distante
            if not tmp.exists() or tmp.stat().st_size != tar_size:
                log.warning(
                    f"Backup transfert tronqué pour {username}/template_{template_id} "
                    f"(local={tmp.stat().st_size if tmp.exists() else 0} vs remote={tar_size})"
                )
                tmp.unlink(missing_ok=True)
                return None

            # Promotion atomique avec rotation .bak + garde-fou
            return _commit_backup(tmp, dest, username, template_id)

        except Exception as e:
            log.error(f"Backup /home/{vm_user} failed pour {username}: {e}")
            tmp.unlink(missing_ok=True)
            return None
        finally:
            if ssh:
                ssh.close()

    return await asyncio.to_thread(_do_backup)


async def restore_home(ip: str, username: str, template_id: int,
                        vm_user: str, vm_password: str) -> bool:
    """Restaure le backup du home sur la nouvelle VM.

    Returns True si la restauration a réussi, False sinon.
    Si le backup principal est corrompu, tente le .bak.
    """
    src = _backup_path(username, template_id)
    bak = src.with_suffix(src.suffix + ".bak")

    if not src.exists() and not bak.exists():
        return False

    remote_tar = "/tmp/_vdi_home_restore.tar.gz"

    def _try_restore(local_src: Path) -> bool:
        ssh = None
        try:
            ssh = _ssh_client(ip, vm_user, vm_password,
                              retries=6, delay=5)

            sftp = ssh.open_sftp()
            try:
                sftp.put(str(local_src), remote_tar)
            finally:
                sftp.close()

            # Tester l'intégrité avant extraction
            stdin, stdout, stderr = ssh.exec_command(
                f"gzip -t {remote_tar} && tar tzf {remote_tar} > /dev/null"
            )
            test_exit = stdout.channel.recv_exit_status()
            if test_exit != 0:
                err = stderr.read().decode().strip()
                log.warning(f"Restore: archive corrompue {local_src.name} pour {username}: {err}")
                ssh.exec_command(f"rm -f {remote_tar}")
                return False

            stdin, stdout, stderr = ssh.exec_command(
                f"tar xzf {remote_tar} -C /home"
            )
            exit_code = stdout.channel.recv_exit_status()
            if exit_code != 0:
                err = stderr.read().decode().strip()
                log.warning(f"Restore tar extract failed (exit {exit_code}): {err}")
                ssh.exec_command(f"rm -f {remote_tar}")
                return False

            stdin, stdout, stderr = ssh.exec_command(
                f"chown -R {vm_user}:{vm_user} /home/{vm_user} 2>/dev/null"
            )
            stdout.channel.recv_exit_status()

            ssh.exec_command(f"rm -f {remote_tar}")

            log.info(
                f"Restore OK ({local_src.name}): {username}/template_{template_id} "
                f"-> /home/{vm_user}"
            )
            return True

        except Exception as e:
            log.error(f"Restore /home/{vm_user} failed pour {username}: {e}")
            return False
        finally:
            if ssh:
                ssh.close()

    def _do_restore():
        if src.exists() and _try_restore(src):
            return True
        if bak.exists():
            log.warning(f"Fallback sur .bak pour {username}/template_{template_id}")
            return _try_restore(bak)
        return False

    return await asyncio.to_thread(_do_restore)


def delete_backup(username: str, template_id: int) -> bool:
    p = _backup_path(username, template_id)
    bak = p.with_suffix(p.suffix + ".bak")
    deleted = False
    if p.exists():
        p.unlink()
        deleted = True
    if bak.exists():
        bak.unlink()
        deleted = True
    if deleted:
        log.info(f"Backup supprimé: {username}/template_{template_id}")
    return deleted


def list_backups(username: Optional[str] = None) -> list[dict]:
    base = Path(settings.BACKUP_DIR)
    if not base.exists():
        return []
    results = []
    dirs = [base / username] if username else base.iterdir()
    for user_dir in dirs:
        if not user_dir.is_dir():
            continue
        for f in user_dir.glob("template_*.tar.gz"):
            try:
                tid = int(f.stem.replace("template_", ""))
            except ValueError:
                continue
            stat = f.stat()
            bak = f.with_suffix(f.suffix + ".bak")
            results.append({
                "username": user_dir.name,
                "template_id": tid,
                "size_bytes": stat.st_size,
                "size_mb": round(stat.st_size / (1024 * 1024), 2),
                "modified": stat.st_mtime,
                "has_backup_copy": bak.exists(),
            })
    return results
