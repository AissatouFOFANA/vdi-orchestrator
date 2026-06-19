"""Client API Proxmox VE."""
import time
import asyncio
import logging
from typing import Optional

import httpx
from fastapi import HTTPException

from ..config import settings

log = logging.getLogger("vdi-orchestrator")

_ticket: dict = {}


async def _auth() -> dict:
    global _ticket
    now = time.time()
    if _ticket.get("timestamp") and now - _ticket["timestamp"] < 7000:
        return _ticket
    url = f"https://{settings.PROXMOX_HOST}:{settings.PROXMOX_PORT}/api2/json/access/ticket"
    async with httpx.AsyncClient(verify=settings.PROXMOX_VERIFY_SSL, timeout=30) as client:
        resp = await client.post(url, data={
            "username": settings.PROXMOX_USER,
            "password": settings.PROXMOX_PASSWORD,
        })
        resp.raise_for_status()
        data = resp.json()["data"]
        _ticket = {
            "ticket": data["ticket"],
            "csrf": data["CSRFPreventionToken"],
            "timestamp": now,
        }
        log.info("Proxmox auth OK")
        return _ticket


async def api(method: str, path: str, data: Optional[dict] = None):
    auth = await _auth()
    url = f"https://{settings.PROXMOX_HOST}:{settings.PROXMOX_PORT}/api2/json{path}"
    headers = {"CSRFPreventionToken": auth["csrf"]}
    cookies = {"PVEAuthCookie": auth["ticket"]}
    async with httpx.AsyncClient(verify=settings.PROXMOX_VERIFY_SSL, timeout=60) as client:
        if method == "GET":
            resp = await client.get(url, headers=headers, cookies=cookies)
        elif method == "POST":
            resp = await client.post(url, headers=headers, cookies=cookies, data=data or {})
        elif method == "PUT":
            resp = await client.put(url, headers=headers, cookies=cookies, data=data or {})
        elif method == "DELETE":
            resp = await client.delete(url, headers=headers, cookies=cookies)
        else:
            raise ValueError(f"Unknown method: {method}")
        resp.raise_for_status()
        return resp.json().get("data", {})


async def ping() -> bool:
    try:
        await _auth()
        return True
    except Exception as e:
        log.warning(f"Proxmox ping failed: {e}")
        return False


async def list_vms() -> list[dict]:
    vms = await api("GET", f"/nodes/{settings.PROXMOX_NODE}/qemu")
    return vms or []


async def list_templates() -> list[dict]:
    vms = await list_vms()
    return [vm for vm in vms if vm.get("template") == 1]


async def find_free_vmid(used_extra: set[int] = None) -> int:
    used_extra = used_extra or set()
    vms = await list_vms()
    used = {vm["vmid"] for vm in vms} | used_extra
    for vmid in range(settings.CLONE_POOL_START_ID, settings.CLONE_POOL_END_ID):
        if vmid not in used:
            return vmid
    raise HTTPException(503, "No free VMID available in pool")


async def create_linked_clone(template_vmid: int, new_vmid: int, name: str,
                              cores: int = 2, memory: int = 2048):
    node = settings.PROXMOX_NODE
    result = await api("POST", f"/nodes/{node}/qemu/{template_vmid}/clone", {
        "newid": new_vmid, "name": name, "full": 0,
    })
    log.info(f"Clone task started: {result} (vmid={new_vmid} from template={template_vmid})")
    await api("PUT", f"/nodes/{node}/qemu/{new_vmid}/config", {
        "cores": cores, "memory": memory,
    })


async def start_vm(vmid: int):
    await api("POST", f"/nodes/{settings.PROXMOX_NODE}/qemu/{vmid}/status/start")
    log.info(f"VM {vmid} start requested")


async def stop_vm(vmid: int):
    try:
        await api("POST", f"/nodes/{settings.PROXMOX_NODE}/qemu/{vmid}/status/stop")
        log.info(f"VM {vmid} stop requested")
    except Exception as e:
        log.warning(f"Stop VM {vmid} failed: {e}")


async def destroy_vm(vmid: int):
    try:
        await stop_vm(vmid)
        await asyncio.sleep(5)
        await api("DELETE", f"/nodes/{settings.PROXMOX_NODE}/qemu/{vmid}")
        log.info(f"VM {vmid} destroyed")
    except Exception as e:
        log.warning(f"Destroy VM {vmid} failed: {e}")


async def get_vm_ip(vmid: int) -> Optional[str]:
    try:
        data = await api("GET", f"/nodes/{settings.PROXMOX_NODE}/qemu/{vmid}/agent/network-get-interfaces")
        if isinstance(data, dict):
            result = data.get("result", data)
            if isinstance(result, list):
                for iface in result:
                    if iface.get("name") in ("lo", "lo0"):
                        continue
                    for addr in iface.get("ip-addresses", []):
                        ip = addr.get("ip-address", "")
                        if ip and not ip.startswith("127.") and not ip.startswith("fe80"):
                            return ip
    except Exception:
        pass
    return None


async def wait_for_vm_ip(vmid: int) -> str:
    start = time.time()
    while time.time() - start < settings.POLL_TIMEOUT:
        ip = await get_vm_ip(vmid)
        if ip:
            log.info(f"VM {vmid} got IP: {ip}")
            return ip
        await asyncio.sleep(settings.POLL_INTERVAL)
    raise HTTPException(504, f"VM {vmid} did not get an IP within {settings.POLL_TIMEOUT}s")


async def get_vm_metrics(vmid: int) -> Optional[dict]:
    """Récupère les métriques live d'une VM depuis Proxmox."""
    try:
        data = await api("GET", f"/nodes/{settings.PROXMOX_NODE}/qemu/{vmid}/status/current")
        if not data:
            return None
        maxmem = data.get("maxmem", 1)
        mem = data.get("mem", 0)
        return {
            "cpu_pct": round(data.get("cpu", 0) * 100, 1),
            "cpus": data.get("cpus", 0),
            "mem_used_mb": round(mem / (1024 * 1024)),
            "mem_max_mb": round(maxmem / (1024 * 1024)),
            "mem_pct": round(mem / maxmem * 100, 1) if maxmem else 0,
            "disk_read_mb": round(data.get("diskread", 0) / (1024 * 1024), 1),
            "disk_write_mb": round(data.get("diskwrite", 0) / (1024 * 1024), 1),
            "net_in_mb": round(data.get("netin", 0) / (1024 * 1024), 1),
            "net_out_mb": round(data.get("netout", 0) / (1024 * 1024), 1),
            "uptime_seconds": data.get("uptime", 0),
            "status": data.get("status", "unknown"),
        }
    except Exception as e:
        log.warning(f"get_vm_metrics({vmid}) failed: {e}")
        return None


async def wait_for_clone_task(vmid: int):
    start = time.time()
    while time.time() - start < settings.POLL_TIMEOUT:
        try:
            status = await api("GET", f"/nodes/{settings.PROXMOX_NODE}/qemu/{vmid}/status/current")
            if status and status.get("status") in ("stopped", "running"):
                return
        except Exception:
            pass
        await asyncio.sleep(2)
    raise HTTPException(504, f"Clone {vmid} not ready within {settings.POLL_TIMEOUT}s")
