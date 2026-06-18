"""Schémas Pydantic."""
from typing import Optional
from pydantic import BaseModel, Field, model_validator


class TemplateIn(BaseModel):
    template_vmid: int
    group_name: str = Field(min_length=1, max_length=255)
    display_name: str = Field(min_length=1, max_length=255)
    protocol: str = "rdp"
    port: int = 3389
    default_username: Optional[str] = None
    default_password: Optional[str] = None
    cores: int = 2
    memory: int = 2048
    cores_min: int = 1
    cores_max: int = 8
    memory_min: int = 1024
    memory_max: int = 16384
    max_clones: int = 5
    enabled: bool = True
    guacamole_groups: list[str] = []

    @model_validator(mode="after")
    def _check_ranges(self):
        if self.cores_min < 1:
            raise ValueError("cores_min doit être >= 1")
        if self.cores_max < self.cores_min:
            raise ValueError("cores_max doit être >= cores_min")
        if self.memory_min < 128:
            raise ValueError("memory_min doit être >= 128 Mo")
        if self.memory_max < self.memory_min:
            raise ValueError("memory_max doit être >= memory_min")
        # Clamper le défaut dans la plage
        self.cores = max(self.cores_min, min(self.cores_max, self.cores))
        self.memory = max(self.memory_min, min(self.memory_max, self.memory))
        return self


class TemplateOut(TemplateIn):
    id: int


class CloneOut(BaseModel):
    id: int
    vmid: int
    template_id: Optional[int]
    clone_name: str
    username: str
    ip_address: Optional[str]
    guac_connection_id: Optional[int]
    status: str
    cores: Optional[int] = None
    memory: Optional[int] = None
    persistent: bool = False
    created_at: str
    connected_at: Optional[str]
    last_activity: Optional[str]
    template_name: Optional[str] = None
    guac_url: Optional[str] = None


class CloneRequest(BaseModel):
    template_id: int
    cores: Optional[int] = None
    memory: Optional[int] = None
    persistent: bool = False


class DestroyRequest(BaseModel):
    backup: bool = True
