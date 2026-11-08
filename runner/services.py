"""Allowlisted sidecar services declared by codegen (Postgres, Redis, …).

The harness starts these on the scan network before MCP initialize. Free-form
``docker run`` from setup_sh stays forbidden — services are structured JSON.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field, field_validator

# Image prefixes the harness may pull/run. Keep tight; expand deliberately.
_ALLOWED_IMAGE_PREFIXES = (
    "postgres:",
    "pgvector/pgvector:",
    "redis:",
    "mysql:",
    "mariadb:",
    "mongo:",
    "elasticsearch:",
    "docker.elastic.co/elasticsearch/elasticsearch:",
    "rabbitmq:",
    "memcached:",
)

_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ENV_VAL_RE = re.compile(r"^[A-Za-z0-9_./:@+=%-]{0,200}$")


class ServiceSpec(BaseModel):
    """One dependency container the MCP server needs before it can speak."""

    name: str
    image: str
    env: dict[str, str] = Field(default_factory=dict)
    port: int = 5432
    ready_timeout_sec: int = 90

    @field_validator("name")
    @classmethod
    def _name_ok(cls, value: str) -> str:
        name = (value or "").strip().lower()
        if not _NAME_RE.match(name):
            raise ValueError(f"invalid service name: {value!r}")
        if name in {"fixture", "fixture.local", "sinkhole", "localhost", "dns"}:
            raise ValueError(f"reserved service name: {name}")
        return name

    @field_validator("image")
    @classmethod
    def _image_ok(cls, value: str) -> str:
        image = (value or "").strip()
        if not image or len(image) > 180 or ".." in image or " " in image:
            raise ValueError(f"invalid service image: {value!r}")
        lower = image.lower()
        if not any(lower.startswith(p) for p in _ALLOWED_IMAGE_PREFIXES):
            raise ValueError(
                f"service image not allowlisted: {image!r} "
                f"(allowed prefixes: {', '.join(_ALLOWED_IMAGE_PREFIXES)})"
            )
        return image

    @field_validator("port")
    @classmethod
    def _port_ok(cls, value: int) -> int:
        if not 1 <= int(value) <= 65535:
            raise ValueError(f"invalid service port: {value}")
        return int(value)

    @field_validator("env")
    @classmethod
    def _env_ok(cls, value: dict[str, str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for key, raw in (value or {}).items():
            if not _ENV_KEY_RE.match(str(key)):
                raise ValueError(f"invalid service env key: {key!r}")
            val = str(raw)
            if not _ENV_VAL_RE.match(val):
                raise ValueError(f"invalid service env value for {key}")
            out[str(key)] = val
        if len(out) > 24:
            raise ValueError("too many service env vars")
        return out


class ServiceGuardError(ValueError):
    pass


def default_port_for_image(image: str) -> int:
    lower = image.lower()
    if lower.startswith("redis:") or lower.startswith("memcached:"):
        return 6379 if lower.startswith("redis:") else 11211
    if lower.startswith("mysql:") or lower.startswith("mariadb:"):
        return 3306
    if lower.startswith("mongo:"):
        return 27017
    if "elasticsearch" in lower:
        return 9200
    if lower.startswith("rabbitmq:"):
        return 5672
    return 5432


def validate_services(raw: Any) -> list[ServiceSpec]:
    """Parse/validate codegen ``services`` list. Empty is fine."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ServiceGuardError("services must be a JSON list")
    if len(raw) > 6:
        raise ServiceGuardError("at most 6 sidecar services")
    out: list[ServiceSpec] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise ServiceGuardError("each service must be an object")
        data = dict(item)
        if "port" not in data and data.get("image"):
            data["port"] = default_port_for_image(str(data["image"]))
        try:
            spec = ServiceSpec.model_validate(data)
        except Exception as exc:  # noqa: BLE001 — surface as guard error
            raise ServiceGuardError(str(exc)) from exc
        if spec.name in seen:
            raise ServiceGuardError(f"duplicate service name: {spec.name}")
        seen.add(spec.name)
        out.append(spec)
    return out


def services_hint_block() -> str:
    return (
        "  services: optional JSON list of sidecar dependency containers the MCP "
        "server needs BEFORE it can speak (Postgres, Redis, MySQL, Mongo, "
        "Elasticsearch, RabbitMQ, Memcached). Each item: "
        "{name, image, env, port}. "
        "name is the hostname launch_sh must use (e.g. postgres). "
        "image must be an allowlisted tag (postgres:16-alpine, redis:7-alpine, …). "
        "env is string→string only. "
        "NEVER point DB hosts at fixture.local — that is an HTTP probe helper only. "
        "Example: "
        '[{"name":"postgres","image":"postgres:16-alpine",'
        '"env":{"POSTGRES_PASSWORD":"toolpain","POSTGRES_USER":"toolpain",'
        '"POSTGRES_DB":"toolbox"},"port":5432}]. '
        "Then launch with exec env POSTGRES_HOST=postgres …\n"
    )
