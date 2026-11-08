"""Environment configuration for the control plane."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _load_dotenv() -> None:
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        os.environ.setdefault(key, val)


_load_dotenv()


@dataclass(frozen=True)
class Settings:
    provisioner: str
    runtime: str
    llm_mode: str
    vultr_api_key: str | None
    vultr_inference_api_key: str | None
    vultr_inference_model: str | None
    vultr_inference_base_url: str
    ollama_base_url: str
    ollama_model: str
    ollama_api_key: str
    codegen_model: str
    control_plane_url: str
    data_dir: Path
    scan_timeout_sec: int
    reaper_max_age_min: int
    scanner_pool_enabled: bool
    scanner_pool_size: int
    scanner_pool_token: str | None

    @property
    def db_path(self) -> Path:
        return self.data_dir / "toolpain.db"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"


def get_settings() -> Settings:
    env_name = os.environ.get("TOOLPAIN_ENV", "local").lower()
    if env_name in {"prod", "staging"} and not os.environ.get("TOOLPAIN_ADMIN_TOKEN"):
        raise RuntimeError("TOOLPAIN_ADMIN_TOKEN is required when TOOLPAIN_ENV is prod or staging")
    root = Path(__file__).resolve().parents[1]
    data = Path(os.environ.get("TOOLPAIN_DATA_DIR", str(root / "data")))
    # Production defaults to live Vultr Inference — never silently use fixtures.
    default_llm = "live" if env_name in {"prod", "staging"} else "fixture"
    default_prov = "vultr" if env_name in {"prod", "staging"} else "demo"
    llm_mode = os.environ.get("LLM_MODE", default_llm).lower()
    provisioner = os.environ.get("PROVISIONER", default_prov).lower()
    if env_name in {"prod", "staging"}:
        if llm_mode in {"fixture", "off"}:
            raise RuntimeError(
                f"TOOLPAIN_ENV={env_name} forbids LLM_MODE={llm_mode}; use live (Vultr Inference)"
            )
        if llm_mode == "live" and not (
            os.environ.get("VULTR_INFERENCE_API_KEY") or ""
        ).strip():
            raise RuntimeError(
                f"TOOLPAIN_ENV={env_name} with LLM_MODE=live requires VULTR_INFERENCE_API_KEY"
            )
        if provisioner == "demo":
            raise RuntimeError(
                f"TOOLPAIN_ENV={env_name} forbids PROVISIONER=demo; use vultr"
            )
    return Settings(
        provisioner=provisioner,
        runtime=os.environ.get("RUNTIME", "runc").lower(),
        llm_mode=llm_mode,
        vultr_api_key=os.environ.get("VULTR_API_KEY") or None,
        vultr_inference_api_key=os.environ.get("VULTR_INFERENCE_API_KEY") or None,
        vultr_inference_model=os.environ.get("VULTR_INFERENCE_MODEL") or None,
        vultr_inference_base_url=os.environ.get(
            "VULTR_INFERENCE_BASE_URL", "https://api.vultrinference.com/v1"
        ),
        # Local Ollama (/v1 chat completions). Offline laptop only — not production.
        ollama_base_url=os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434/v1"),
        ollama_model=os.environ.get("OLLAMA_MODEL", "llama3.2:latest"),
        ollama_api_key=os.environ.get("OLLAMA_API_KEY", "ollama"),
        codegen_model=(
            os.environ.get("CODEGEN_MODEL", "").strip()
            or os.environ.get("VULTR_INFERENCE_MODEL", "").strip()
            or "deepseek-v4.1-flash-1017"
        ),
        control_plane_url=os.environ.get("CONTROL_PLANE_URL", "http://127.0.0.1:8000"),
        data_dir=data,
        scan_timeout_sec=int(os.environ.get("SCAN_TIMEOUT_SEC", "1800")),
        reaper_max_age_min=int(os.environ.get("REAPER_MAX_AGE_MIN", "30")),
        scanner_pool_enabled=os.environ.get("SCANNER_POOL_ENABLED", "").strip().lower()
        in {"1", "true", "yes", "on"},
        scanner_pool_size=int(os.environ.get("SCANNER_POOL_SIZE", "2")),
        scanner_pool_token=os.environ.get("SCANNER_POOL_TOKEN") or None,
    )
