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
    openai_api_key: str | None
    openai_base_url: str
    openai_model: str
    control_plane_url: str
    data_dir: Path
    scan_timeout_sec: int
    reaper_max_age_min: int

    @property
    def db_path(self) -> Path:
        return self.data_dir / "toolpain.db"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"


def get_settings() -> Settings:
    root = Path(__file__).resolve().parents[1]
    data = Path(os.environ.get("TOOLPAIN_DATA_DIR", str(root / "data")))
    return Settings(
        provisioner=os.environ.get("PROVISIONER", "fake").lower(),
        runtime=os.environ.get("RUNTIME", "runc").lower(),
        llm_mode=os.environ.get("LLM_MODE", "fake").lower(),
        vultr_api_key=os.environ.get("VULTR_API_KEY") or None,
        vultr_inference_api_key=os.environ.get("VULTR_INFERENCE_API_KEY") or None,
        vultr_inference_model=os.environ.get("VULTR_INFERENCE_MODEL") or None,
        vultr_inference_base_url=os.environ.get(
            "VULTR_INFERENCE_BASE_URL", "https://api.vultrinference.com/v1"
        ),
        # Local Ollama (Cursor / on-machine). OpenAI-compatible /v1 endpoint.
        ollama_base_url=os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434/v1"),
        ollama_model=os.environ.get("OLLAMA_MODEL", "llama3.2:latest"),
        ollama_api_key=os.environ.get("OLLAMA_API_KEY", "ollama"),
        # OpenAI cloud (or any OpenAI-compatible gateway).
        openai_api_key=os.environ.get("OPENAI_API_KEY") or None,
        openai_base_url=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        openai_model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
        control_plane_url=os.environ.get("CONTROL_PLANE_URL", "http://127.0.0.1:8000"),
        data_dir=data,
        scan_timeout_sec=int(os.environ.get("SCAN_TIMEOUT_SEC", "1800")),
        reaper_max_age_min=int(os.environ.get("REAPER_MAX_AGE_MIN", "30")),
    )
