"""Gateway configuration: mask.toml with environment overrides.

Precedence (lowest to highest):
    defaults < mask.toml < MASK_* environment variables < CLI flags
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CONFIG_NAME = "mask.toml"


@dataclass
class GatewayConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    upstream_base_url: str = "https://api.openai.com/v1"
    upstream_api_key: str = ""
    use_ner: bool = True
    dictionary_path: str | None = None
    # "global": one Session (and mapping table) for the whole process, so
    # pseudonyms stay stable across the turns of a conversation.
    # "request": a fresh Session per request; lighter table but the LLM
    # cannot rely on pseudonyms from earlier turns.
    session_scope: str = "global"

    def __post_init__(self) -> None:
        if self.session_scope not in ("global", "request"):
            raise ValueError(
                f"session.scope must be 'global' or 'request', got {self.session_scope!r}"
            )

    @classmethod
    def load(cls, path: str | Path | None = None) -> "GatewayConfig":
        """Load config from `path`, MASK_CONFIG, or ./mask.toml (if present)."""
        resolved = cls._resolve_path(path)
        data: dict = {}
        if resolved is not None:
            with open(resolved, "rb") as f:
                data = tomllib.load(f)
        server = data.get("server", {})
        upstream = data.get("upstream", {})
        mask = data.get("mask", {})
        session = data.get("session", {})

        cfg = cls(
            host=server.get("host", cls.host),
            port=int(server.get("port", cls.port)),
            upstream_base_url=upstream.get("base_url", cls.upstream_base_url),
            upstream_api_key=upstream.get("api_key", ""),
            use_ner=bool(mask.get("use_ner", True)),
            dictionary_path=mask.get("dictionary"),
            session_scope=session.get("scope", "global"),
        )

        if os.environ.get("MASK_SERVER_HOST"):
            cfg.host = os.environ["MASK_SERVER_HOST"]
        if os.environ.get("MASK_SERVER_PORT"):
            cfg.port = int(os.environ["MASK_SERVER_PORT"])
        if os.environ.get("MASK_UPSTREAM_BASE_URL"):
            cfg.upstream_base_url = os.environ["MASK_UPSTREAM_BASE_URL"]
        if os.environ.get("MASK_UPSTREAM_API_KEY"):
            cfg.upstream_api_key = os.environ["MASK_UPSTREAM_API_KEY"]
        return cfg

    @staticmethod
    def _resolve_path(path: str | Path | None) -> Path | None:
        if path is not None:
            p = Path(path)
            if not p.exists():
                raise FileNotFoundError(f"config file not found: {p}")
            return p
        env = os.environ.get("MASK_CONFIG")
        if env:
            p = Path(env)
            if not p.exists():
                raise FileNotFoundError(f"config file not found: {p}")
            return p
        cwd_default = Path(DEFAULT_CONFIG_NAME)
        return cwd_default if cwd_default.exists() else None
