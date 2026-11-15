"""Local pseudonymization gateway (OpenAI-compatible)."""

from __future__ import annotations

import argparse
import logging

import uvicorn

from mask.gateway.app import create_app
from mask.gateway.config import GatewayConfig


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="mask-server",
        description="PII pseudonymization gateway for OpenAI-compatible LLM APIs",
    )
    parser.add_argument(
        "--config", help="path to mask.toml (default: $MASK_CONFIG or ./mask.toml)"
    )
    parser.add_argument("--host", help="bind address (overrides config/env)")
    parser.add_argument("--port", type=int, help="port (overrides config/env)")
    parser.add_argument(
        "--log-level", default="info", help="debug/info/warning/error"
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=args.log_level.upper())
    config = GatewayConfig.load(args.config)
    if args.host:
        config.host = args.host
    if args.port:
        config.port = args.port

    uvicorn.run(create_app(config), host=config.host, port=config.port)


if __name__ == "__main__":
    main()
