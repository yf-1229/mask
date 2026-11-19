"""Shell entrance tests: `mask` CLI (pure render + gateway-backed status)."""

from fastapi.testclient import TestClient

from mask.cli import main as cli_main, render_check, render_status
from tests.conftest import make_session_with_dict


def test_render_status_panel_lights(tmp_path):
    snapshot = {
        "status": "ok",
        "uptime_seconds": 42.0,
        "posture": {
            "leak_gate": "block",
            "leak_gate_active": True,
            "session_scope": "global",
            "ner": True,
            "dictionary_terms": 3,
            "mapping_records": 7,
            "gateway_token": True,
        },
        "counts": {
            "requests_total": 12,
            "entities_masked": 34,
            "tokens_restored": 30,
            "leak_blocks": 1,
            "paths_denied": 2,
            "auth_denied": 0,
            "tokens_unresolved": 0,
        },
    }
    text = render_status(snapshot, colorize=False)
    assert "leak gate" in text and "fail-closed" in text
    assert "global" in text and "7 records" in text
    assert "ja_ginza detection on" in text
    assert "required (both entrances)" in text
    assert "34" in text
    # no ANSI when colorize=False
    assert "\033[" not in text


def test_render_status_flags_warn_gate():
    text = render_status(
        {
            "posture": {"leak_gate": "warn", "leak_gate_active": False},
            "counts": {"tokens_unresolved": 0},
        },
        colorize=False,
    )
    assert "warn only" in text


def test_render_check_counts_entities(tmp_path):
    session = make_session_with_dict({"山田太郎": "person", "090-1234-5678": "phone"})
    masked, result = session.masked("山田太郎さんと090-1234-5678の件")
    text = render_check(masked, result, colorize=False)
    assert "2 entities" in text
    assert "人名 1" in text and "電話 1" in text
    assert "⟦token⟧" in text


def test_cli_check_reads_argument(tmp_path, capsys):
    # a dictionary so detection is deterministic without the NER model
    d = tmp_path / "dictionary.tsv"
    d.write_text("山田太郎\tperson\n", encoding="utf-8")
    cfg = tmp_path / "mask.toml"
    cfg.write_text(
        f'[mask]\nuse_ner = false\ndictionary = "{d}"\n', encoding="utf-8"
    )
    rc = cli_main(["check", "--config", str(cfg), "--no-color", "山田太郎さん"])
    out = capsys.readouterr()
    assert rc == 0
    assert "山田" not in out.out  # stdout carries the masked text only
    assert "⟦人名" in out.out
    assert "1 entities" in out.err


def test_cli_status_panel_from_gateway_snapshot(tmp_path):
    import httpx

    from mask.gateway import create_app
    from mask.gateway.config import GatewayConfig
    from tests.test_gateway import _fake_upstream

    config = GatewayConfig(
        upstream_base_url="https://upstream.test/v1",
        upstream_api_key="sk-real",
        use_ner=False,
        session_scope="global",
    )
    http = httpx.AsyncClient(
        base_url=config.upstream_base_url,
        transport=httpx.MockTransport(_fake_upstream),
        timeout=None,
    )
    app = create_app(config, client=http)
    with TestClient(app) as client:
        snapshot = client.get("/status").json()
    text = render_status(snapshot, colorize=False)
    assert "reliability indicators" in text
    assert "leak gate" in text
    assert "not set (localhost only)" in text
