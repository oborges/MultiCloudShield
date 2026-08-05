import json

from typer.testing import CliRunner

from multicloudshield.cli.app import app

runner = CliRunner()


def test_documented_local_demo_command_emits_json_and_partial_exit() -> None:
    result = runner.invoke(
        app,
        ["scan", "--local", "--provider", "demo", "--scope", "deterministic-v1"],
    )
    assert result.exit_code == 4
    payload = json.loads(result.stdout)
    assert payload["status"] == "partially_completed"
    assert payload["is_demo"] is True
    assert payload["assets"] and payload["findings"]


def test_cli_config_output_redacts_security_values(monkeypatch) -> None:
    monkeypatch.setenv("MCS_SECRET_KEY", "a-development-value-never-print")
    result = runner.invoke(app, ["config", "show"])
    assert result.exit_code == 0
    assert "a-development-value-never-print" not in result.stdout
    assert "**********" in result.stdout
