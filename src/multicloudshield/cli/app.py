from __future__ import annotations

import asyncio
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import typer

from multicloudshield import __version__
from multicloudshield.api.auth import PASSWORD_HASHER, create_api_token
from multicloudshield.config import Settings
from multicloudshield.core.enums import CloudProvider, CredentialMechanism, Severity
from multicloudshield.core.identity import local_uuid
from multicloudshield.core.models import ConnectionDescriptor, ScanResult
from multicloudshield.engine import ScanOptions, run_scan
from multicloudshield.engine.export import export_csv, export_json
from multicloudshield.persistence import Database, OrgScope, Repository
from multicloudshield.persistence.models import ApiTokenRow
from multicloudshield.policy import load_bundle

app = typer.Typer(no_args_is_help=True, help="Read-only multi-cloud security posture management.")
connection_app = typer.Typer(no_args_is_help=True)
scan_app = typer.Typer(invoke_without_command=True, no_args_is_help=False)
finding_app = typer.Typer(no_args_is_help=True)
policy_app = typer.Typer(no_args_is_help=True)
demo_app = typer.Typer(no_args_is_help=True)
config_app = typer.Typer(no_args_is_help=True)
token_app = typer.Typer(no_args_is_help=True)
app.add_typer(connection_app, name="connection")
app.add_typer(scan_app, name="scan")
app.add_typer(finding_app, name="findings")
app.add_typer(policy_app, name="policy")
app.add_typer(demo_app, name="demo")
app.add_typer(config_app, name="config")
app.add_typer(token_app, name="token")


def _server_url() -> str:
    value = os.getenv("MCS_SERVER_URL", "http://localhost:8080").rstrip("/")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
        raise typer.BadParameter("MCS_SERVER_URL must be an HTTP(S) URL without credentials")
    return value


def _remote(method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
    base = _server_url()
    token = os.getenv("MCS_API_TOKEN")
    if not token:
        raise typer.BadParameter("MCS_API_TOKEN is required for remote commands")
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(  # noqa: S310 -- validated HTTP(S) base
        base + "/api/v1" + path,
        method=method,
        data=data,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - fixed configured server base
            body = response.read()
            return json.loads(body) if body else None
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        typer.echo(detail, err=True)
        raise typer.Exit(3) from exc


def _write(value: Any, output: str, out: Path | None = None) -> None:
    if isinstance(value, ScanResult):
        text = export_csv(value) if output == "csv" else export_json(value)
    elif output == "json":
        text = json.dumps(value, default=str, sort_keys=True, indent=2)
    else:
        items = value.get("items", []) if isinstance(value, dict) else value
        text = "\n".join(
            "\t".join(f"{key}={val}" for key, val in item.items())
            if isinstance(item, dict)
            else str(item)
            for item in items
        )
    if out:
        out.write_text(text + ("" if text.endswith("\n") else "\n"), encoding="utf-8")
    else:
        typer.echo(text)


@app.command("version")
def version() -> None:
    typer.echo(__version__)


@config_app.command("show")
def config_show() -> None:
    settings = Settings(process_role="cli")
    payload = settings.model_dump(mode="json")
    payload["secret_key"] = "**********"
    payload["bootstrap_token"] = "**********" if settings.bootstrap_token else None
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@app.command("bootstrap")
def bootstrap(
    email: str = typer.Option(...),
    password: str | None = typer.Option(None, help="Omit to receive a hidden prompt."),
) -> None:
    password_value = password or typer.prompt("Password", hide_input=True, confirmation_prompt=True)
    if len(password_value) < 12:
        raise typer.BadParameter("password must be at least 12 characters")

    async def execute() -> tuple[str, str]:
        settings = Settings(process_role="cli")
        database = Database(settings.database.url)
        try:
            async with database.session() as session:
                repo = Repository(session)
                organization = await repo.first_organization()
                if organization is None:
                    organization = await repo.create_organization("default", "MultiCloudShield")
                scope = OrgScope(organization.id)
                if await repo.user_by_email(email):
                    raise ValueError("user already exists")
                user = await repo.create_user(scope, email, PASSWORD_HASHER.hash(password_value))
                raw, prefix, hashed = create_api_token()
                session.add(
                    ApiTokenRow(
                        organization_id=organization.id,
                        name="bootstrap",
                        token_prefix=prefix,
                        token_hash=hashed,
                        role="owner",
                        expires_at=datetime.now(UTC) + timedelta(days=90),
                    )
                )
                await session.commit()
                return str(user.id), raw
        finally:
            await database.dispose()

    try:
        user_id, token = asyncio.run(execute())
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(json.dumps({"user_id": user_id, "api_token": token, "shown_once": True}, indent=2))


def _scan_local(
    provider: CloudProvider = typer.Option(CloudProvider.DEMO),
    scope: str = typer.Option("deterministic-v1"),
    output: str = typer.Option("json", help="json or csv"),
    out: Path | None = typer.Option(None),
    fail_on: Severity | None = typer.Option(None),
) -> None:
    if output not in {"json", "csv"}:
        raise typer.BadParameter("output must be json or csv")
    organization_id = local_uuid("organization", f"local:{provider.value}:{scope}")
    connection_id = local_uuid("connection", f"local:{provider.value}:{scope}")
    mechanism = {
        CloudProvider.DEMO: CredentialMechanism.DEMO_NONE,
        CloudProvider.AWS: CredentialMechanism.AWS_DEFAULT_CHAIN,
        CloudProvider.AZURE: CredentialMechanism.AZURE_DEFAULT_CREDENTIAL,
        CloudProvider.GCP: CredentialMechanism.GCP_ADC,
        CloudProvider.IBM: CredentialMechanism.IBM_TRUSTED_PROFILE,
    }[provider]
    connection = ConnectionDescriptor(
        id=connection_id,
        organization_id=organization_id,
        name=f"local-{provider.value}",
        provider=provider,
        scope_id=scope,
        credential_mechanism=mechanism,
        is_demo=provider is CloudProvider.DEMO,
    )
    result = asyncio.run(
        run_scan(
            connection,
            options=ScanOptions(retry_base_seconds=0 if provider is CloudProvider.DEMO else 0.25),
        )
    )
    _write(result, output, out)
    if result.status.value == "failed":
        raise typer.Exit(3)
    if result.status.value == "partially_completed":
        raise typer.Exit(4)
    if fail_on is not None and any(
        finding.severity.rank >= fail_on.rank for finding in result.findings
    ):
        raise typer.Exit(2)


@scan_app.callback()
def scan_command(
    ctx: typer.Context,
    local: bool = typer.Option(False, "--local", help="Run without the API or database."),
    provider: CloudProvider = typer.Option(CloudProvider.DEMO),
    scope: str = typer.Option("deterministic-v1"),
    output: str = typer.Option("json", help="json or csv"),
    out: Path | None = typer.Option(None),
    fail_on: Severity | None = typer.Option(None),
) -> None:
    if ctx.invoked_subcommand is not None:
        return
    if not local:
        typer.echo(ctx.get_help())
        raise typer.Exit(0)
    _scan_local(provider=provider, scope=scope, output=output, out=out, fail_on=fail_on)


@scan_app.command("local", hidden=True)
def scan_local_alias(
    provider: CloudProvider = typer.Option(CloudProvider.DEMO),
    scope: str = typer.Option("deterministic-v1"),
    output: str = typer.Option("json", help="json or csv"),
    out: Path | None = typer.Option(None),
    fail_on: Severity | None = typer.Option(None),
) -> None:
    """Compatibility alias for early v0.1 development builds."""
    _scan_local(provider=provider, scope=scope, output=output, out=out, fail_on=fail_on)


@scan_app.command("start")
def scan_start(
    connection: uuid.UUID = typer.Option(...),
    wait: bool = typer.Option(False),
    output: str = typer.Option("json"),
) -> None:
    response = _remote(
        "POST", "/scans?" + urllib.parse.urlencode({"connection_id": str(connection)})
    )
    _write(response, output)
    if wait:
        scan_id = response["scan_id"]
        for _ in range(360):
            current = _remote("GET", f"/scans/{scan_id}")
            if current.get("status") not in {"queued", "running"}:
                _write(current, output)
                return
            __import__("time").sleep(1)
        raise typer.Exit(3)


@scan_app.command("status")
def scan_status(scan_id: uuid.UUID, output: str = typer.Option("json")) -> None:
    _write(_remote("GET", f"/scans/{scan_id}"), output)


@scan_app.command("list")
def scan_list(output: str = typer.Option("json")) -> None:
    _write(_remote("GET", "/scans"), output)


@scan_app.command("cancel")
def scan_cancel(scan_id: uuid.UUID) -> None:
    _write(_remote("DELETE", f"/scans/{scan_id}"), "json")


@connection_app.command("list")
def connection_list(output: str = typer.Option("json")) -> None:
    _write(_remote("GET", "/connections"), output)


@token_app.command("create")
def token_create(
    name: str = typer.Option(...),
    role: str = typer.Option("viewer"),
    expires_days: int = typer.Option(90, min=1, max=365),
) -> None:
    _write(
        _remote(
            "POST",
            "/tokens",
            {"name": name, "role": role, "expires_days": expires_days},
        ),
        "json",
    )


@token_app.command("list")
def token_list() -> None:
    _write(_remote("GET", "/tokens"), "json")


@token_app.command("revoke")
def token_revoke(token_id: uuid.UUID) -> None:
    _remote("DELETE", f"/tokens/{token_id}")
    typer.echo(json.dumps({"id": str(token_id), "revoked": True}))


@connection_app.command("add")
def connection_add(
    provider: CloudProvider = typer.Option(...),
    name: str = typer.Option(...),
    scope_id: str = typer.Option(...),
    mechanism: CredentialMechanism = typer.Option(...),
    reference_json: str = typer.Option("{}"),
) -> None:
    try:
        reference = json.loads(reference_json)
    except json.JSONDecodeError as exc:
        raise typer.BadParameter("reference-json must be valid JSON") from exc
    _write(
        _remote(
            "POST",
            "/connections",
            {
                "provider": provider.value,
                "name": name,
                "scope_id": scope_id,
                "credential_mechanism": mechanism.value,
                "credential_reference": reference,
                "region_allowlist": [],
            },
        ),
        "json",
    )


@connection_app.command("test")
def connection_test(connection_id: uuid.UUID) -> None:
    _write(_remote("POST", f"/connections/{connection_id}/test"), "json")


@connection_app.command("enable")
def connection_enable(connection_id: uuid.UUID) -> None:
    _write(_remote("PATCH", f"/connections/{connection_id}?enabled=true"), "json")


@connection_app.command("disable")
def connection_disable(connection_id: uuid.UUID) -> None:
    _write(_remote("PATCH", f"/connections/{connection_id}?enabled=false"), "json")


@connection_app.command("remove")
def connection_remove(
    connection_id: uuid.UUID, purge: bool = typer.Option(False, help="Permanently purge history.")
) -> None:
    suffix = "?purge=true" if purge else "?purge=false"
    _write(_remote("DELETE", f"/connections/{connection_id}{suffix}"), "json")


@finding_app.command("list")
def finding_list(
    output: str = typer.Option("json"),
    severity: str | None = None,
    provider: str | None = None,
    status: str | None = None,
) -> None:
    query = urllib.parse.urlencode(
        {
            key: value
            for key, value in {"severity": severity, "provider": provider, "status": status}.items()
            if value
        }
    )
    _write(_remote("GET", "/findings" + ("?" + query if query else "")), output)


@finding_app.command("show")
def finding_show(finding_id: uuid.UUID) -> None:
    _write(_remote("GET", f"/findings/{finding_id}"), "json")


@finding_app.command("export")
def finding_export(
    format: str = typer.Option("json"), out: Path | None = typer.Option(None)
) -> None:
    base = _server_url()
    token = os.getenv("MCS_API_TOKEN")
    if not token:
        raise typer.BadParameter("MCS_API_TOKEN is required")
    request = urllib.request.Request(  # noqa: S310 -- validated HTTP(S) base
        base + f"/api/v1/exports/findings?format={format}",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
        data = response.read()
    if out:
        out.write_bytes(data)
    else:
        sys.stdout.buffer.write(data)


@policy_app.command("list")
def policy_list(output: str = typer.Option("json")) -> None:
    _write({"items": [item.model_dump(mode="json") for item in load_bundle().policies]}, output)


@policy_app.command("show")
def policy_show(policy_id: str) -> None:
    item = next((policy for policy in load_bundle().policies if policy.id == policy_id), None)
    if not item:
        raise typer.Exit(1)
    _write(item.model_dump(mode="json"), "json")


@policy_app.command("validate")
def policy_validate() -> None:
    bundle = load_bundle()
    typer.echo(
        json.dumps({"valid": True, "version": bundle.version, "policies": len(bundle.policies)})
    )


@demo_app.command("seed")
def demo_seed() -> None:
    async def execute() -> tuple[str, int]:
        settings = Settings(process_role="cli")
        database = Database(settings.database.url)
        try:
            async with database.session() as session:
                repo = Repository(session)
                organization = await repo.first_organization()
                if organization is None:
                    raise ValueError("run mcs bootstrap first")
                scope = OrgScope(organization.id)
                existing = next(
                    (row for row in await repo.list_connections(scope) if row.provider == "demo"),
                    None,
                )
                descriptor = ConnectionDescriptor(
                    id=existing.id
                    if existing
                    else local_uuid("connection", "demo:deterministic-v1"),
                    organization_id=organization.id,
                    name=existing.name if existing else "Demo estate",
                    provider=CloudProvider.DEMO,
                    scope_id="deterministic-v1",
                    credential_mechanism=CredentialMechanism.DEMO_NONE,
                    is_demo=True,
                )
                if existing is None:
                    await repo.create_connection(scope, descriptor)
                    await session.commit()
                result = await run_scan(descriptor, options=ScanOptions(retry_base_seconds=0))
                await repo.persist_scan(scope, result, trigger="manual_cli")
                await session.commit()
                return str(result.scan_id), len(result.findings)
        finally:
            await database.dispose()

    try:
        scan_id, count = asyncio.run(execute())
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(json.dumps({"scan_id": scan_id, "findings": count, "is_demo": True}))


if __name__ == "__main__":
    app()
