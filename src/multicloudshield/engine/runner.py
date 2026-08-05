from __future__ import annotations

import asyncio
from dataclasses import dataclass
from time import monotonic, sleep
from typing import Any
from uuid import UUID

from multicloudshield import __version__
from multicloudshield.core.enums import EvaluationResult, ScanErrorCategory, ScanStatus
from multicloudshield.core.identity import digest, finding_fingerprint
from multicloudshield.core.models import (
    ConnectionDescriptor,
    Evidence,
    Finding,
    PolicyEvaluation,
    ScanError,
    ScanResult,
    ScanStatistics,
    ScanTarget,
    utcnow,
)
from multicloudshield.core.security import redact_text
from multicloudshield.engine.retry import backoff_delay
from multicloudshield.policy import PolicyBundle, evaluate_policy, load_bundle
from multicloudshield.policy.engine import EvaluationOutcome, result_counter_name
from multicloudshield.policy.verdict import Verdict
from multicloudshield.providers import get_adapter
from multicloudshield.providers.base import (
    CancellationToken,
    CollectionContext,
    PageBudget,
    ProviderError,
)
from multicloudshield.providers.normalize import normalize_observation


@dataclass(frozen=True)
class ScanOptions:
    max_concurrent_targets: int = 16
    max_pages_per_target: int = 200
    max_items_per_target: int = 50_000
    target_deadline_seconds: float = 300
    scan_deadline_seconds: float = 3600
    max_retries: int = 5
    retry_base_seconds: float = 0.25
    cancel: CancellationToken | None = None


async def run_scan(
    connection: ConnectionDescriptor,
    *,
    bundle: PolicyBundle | None = None,
    options: ScanOptions | None = None,
    scan_id: UUID | None = None,
) -> ScanResult:
    opts = options or ScanOptions()
    policy_bundle = bundle or load_bundle()
    adapter = get_adapter(connection.provider)
    cancel = opts.cancel or CancellationToken()
    started_at = utcnow()
    started_clock = monotonic()
    collectors = tuple(adapter.collectors())
    scopes = adapter.resolve_scopes(connection)
    result = ScanResult(
        scan_id=scan_id or __import__("uuid").uuid4(),
        connection=connection,
        status=ScanStatus.RUNNING,
        started_at=started_at,
        finished_at=started_at,
        engine_version=__version__,
        policy_bundle_version=policy_bundle.version,
        collector_set_digest=digest(sorted(f"{item.id}@{item.version}" for item in collectors)),
        is_demo=connection.is_demo,
    )
    stats = ScanStatistics(targets_total=len(scopes) * len(collectors))
    semaphore = asyncio.Semaphore(opts.max_concurrent_targets)

    async def one_target(
        collector: Any, scope: Any
    ) -> tuple[
        Any, Any, list[Any], list[tuple[str, dict[str, Any]]], list[ScanError], PageBudget, int
    ]:
        async with semaphore:
            budget = PageBudget(opts.max_pages_per_target, opts.max_items_per_target)
            observations: list[Any] = []
            assets_and_provenance: list[tuple[str, dict[str, Any]]] = []
            errors: list[ScanError] = []
            retries = 0
            for attempt in range(opts.max_retries + 1):
                context = CollectionContext(
                    connection=connection,
                    scope=scope,
                    cancel=cancel,
                    budget=budget,
                    deadline_at=monotonic() + opts.target_deadline_seconds,
                )
                try:
                    batch = await asyncio.to_thread(list, collector.collect(context))
                    observations.extend(batch)
                    break
                except ProviderError as exc:
                    if exc.retryable and attempt < opts.max_retries:
                        retries += 1
                        delay = backoff_delay(attempt, base=opts.retry_base_seconds)
                        if delay:
                            await asyncio.to_thread(sleep, delay)
                        continue
                    errors.append(
                        ScanError(
                            category=exc.category,
                            provider=connection.provider,
                            scope_id=scope.id,
                            collector_id=collector.id,
                            operation=exc.operation,
                            message=redact_text(str(exc)),
                            provider_error_code=exc.code,
                            retryable=exc.retryable,
                            retry_count=retries,
                            remediation_hint=exc.permission,
                        )
                    )
                    break
                except Exception:
                    errors.append(
                        ScanError(
                            category=ScanErrorCategory.INTERNAL,
                            provider=connection.provider,
                            scope_id=scope.id,
                            collector_id=collector.id,
                            message="collector failed unexpectedly",
                        )
                    )
                    break
            normalized: list[Any] = []
            for observation in observations:
                try:
                    asset = normalize_observation(
                        observation,
                        organization_id=connection.organization_id,
                        connection_id=connection.id,
                    )
                    normalized.append(asset)
                    assets_and_provenance.append((asset.asset_urn, observation.provenance))
                except ValueError as exc:
                    errors.append(
                        ScanError(
                            category=ScanErrorCategory.PARSE_ERROR,
                            provider=observation.provider,
                            scope_id=scope.id,
                            collector_id=collector.id,
                            message=redact_text(str(exc)),
                        )
                    )
            return collector, scope, normalized, assets_and_provenance, errors, budget, retries

    tasks = {
        asyncio.create_task(one_target(collector, scope)): (collector, scope)
        for scope in scopes
        for collector in collectors
    }
    done, pending = await asyncio.wait(tasks, timeout=opts.scan_deadline_seconds)
    deadline_exceeded = bool(pending)
    target_results = [await task for task in done]
    if pending:
        cancel.cancel()
        for task in pending:
            collector, scope = tasks[task]
            task.cancel()
            target_results.append(
                (
                    collector,
                    scope,
                    [],
                    [],
                    [
                        ScanError(
                            category=ScanErrorCategory.TIMEOUT,
                            provider=connection.provider,
                            scope_id=scope.id,
                            collector_id=collector.id,
                            message="scan deadline exceeded",
                        )
                    ],
                    PageBudget(opts.max_pages_per_target, opts.max_items_per_target),
                    0,
                )
            )
        await asyncio.gather(*pending, return_exceptions=True)
    provenance_by_urn: dict[str, dict[str, Any]] = {}
    for collector, scope, assets, provenances, errors, budget, retries in target_results:
        result.assets.extend(assets)
        provenance_by_urn.update(provenances)
        result.errors.extend(errors)
        stats.pages_fetched += budget.pages
        stats.api_calls += budget.pages + retries
        stats.retries += retries
        if errors and all(error.category is ScanErrorCategory.SERVICE_DISABLED for error in errors):
            target_status = "skipped"
            stats.targets_skipped += 1
        elif errors:
            target_status = "failed"
            stats.targets_failed += 1
        else:
            target_status = "succeeded"
            stats.targets_succeeded += 1
        result.targets.append(
            ScanTarget(
                scan_id=result.scan_id,
                scope_kind=scope.kind,
                scope_id=scope.id,
                collector_id=collector.id,
                collector_version=collector.version,
                status=target_status,
                items_collected=len(assets),
                pages_fetched=budget.pages,
                error_count=len(errors),
            )
        )

    result.targets.sort(key=lambda item: (item.scope_id, item.collector_id))

    deduplicated = {asset.asset_urn: asset for asset in result.assets}
    result.assets = sorted(deduplicated.values(), key=lambda item: item.asset_urn)
    stats.assets_discovered = len(result.assets)
    succeeded_targets = {
        (target.scope_id, target.collector_id)
        for target in result.targets
        if target.status == "succeeded"
    }
    for asset in result.assets:
        provenance = provenance_by_urn.get(asset.asset_urn, {})
        collector_id = str(provenance.get("collector_id", ""))
        if (asset.scope_id, collector_id) not in succeeded_targets:
            continue
        for policy in policy_bundle.policies:
            try:
                outcome = evaluate_policy(
                    policy,
                    provider=asset.provider,
                    resource_type=asset.resource_type,
                    facts=asset.facts,
                )
            except Exception:
                outcome = EvaluationOutcome(Verdict(EvaluationResult.ERROR, "POLICY_ERROR"), {})
                result.errors.append(
                    ScanError(
                        category=ScanErrorCategory.INTERNAL,
                        provider=asset.provider,
                        scope_id=asset.scope_id,
                        collector_id="policy-engine",
                        message="policy evaluation failed",
                        provider_error_code=policy.id,
                    )
                )
            evidence_payload = {
                "observed_facts": outcome.observed_facts,
                "provenance": provenance_by_urn.get(asset.asset_urn, {}),
            }
            evidence = Evidence(
                scan_id=result.scan_id,
                observed_facts=outcome.observed_facts,
                provenance=provenance_by_urn.get(asset.asset_urn, {}),
                content_digest=digest(evidence_payload),
            )
            evaluation = PolicyEvaluation(
                scan_id=result.scan_id,
                asset_id=asset.id,
                asset_urn=asset.asset_urn,
                policy_id=policy.id,
                policy_version=policy.version,
                result=outcome.verdict.result,
                reason_code=outcome.verdict.reason_code,
                severity=policy.severity,
                evidence_id=evidence.id,
            )
            result.evidence.append(evidence)
            result.evaluations.append(evaluation)
            stats.policies_evaluated += 1
            name = result_counter_name(outcome.verdict.result)
            setattr(stats, name, getattr(stats, name) + 1)
            if outcome.verdict.result is EvaluationResult.FAIL:
                for sub_locator in outcome.verdict.sub_locators or ("",):
                    result.findings.append(
                        Finding(
                            organization_id=connection.organization_id,
                            connection_id=connection.id,
                            asset_id=asset.id,
                            asset_urn=asset.asset_urn,
                            provider=asset.provider,
                            resource_type=asset.resource_type,
                            resource_name=asset.name,
                            fingerprint=finding_fingerprint(
                                connection.organization_id,
                                connection.id,
                                policy.id,
                                asset.asset_urn,
                                sub_locator,
                            ),
                            policy_id=policy.id,
                            policy_version=policy.version,
                            title=policy.title,
                            risk_explanation=policy.rationale,
                            remediation=policy.remediation.model_dump(mode="json"),
                            compliance_mappings=[
                                item.model_dump(mode="json") for item in policy.compliance_mappings
                            ],
                            severity=policy.severity,
                            evidence_id=evidence.id,
                            first_seen_scan_id=result.scan_id,
                            last_seen_scan_id=result.scan_id,
                            is_demo=asset.is_demo,
                        )
                    )
    result.findings.sort(key=lambda item: (item.severity.rank * -1, item.fingerprint))
    result.errors.sort(
        key=lambda item: (
            item.category.value,
            item.collector_id,
            item.scope_id,
            item.provider_error_code or "",
        )
    )
    if cancel.cancelled and not deadline_exceeded:
        result.status = ScanStatus.CANCELLED
        result.findings = []
    elif stats.targets_succeeded and stats.targets_failed:
        result.status = ScanStatus.PARTIALLY_COMPLETED
    elif stats.targets_failed and not stats.targets_succeeded:
        result.status = ScanStatus.FAILED
    else:
        result.status = ScanStatus.COMPLETED
    result.finished_at = utcnow()
    stats.duration_ms = int((monotonic() - started_clock) * 1000)
    result.stats = stats
    return result
