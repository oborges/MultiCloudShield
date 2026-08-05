from multicloudshield.core.security import csv_safe, redact, redact_text, sanitize_text


def test_csv_formula_injection_is_neutralized() -> None:
    for value in ("=SUM(A1:A2)", "+cmd", "-1+2", "@payload", "\tformula", "\rformula"):
        assert csv_safe(value).startswith("'")
    assert csv_safe("ordinary") == "ordinary"


def test_recursive_redaction_covers_keys_and_bearer_tokens() -> None:
    payload = {"password": "not-for-output", "nested": {"authorization": "Bearer opaque"}}
    assert redact(payload) == {"password": "[REDACTED]", "nested": {"authorization": "[REDACTED]"}}
    assert "opaque" not in redact_text("failed with Bearer opaque")


def test_provider_control_characters_are_removed_and_bounded() -> None:
    value = sanitize_text("safe\x00<script>" + "x" * 100, max_length=20)
    assert "\x00" not in value
    assert len(value) == 20
