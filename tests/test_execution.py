from __future__ import annotations

import json
import signal
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import audit


# --- write_artifacts ---


def test_write_artifacts_creates_both_files(tmp_path: Path) -> None:
    rp = tmp_path / "report.md"
    mp = tmp_path / "meta.json"
    r, m = audit.write_artifacts("# Report", {"key": "val"}, report_path=rp, metadata_path=mp)
    assert r.exists()
    assert m.exists()


def test_write_artifacts_report_content(tmp_path: Path) -> None:
    rp = tmp_path / "report.md"
    mp = tmp_path / "meta.json"
    r, _ = audit.write_artifacts("My Report", {}, report_path=rp, metadata_path=mp)
    assert r.read_text() == "My Report"


def test_write_artifacts_metadata_json_format(tmp_path: Path) -> None:
    rp = tmp_path / "report.md"
    mp = tmp_path / "meta.json"
    _, m = audit.write_artifacts("r", {"z": 1, "a": 2}, report_path=rp, metadata_path=mp)
    data = json.loads(m.read_text())
    assert data == {"a": 2, "z": 1}
    # Verify it's formatted with indent=2 and sort_keys
    raw = m.read_text()
    assert '  "a": 2' in raw


def test_write_artifacts_creates_parent_dirs(tmp_path: Path) -> None:
    rp = tmp_path / "sub" / "report.md"
    mp = tmp_path / "sub2" / "meta.json"
    r, m = audit.write_artifacts("r", {}, report_path=rp, metadata_path=mp)
    assert r.exists()
    assert m.exists()


# --- _check_prerequisites ---


def test_check_prerequisites_deno_found() -> None:
    with patch("shutil.which", return_value="/usr/bin/deno"):
        audit._check_prerequisites()  # should not raise


def test_check_prerequisites_deno_not_found_raises() -> None:
    with patch("shutil.which", return_value=None):
        with patch("pathlib.Path.exists", return_value=False):
            with pytest.raises(RuntimeError, match="deno"):
                audit._check_prerequisites()


def test_check_prerequisites_deno_local_fallback(tmp_path: Path) -> None:
    # Simulate local deno being found after first which() fails
    call_count = {"n": 0}

    def mock_which(name: str) -> str | None:
        call_count["n"] += 1
        if call_count["n"] == 1:
            return None  # first call: deno not on PATH
        return "/home/user/.deno/bin/deno"  # second call: found after PATH update

    local_deno = tmp_path / ".deno" / "bin" / "deno"
    local_deno.parent.mkdir(parents=True)
    local_deno.touch()

    with patch("shutil.which", side_effect=mock_which):
        with patch("pathlib.Path.home", return_value=tmp_path):
            audit._check_prerequisites()


def test_check_prerequisites_deno_local_fallback_missing() -> None:
    with patch("shutil.which", return_value=None):
        with patch("pathlib.Path.exists", return_value=False):
            with pytest.raises(RuntimeError, match="deno"):
                audit._check_prerequisites()


# --- _build_lm ---


def test_build_lm_calls_dspy_lm() -> None:
    mock_lm = MagicMock()
    with patch("dspy.LM", return_value=mock_lm) as patched:
        result = audit._build_lm("model", "http://api", 4096, "key123")
        patched.assert_called_once_with(
            "model", api_base="http://api", max_tokens=4096, api_key="key123"
        )
        assert result is mock_lm


def test_build_lm_returns_lm_instance() -> None:
    mock_lm = MagicMock()
    with patch("dspy.LM", return_value=mock_lm):
        result = audit._build_lm("m", "b", 100, "k")
        assert result is mock_lm


# --- CodeScanner ---


def test_code_scanner_is_dspy_signature() -> None:
    import dspy
    assert issubclass(audit.CodeScanner, dspy.Signature)


def test_code_scanner_has_expected_fields() -> None:
    fields = audit.CodeScanner.model_fields
    assert "source_overview" in fields
    assert "documentation" in fields


# --- AuditTimeoutError ---


def test_audit_timeout_error_is_timeout_error() -> None:
    assert issubclass(audit.AuditTimeoutError, TimeoutError)


def test_audit_timeout_error_message() -> None:
    with pytest.raises(audit.AuditTimeoutError, match="test message"):
        raise audit.AuditTimeoutError("test message")


# --- timeout_guard ---


def test_timeout_guard_zero_seconds_noop() -> None:
    with audit.timeout_guard(0):
        pass  # should not raise


def test_timeout_guard_negative_seconds_noop() -> None:
    with audit.timeout_guard(-1):
        pass  # should not raise


def test_timeout_guard_restores_signal() -> None:
    if not hasattr(signal, "SIGALRM"):
        pytest.skip("No SIGALRM on this platform")
    if threading.current_thread() is not threading.main_thread():
        pytest.skip("Must run in main thread")

    original = signal.getsignal(signal.SIGALRM)
    with audit.timeout_guard(60):
        pass
    restored = signal.getsignal(signal.SIGALRM)
    assert restored is original


def test_timeout_guard_raises_on_timeout() -> None:
    if not hasattr(signal, "SIGALRM"):
        pytest.skip("No SIGALRM on this platform")
    if threading.current_thread() is not threading.main_thread():
        pytest.skip("Must run in main thread")

    with pytest.raises(audit.AuditTimeoutError):
        with audit.timeout_guard(1):
            time.sleep(5)


def test_timeout_guard_non_main_thread_noop() -> None:
    result = {"ok": False}

    def run_in_thread() -> None:
        with audit.timeout_guard(60):
            result["ok"] = True

    t = threading.Thread(target=run_in_thread)
    t.start()
    t.join(timeout=5)
    assert result["ok"]


# --- run_audit_with_retry ---


def test_run_audit_success_first_attempt() -> None:
    mock_scanner = MagicMock(return_value="result")
    with patch("time.sleep"):
        result, attempt, duration = audit.run_audit_with_retry(
            mock_scanner,
            source_overview="overview",
            retries=2,
            timeout_seconds=0,
            backoff_seconds=1.0,
        )
    assert result == "result"
    assert attempt == 1


def test_run_audit_fails_then_succeeds() -> None:
    mock_scanner = MagicMock(side_effect=[Exception("fail"), "ok"])
    with patch("time.sleep"):
        result, attempt, _ = audit.run_audit_with_retry(
            mock_scanner,
            source_overview="overview",
            retries=2,
            timeout_seconds=0,
            backoff_seconds=0.1,
        )
    assert result == "ok"
    assert attempt == 2


def test_run_audit_all_attempts_fail() -> None:
    mock_scanner = MagicMock(side_effect=Exception("fail"))
    with patch("time.sleep"):
        with pytest.raises(RuntimeError, match="failed after"):
            audit.run_audit_with_retry(
                mock_scanner,
                source_overview="overview",
                retries=1,
                timeout_seconds=0,
                backoff_seconds=0.1,
            )


def test_run_audit_retries_count() -> None:
    mock_scanner = MagicMock(
        side_effect=[Exception("1"), Exception("2"), "success"]
    )
    with patch("time.sleep"):
        result, attempt, _ = audit.run_audit_with_retry(
            mock_scanner,
            source_overview="overview",
            retries=2,
            timeout_seconds=0,
            backoff_seconds=0.1,
        )
    assert result == "success"
    assert attempt == 3


def test_run_audit_backoff_sleep() -> None:
    mock_scanner = MagicMock(
        side_effect=[Exception("1"), Exception("2"), "ok"]
    )
    with patch("time.sleep") as mock_sleep:
        audit.run_audit_with_retry(
            mock_scanner,
            source_overview="overview",
            retries=2,
            timeout_seconds=0,
            backoff_seconds=2.0,
        )
    # First retry: 2.0 * 2^0 = 2.0, Second retry: 2.0 * 2^1 = 4.0
    calls = [c.args[0] for c in mock_sleep.call_args_list]
    assert calls[0] == pytest.approx(2.0)
    assert calls[1] == pytest.approx(4.0)


def test_run_audit_heartbeat_prints(capsys: pytest.CaptureFixture[str]) -> None:
    def slow_scanner(**kwargs: Any) -> str:
        time.sleep(0.1)
        return "done"

    with patch("time.sleep"):
        audit.run_audit_with_retry(
            slow_scanner,
            source_overview="overview",
            retries=0,
            timeout_seconds=0,
            backoff_seconds=0.1,
        )
    output = capsys.readouterr().out
    assert "Starting audit attempt" in output


def test_run_audit_timeout_zero() -> None:
    mock_scanner = MagicMock(return_value="result")
    with patch("time.sleep"):
        result, _, _ = audit.run_audit_with_retry(
            mock_scanner,
            source_overview="overview",
            retries=0,
            timeout_seconds=0,
            backoff_seconds=0.1,
        )
    assert result == "result"
