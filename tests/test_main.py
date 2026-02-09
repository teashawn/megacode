from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import audit


@pytest.fixture()
def main_repo(tmp_path: Path) -> Path:
    """Create a minimal repo for main() tests."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("[project]", encoding="utf-8")
    (repo / "app.py").write_text("import os\npassword = 'secret'\n", encoding="utf-8")
    return repo


# --- parse_args ---


def test_parse_args_language_flag() -> None:
    """--language flag is accepted by the arg parser."""
    original = sys.argv
    try:
        sys.argv = ["audit", "--language", "dotnet", "--source-root", "/tmp"]
        args = audit.parse_args()
        assert args.language == "dotnet"
    finally:
        sys.argv = original


def test_parse_args_language_auto_default() -> None:
    """--language defaults to auto."""
    original = sys.argv
    try:
        sys.argv = ["audit", "--source-root", "/tmp"]
        args = audit.parse_args()
        assert args.language == "auto"
    finally:
        sys.argv = original


def test_parse_args_fast_mode_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["audit", "--fast-mode", "--source-root", "/tmp"])
    args = audit.parse_args()
    assert args.fast_mode is True


def test_parse_args_default_fast_mode_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["audit", "--source-root", "/tmp"])
    args = audit.parse_args()
    assert args.fast_mode is False


def test_parse_args_numeric_args(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", "/tmp",
        "--max-iterations", "5",
        "--max-files", "100",
        "--retries", "3",
    ])
    args = audit.parse_args()
    assert args.max_iterations == 5
    assert args.max_files == 100
    assert args.retries == 3


def test_parse_args_all_language_choices(monkeypatch: pytest.MonkeyPatch) -> None:
    for lang in ["auto", "python", "go", "react", "dotnet"]:
        monkeypatch.setattr(
            sys, "argv", ["audit", "--language", lang, "--source-root", "/tmp"]
        )
        args = audit.parse_args()
        assert args.language == lang


def test_parse_args_output_paths_as_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", "/tmp",
        "--output-report", "/tmp/report.md",
        "--output-metadata", "/tmp/meta.json",
        "--output-manifest", "/tmp/manifest.jsonl",
    ])
    args = audit.parse_args()
    assert isinstance(args.output_report, Path)
    assert isinstance(args.output_metadata, Path)
    assert isinstance(args.output_manifest, Path)


# --- main() validation errors ---


def test_main_source_root_not_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(tmp_path / "nonexistent"),
    ])
    with pytest.raises(RuntimeError, match="not a directory"):
        audit.main()


def test_main_zero_iterations(main_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo), "--max-iterations", "0",
    ])
    with pytest.raises(ValueError, match="max-iterations"):
        audit.main()


def test_main_zero_max_files(main_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo), "--max-files", "0",
    ])
    with pytest.raises(ValueError, match="max-files"):
        audit.main()


def test_main_negative_retries(main_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo), "--retries", "-1",
    ])
    with pytest.raises(ValueError, match="retries"):
        audit.main()


def test_main_negative_timeout(main_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo), "--timeout-seconds", "-1",
    ])
    with pytest.raises(ValueError, match="timeout-seconds"):
        audit.main()


def test_main_negative_backoff(main_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo), "--backoff-seconds", "-1",
    ])
    with pytest.raises(ValueError, match="backoff-seconds"):
        audit.main()


def test_main_zero_max_file_bytes(main_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo), "--max-file-bytes", "0",
    ])
    with pytest.raises(ValueError, match="max-file-bytes"):
        audit.main()


def test_main_zero_rlm_max_llm_calls(main_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo), "--rlm-max-llm-calls", "0",
    ])
    with pytest.raises(ValueError, match="rlm-max-llm-calls"):
        audit.main()


def test_main_zero_rlm_max_output_chars(main_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo), "--rlm-max-output-chars", "0",
    ])
    with pytest.raises(ValueError, match="rlm-max-output-chars"):
        audit.main()


def test_main_zero_tool_max_lines(main_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo), "--tool-max-lines", "0",
    ])
    with pytest.raises(ValueError, match="tool-max-lines"):
        audit.main()


def test_main_zero_tool_max_chars(main_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo), "--tool-max-chars", "0",
    ])
    with pytest.raises(ValueError, match="tool-max-chars"):
        audit.main()


def test_main_zero_search_max_files(main_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo), "--search-max-files", "0",
    ])
    with pytest.raises(ValueError, match="search-max-files"):
        audit.main()


def test_main_zero_search_max_matches(main_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo), "--search-max-matches", "0",
    ])
    with pytest.raises(ValueError, match="search-max-matches"):
        audit.main()


def test_main_zero_search_rg_chunk_size(main_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo), "--search-rg-chunk-size", "0",
    ])
    with pytest.raises(ValueError, match="search-rg-chunk-size"):
        audit.main()


def test_main_zero_overview_top_files(main_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo), "--overview-top-files", "0",
    ])
    with pytest.raises(ValueError, match="overview-top-files"):
        audit.main()


def test_main_zero_lm_max_tokens(main_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo), "--lm-max-tokens", "0",
    ])
    with pytest.raises(ValueError, match="lm-max-tokens"):
        audit.main()


# --- main() fast mode ---


def test_main_fast_mode_clamps_iterations(
    main_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mock_result = MagicMock()
    mock_result.documentation = "report"

    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo),
        "--fast-mode", "--max-iterations", "20",
        "--language", "python",
    ])
    with (
        patch("audit._check_prerequisites"),
        patch("audit._build_lm", return_value=MagicMock()),
        patch("dspy.configure"),
        patch("dspy.RLM", return_value=MagicMock()),
        patch(
            "audit.run_audit_with_retry",
            return_value=(mock_result, 1, 10.0),
        ),
    ):
        result = audit.main()
    assert result == 0


def test_main_fast_mode_clamps_llm_calls(
    main_repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    mock_result = MagicMock()
    mock_result.documentation = "report"

    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo),
        "--fast-mode", "--rlm-max-llm-calls", "100",
        "--language", "python",
    ])
    with (
        patch("audit._check_prerequisites"),
        patch("audit._build_lm", return_value=MagicMock()),
        patch("dspy.configure"),
        patch("dspy.RLM", return_value=MagicMock()),
        patch(
            "audit.run_audit_with_retry",
            return_value=(mock_result, 1, 10.0),
        ),
    ):
        audit.main()
    output = capsys.readouterr().out
    assert "Fast mode enabled" in output


def test_main_fast_mode_clamps_max_tokens(
    main_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mock_result = MagicMock()
    mock_result.documentation = "report"

    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo),
        "--fast-mode", "--lm-max-tokens", "16384",
        "--language", "python",
    ])
    with (
        patch("audit._check_prerequisites"),
        patch("audit._build_lm", return_value=MagicMock()),
        patch("dspy.configure"),
        patch("dspy.RLM", return_value=MagicMock()),
        patch(
            "audit.run_audit_with_retry",
            return_value=(mock_result, 1, 10.0),
        ),
    ):
        result = audit.main()
    assert result == 0


# --- main() language detection ---


def test_main_auto_detect_python(
    main_repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    mock_result = MagicMock()
    mock_result.documentation = "report"

    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo), "--language", "auto",
    ])
    with (
        patch("audit._check_prerequisites"),
        patch("audit._build_lm", return_value=MagicMock()),
        patch("dspy.configure"),
        patch("dspy.RLM", return_value=MagicMock()),
        patch(
            "audit.run_audit_with_retry",
            return_value=(mock_result, 1, 10.0),
        ),
    ):
        audit.main()
    output = capsys.readouterr().out
    assert "Auto-detected language profile: python" in output


def test_main_auto_fallback_to_dotnet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    # Need at least one file that dotnet profile will index
    (repo / "Program.cs").write_text("class P {}", encoding="utf-8")

    mock_result = MagicMock()
    mock_result.documentation = "report"

    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(repo), "--language", "auto",
    ])
    with (
        patch("audit._check_prerequisites"),
        patch("audit._build_lm", return_value=MagicMock()),
        patch("dspy.configure"),
        patch("dspy.RLM", return_value=MagicMock()),
        patch("audit.detect_language", return_value=None),
        patch(
            "audit.run_audit_with_retry",
            return_value=(mock_result, 1, 10.0),
        ),
    ):
        audit.main()
    output = capsys.readouterr().out
    assert "Defaulting to dotnet" in output


def test_main_explicit_language(
    main_repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    mock_result = MagicMock()
    mock_result.documentation = "report"

    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo), "--language", "python",
    ])
    with (
        patch("audit._check_prerequisites"),
        patch("audit._build_lm", return_value=MagicMock()),
        patch("dspy.configure"),
        patch("dspy.RLM", return_value=MagicMock()),
        patch(
            "audit.run_audit_with_retry",
            return_value=(mock_result, 1, 10.0),
        ),
    ):
        audit.main()
    output = capsys.readouterr().out
    assert "Using language profile: Python" in output


# --- main() execution ---


def test_main_empty_manifest_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    # Only a file that won't match python profile
    (repo / "README.md").write_text("hello", encoding="utf-8")

    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(repo), "--language", "python",
    ])
    with patch("audit._check_prerequisites"):
        with pytest.raises(RuntimeError, match="No files indexed"):
            audit.main()


def test_main_success_returns_zero(
    main_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mock_result = MagicMock()
    mock_result.documentation = "# Security Report"

    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo), "--language", "python",
    ])
    with (
        patch("audit._check_prerequisites"),
        patch("audit._build_lm", return_value=MagicMock()),
        patch("dspy.configure"),
        patch("dspy.RLM", return_value=MagicMock()),
        patch(
            "audit.run_audit_with_retry",
            return_value=(mock_result, 1, 5.0),
        ),
    ):
        result = audit.main()
    assert result == 0


def test_main_writes_outputs(
    main_repo: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    mock_result = MagicMock()
    mock_result.documentation = "# Security Report"
    report_path = tmp_path / "output" / "report.md"
    meta_path = tmp_path / "output" / "meta.json"
    manifest_path = tmp_path / "output" / "manifest.jsonl"

    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo),
        "--language", "python",
        "--output-report", str(report_path),
        "--output-metadata", str(meta_path),
        "--output-manifest", str(manifest_path),
    ])
    with (
        patch("audit._check_prerequisites"),
        patch("audit._build_lm", return_value=MagicMock()),
        patch("dspy.configure"),
        patch("dspy.RLM", return_value=MagicMock()),
        patch(
            "audit.run_audit_with_retry",
            return_value=(mock_result, 1, 5.0),
        ),
    ):
        audit.main()

    assert report_path.exists()
    assert meta_path.exists()
    assert manifest_path.exists()
    assert "Security Report" in report_path.read_text()
    meta = json.loads(meta_path.read_text())
    assert "duration_seconds" in meta


def test_main_verbose_env_note(
    main_repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    mock_result = MagicMock()
    mock_result.documentation = "report"

    monkeypatch.setattr(sys, "argv", [
        "audit", "--source-root", str(main_repo),
        "--language", "python", "--no-verbose",
    ])
    monkeypatch.setenv("AUDIT_VERBOSE", "1")
    with (
        patch("audit._check_prerequisites"),
        patch("audit._build_lm", return_value=MagicMock()),
        patch("dspy.configure"),
        patch("dspy.RLM", return_value=MagicMock()),
        patch(
            "audit.run_audit_with_retry",
            return_value=(mock_result, 1, 5.0),
        ),
    ):
        audit.main()
    output = capsys.readouterr().out
    assert "verbose RLM logs are disabled" in output
