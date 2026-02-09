from __future__ import annotations

import re
from pathlib import Path

import pytest

import audit


# --- _normalize_relative_path ---


def test_normalize_relative_path() -> None:
    assert audit._normalize_relative_path("./src\\foo.cs") == "src/foo.cs"


def test_normalize_relative_path_multiple_leading_dotslash() -> None:
    assert audit._normalize_relative_path("././src/file.py") == "src/file.py"


def test_normalize_relative_path_backslash_and_whitespace() -> None:
    assert audit._normalize_relative_path("  src\\sub\\f.cs  ") == "src/sub/f.cs"


def test_normalize_relative_path_already_clean() -> None:
    assert audit._normalize_relative_path("src/file.py") == "src/file.py"


# --- _normalize_lm_model_id ---


def test_normalize_lm_model_id_for_openai_compatible_base() -> None:
    resolved = audit._normalize_lm_model_id("mitko", "http://localhost:8000/v1")
    assert resolved == "openai/mitko"

    already_qualified = audit._normalize_lm_model_id(
        "openai/mitko", "http://localhost:8000/v1"
    )
    assert already_qualified == "openai/mitko"


def test_normalize_lm_model_id_empty_raises() -> None:
    with pytest.raises(ValueError, match="model cannot be empty"):
        audit._normalize_lm_model_id("", "some-provider")


def test_normalize_lm_model_id_whitespace_only_raises() -> None:
    with pytest.raises(ValueError, match="model cannot be empty"):
        audit._normalize_lm_model_id("   ", "some-provider")


def test_normalize_lm_model_id_non_http_base() -> None:
    result = audit._normalize_lm_model_id("mymodel", "some-provider")
    assert result == "mymodel"


def test_normalize_lm_model_id_https_base() -> None:
    result = audit._normalize_lm_model_id("mymodel", "https://api.example.com/v1")
    assert result == "openai/mymodel"


# --- _resolve_repo_path ---


def test_resolve_repo_path_blocks_escape(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    path = audit._resolve_repo_path(repo, "src/file.cs")
    assert path == repo / "src" / "file.cs"

    try:
        audit._resolve_repo_path(repo, "../etc/passwd")
        assert False, "expected ValueError for escaping repo root"
    except ValueError:
        pass


def test_resolve_repo_path_empty_raises(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(ValueError, match="cannot be empty"):
        audit._resolve_repo_path(repo, "")


def test_resolve_repo_path_absolute_raises(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(ValueError, match="must be repository-relative"):
        audit._resolve_repo_path(repo, "/etc/passwd")


def test_resolve_repo_path_dotslash_normalization(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    result = audit._resolve_repo_path(repo, "./src/file.py")
    assert result == (repo / "src" / "file.py").resolve()


def test_resolve_repo_path_deep_escape(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(ValueError, match="escapes source_root"):
        audit._resolve_repo_path(repo, "../../etc/passwd")


# --- _is_audit_file ---


def test_is_audit_file_by_extension_python() -> None:
    assert audit._is_audit_file(Path("views.py"), audit.PYTHON_PROFILE) is True


def test_is_audit_file_by_filename_python() -> None:
    assert audit._is_audit_file(Path("requirements.txt"), audit.PYTHON_PROFILE) is True


def test_is_audit_file_rejects_unknown_extension() -> None:
    assert audit._is_audit_file(Path("image.png"), audit.PYTHON_PROFILE) is False


def test_is_audit_file_case_insensitive_extension() -> None:
    assert audit._is_audit_file(Path("module.PY"), audit.PYTHON_PROFILE) is True


def test_is_audit_file_go_profile() -> None:
    assert audit._is_audit_file(Path("main.go"), audit.GO_PROFILE) is True
    assert audit._is_audit_file(Path("main.py"), audit.GO_PROFILE) is False


# --- _extension_priority ---


def test_extension_priority_known_ext() -> None:
    assert audit._extension_priority(".py", audit.PYTHON_PROFILE) == 10


def test_extension_priority_unknown_ext() -> None:
    assert audit._extension_priority(".xyz", audit.PYTHON_PROFILE) == 0


def test_extension_priority_case_insensitive() -> None:
    assert audit._extension_priority(".PY", audit.PYTHON_PROFILE) == 10


def test_extension_priority_go_profile() -> None:
    assert audit._extension_priority(".go", audit.GO_PROFILE) == 10
    assert audit._extension_priority(".tmpl", audit.GO_PROFILE) == 7


# --- _compile_pattern ---


def test_compile_pattern_returns_compiled_regex() -> None:
    audit._compile_pattern.cache_clear()
    pat = audit._compile_pattern("hello", False)
    assert isinstance(pat, re.Pattern)
    assert pat.search("hello world")


def test_compile_pattern_ignore_case_flag() -> None:
    audit._compile_pattern.cache_clear()
    pat = audit._compile_pattern("hello", True)
    assert pat.search("HELLO WORLD")


def test_compile_pattern_caching() -> None:
    audit._compile_pattern.cache_clear()
    pat1 = audit._compile_pattern("test", True)
    pat2 = audit._compile_pattern("test", True)
    assert pat1 is pat2
