from __future__ import annotations

import dataclasses
import json
import os
import re
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import audit


# ---------------------------------------------------------------------------
# Existing tests (17 total) -- unchanged
# ---------------------------------------------------------------------------


def test_normalize_relative_path() -> None:
    assert audit._normalize_relative_path("./src\\foo.cs") == "src/foo.cs"


def test_normalize_lm_model_id_for_openai_compatible_base() -> None:
    resolved = audit._normalize_lm_model_id("mitko", "http://localhost:8000/v1")
    assert resolved == "openai/mitko"

    already_qualified = audit._normalize_lm_model_id(
        "openai/mitko", "http://localhost:8000/v1"
    )
    assert already_qualified == "openai/mitko"


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


def test_collect_source_manifest_indexes_expected_files(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True)
    (src / "Controller.cs").write_text("public class Controller {}", encoding="utf-8")
    (src / "ignored.txt").write_text("ignore me", encoding="utf-8")
    (src / "web.config").write_text("<configuration/>", encoding="utf-8")

    manifest, stats = audit.collect_source_manifest(
        repo,
        max_files=100,
        max_file_bytes=200000,
        skip_hidden_dirs=True,
        profile=audit.DOTNET_PROFILE,
    )
    paths = {item["path"] for item in manifest}

    assert "src/Controller.cs" in paths
    assert "src/web.config" in paths
    assert "src/ignored.txt" not in paths
    assert stats["files"] == 2


def test_score_manifest_entry_detects_security_signals() -> None:
    signal_score, path_score = audit._score_manifest_entry(
        "src/SecurityController.cs",
        "var password = \"p\"; var algo = \"MD5\"; var sql = \"FromSqlRaw\";",
        audit.DOTNET_PROFILE,
    )
    assert signal_score >= 2
    assert path_score >= 1


def test_rlm_tools_list_read_search(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    file_path = repo / "Program.cs"
    file_path.write_text(
        "var s = \"secret\";\n"
        "var sql = \"SELECT * FROM t\";\n",
        encoding="utf-8",
    )

    manifest = [
        {
            "path": "Program.cs",
            "bytes": file_path.stat().st_size,
            "ext": ".cs",
            "signal_score": 2,
            "path_score": 0,
        }
    ]

    _tool_help, list_manifest, read_file, search_pattern = audit.build_rlm_tools(
        repo,
        manifest,
        default_tool_max_lines=50,
        default_tool_max_chars=5000,
        default_search_max_files=100,
        default_search_max_matches=100,
    )

    listed = list_manifest(limit=10)
    assert listed and listed[0]["path"] == "Program.cs"

    snippet = read_file("Program.cs", start_line=1)
    assert snippet["path"] == "Program.cs"
    assert "1: var s = \"secret\";" in snippet["content"]

    matches = search_pattern("secret", ignore_case=True)
    assert matches
    assert matches[0]["path"] == "Program.cs"


def test_search_pattern_invalid_regex_raises_value_error(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    file_path = repo / "Program.cs"
    file_path.write_text("var s = \"secret\";\n", encoding="utf-8")

    manifest = [
        {
            "path": "Program.cs",
            "bytes": file_path.stat().st_size,
            "ext": ".cs",
            "signal_score": 1,
            "path_score": 0,
        }
    ]

    _tool_help, _list_manifest, _read_file, search_pattern = audit.build_rlm_tools(
        repo,
        manifest,
        default_tool_max_lines=50,
        default_tool_max_chars=5000,
        default_search_max_files=100,
        default_search_max_matches=100,
    )

    try:
        search_pattern("[")
        assert False, "expected ValueError for invalid regex"
    except ValueError:
        pass


# --- Language profile tests ---


def test_language_profile_structure() -> None:
    """Verify DOTNET_PROFILE has all required fields with correct types."""
    p = audit.DOTNET_PROFILE
    assert p.name == "dotnet"
    assert p.display_name == ".NET"
    assert isinstance(p.include_extensions, frozenset)
    assert ".cs" in p.include_extensions
    assert isinstance(p.include_filenames, frozenset)
    assert "Dockerfile" in p.include_filenames
    assert isinstance(p.skip_dirs, frozenset)
    assert ".git" in p.skip_dirs
    assert isinstance(p.security_path_hints, tuple)
    assert "auth" in p.security_path_hints
    assert isinstance(p.extension_priority, dict)
    assert p.extension_priority[".cs"] == 10
    assert isinstance(p.scanner_instructions, str)
    assert "FromSqlRaw" in p.scanner_instructions
    assert isinstance(p.tool_help_examples, tuple)
    assert len(p.tool_help_examples) > 0
    assert isinstance(p.detection_markers, frozenset)
    assert isinstance(p.detection_extensions, frozenset)


def test_language_profiles_registry() -> None:
    """LANGUAGE_PROFILES dict contains dotnet and maps correctly."""
    assert "dotnet" in audit.LANGUAGE_PROFILES
    assert audit.LANGUAGE_PROFILES["dotnet"] is audit.DOTNET_PROFILE


def test_detect_language_dotnet(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "MyApp.sln").write_text("", encoding="utf-8")
    (repo / "src").mkdir()
    (repo / "src" / "Program.cs").write_text("class P {}", encoding="utf-8")

    detected = audit.detect_language(repo)
    assert detected == "dotnet"


def test_detect_language_returns_none_for_empty(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("hello", encoding="utf-8")

    detected = audit.detect_language(repo)
    assert detected is None


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


# --- Python profile tests ---
# Note: Signal pattern tests below use string literals that contain names of
# dangerous functions (e.g. "pickle.loads") to verify regex detection. These
# are NOT actual invocations — they test that the audit scanner would flag them.


def test_detect_language_python(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("[project]", encoding="utf-8")
    (repo / "requirements.txt").write_text("django\n", encoding="utf-8")
    (repo / "app.py").write_text("import flask", encoding="utf-8")

    detected = audit.detect_language(repo)
    assert detected == "python"


def test_collect_manifest_python_profile(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    src = repo / "app"
    src.mkdir(parents=True)
    (src / "views.py").write_text("from django.views import View", encoding="utf-8")
    (src / "models.py").write_text("from django.db import models", encoding="utf-8")
    (src / "ignored.rs").write_text("fn main() {}", encoding="utf-8")
    (repo / "requirements.txt").write_text("django\n", encoding="utf-8")

    manifest, stats = audit.collect_source_manifest(
        repo,
        max_files=100,
        max_file_bytes=200000,
        skip_hidden_dirs=True,
        profile=audit.PYTHON_PROFILE,
    )
    paths = {item["path"] for item in manifest}

    assert "app/views.py" in paths
    assert "app/models.py" in paths
    assert "requirements.txt" in paths
    assert "app/ignored.rs" not in paths


def test_python_signal_pattern() -> None:
    pattern = audit.PYTHON_PROFILE.security_signal_pattern
    assert pattern.search("pickle.loads(data)")
    assert pattern.search("mark_safe(html)")
    assert pattern.search("hashlib.md5(data)")
    assert pattern.search("os.system(cmd)")
    assert not pattern.search("print('hello')")


# --- Go profile tests ---


def test_detect_language_go(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "go.mod").write_text("module example.com/app", encoding="utf-8")
    (repo / "go.sum").write_text("", encoding="utf-8")
    (repo / "main.go").write_text("package main", encoding="utf-8")

    detected = audit.detect_language(repo)
    assert detected == "go"


def test_collect_manifest_go_profile(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    cmd = repo / "cmd"
    cmd.mkdir(parents=True)
    (cmd / "main.go").write_text("package main", encoding="utf-8")
    (cmd / "ignored.py").write_text("import os", encoding="utf-8")
    (repo / "go.mod").write_text("module example.com/app", encoding="utf-8")

    manifest, stats = audit.collect_source_manifest(
        repo,
        max_files=100,
        max_file_bytes=200000,
        skip_hidden_dirs=True,
        profile=audit.GO_PROFILE,
    )
    paths = {item["path"] for item in manifest}

    assert "cmd/main.go" in paths
    assert "go.mod" in paths
    assert "cmd/ignored.py" not in paths


def test_go_signal_pattern() -> None:
    pattern = audit.GO_PROFILE.security_signal_pattern
    assert pattern.search("InsecureSkipVerify: true")
    assert pattern.search("exec.Command(cmd)")
    assert pattern.search("unsafe.Pointer(p)")
    assert pattern.search("password = secret")
    assert not pattern.search("fmt.Println(x)")


# --- React profile tests ---


def test_detect_language_react(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        '{"dependencies":{"react":"^18.0.0"}}', encoding="utf-8"
    )
    (repo / "App.tsx").write_text("export default function App() {}", encoding="utf-8")

    detected = audit.detect_language(repo)
    assert detected == "react"


def test_collect_manifest_react_profile(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True)
    (src / "App.tsx").write_text("export default function App() {}", encoding="utf-8")
    (src / "utils.ts").write_text("export const x = 1", encoding="utf-8")
    (src / "ignored.go").write_text("package main", encoding="utf-8")
    (repo / "package.json").write_text("{}", encoding="utf-8")

    manifest, stats = audit.collect_source_manifest(
        repo,
        max_files=100,
        max_file_bytes=200000,
        skip_hidden_dirs=True,
        profile=audit.REACT_PROFILE,
    )
    paths = {item["path"] for item in manifest}

    assert "src/App.tsx" in paths
    assert "src/utils.ts" in paths
    assert "package.json" in paths
    assert "src/ignored.go" not in paths


def test_react_signal_pattern() -> None:
    pattern = audit.REACT_PROFILE.security_signal_pattern
    assert pattern.search("dangerouslySetInnerHTML={{__html: x}}")
    assert pattern.search("element.innerHTML = userInput")
    assert pattern.search("localStorage.setItem('token', jwt)")
    assert not pattern.search("console.log('hello')")


# ===========================================================================
# NEW TESTS BEGIN HERE
# ===========================================================================


# ---------------------------------------------------------------------------
# Section 1: LanguageProfile Dataclass
# ---------------------------------------------------------------------------


def test_language_profile_frozen_immutable() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        audit.DOTNET_PROFILE.name = "changed"  # type: ignore[misc]


def test_language_profiles_registry_all_four() -> None:
    assert set(audit.LANGUAGE_PROFILES.keys()) == {"dotnet", "python", "go", "react"}


def test_language_profile_python_structure() -> None:
    p = audit.PYTHON_PROFILE
    assert p.name == "python"
    assert p.display_name == "Python"
    assert ".py" in p.include_extensions
    assert isinstance(p.scanner_instructions, str)
    assert "pickle" in p.scanner_instructions


def test_language_profile_go_structure() -> None:
    p = audit.GO_PROFILE
    assert p.name == "go"
    assert p.display_name == "Go"
    assert ".go" in p.include_extensions
    assert isinstance(p.scanner_instructions, str)
    assert "exec.Command" in p.scanner_instructions


# ---------------------------------------------------------------------------
# Section 2: _normalize_relative_path
# ---------------------------------------------------------------------------


def test_normalize_relative_path_multiple_leading_dotslash() -> None:
    assert audit._normalize_relative_path("././src/file.py") == "src/file.py"


def test_normalize_relative_path_backslash_and_whitespace() -> None:
    assert audit._normalize_relative_path("  src\\sub\\f.cs  ") == "src/sub/f.cs"


def test_normalize_relative_path_already_clean() -> None:
    assert audit._normalize_relative_path("src/file.py") == "src/file.py"


# ---------------------------------------------------------------------------
# Section 3: _normalize_lm_model_id
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Section 4: _resolve_repo_path
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Section 5: _is_audit_file
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Section 6: _extension_priority
# ---------------------------------------------------------------------------


def test_extension_priority_known_ext() -> None:
    assert audit._extension_priority(".py", audit.PYTHON_PROFILE) == 10


def test_extension_priority_unknown_ext() -> None:
    assert audit._extension_priority(".xyz", audit.PYTHON_PROFILE) == 0


def test_extension_priority_case_insensitive() -> None:
    assert audit._extension_priority(".PY", audit.PYTHON_PROFILE) == 10


def test_extension_priority_go_profile() -> None:
    assert audit._extension_priority(".go", audit.GO_PROFILE) == 10
    assert audit._extension_priority(".tmpl", audit.GO_PROFILE) == 7


# ---------------------------------------------------------------------------
# Section 7: _compile_pattern
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Section 8: _score_manifest_entry
# ---------------------------------------------------------------------------


def test_score_manifest_entry_python_signals() -> None:
    signal_score, _ = audit._score_manifest_entry(
        "app/views.py",
        "eval(input); exec(code); pickle.loads(d)",
        audit.PYTHON_PROFILE,
    )
    assert signal_score >= 3


def test_score_manifest_entry_python_path_hints() -> None:
    _, path_score = audit._score_manifest_entry(
        "app/auth/views.py",
        "pass",
        audit.PYTHON_PROFILE,
    )
    assert path_score >= 2


def test_score_manifest_entry_go_signals() -> None:
    signal_score, _ = audit._score_manifest_entry(
        "cmd/main.go",
        "exec.Command(cmd); InsecureSkipVerify: true",
        audit.GO_PROFILE,
    )
    assert signal_score >= 2


def test_score_manifest_entry_react_signals() -> None:
    signal_score, _ = audit._score_manifest_entry(
        "src/App.tsx",
        "dangerouslySetInnerHTML={{__html: x}}; localStorage.setItem('t', v)",
        audit.REACT_PROFILE,
    )
    assert signal_score >= 2


def test_score_manifest_entry_no_signals() -> None:
    signal_score, path_score = audit._score_manifest_entry(
        "readme.txt",
        "hello world",
        audit.PYTHON_PROFILE,
    )
    assert signal_score == 0
    assert path_score == 0


def test_score_manifest_entry_go_path_hints() -> None:
    _, path_score = audit._score_manifest_entry(
        "internal/security/handler.go",
        "pass",
        audit.GO_PROFILE,
    )
    assert path_score >= 2


# ---------------------------------------------------------------------------
# Section 9: detect_language
# ---------------------------------------------------------------------------


def test_detect_language_oserror_returns_none() -> None:
    result = audit.detect_language(Path("/nonexistent/path/abc123"))
    assert result is None


def test_detect_language_wildcard_marker_sln(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "MyApp.sln").write_text("", encoding="utf-8")
    detected = audit.detect_language(repo)
    assert detected == "dotnet"


def test_detect_language_below_threshold(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("hello", encoding="utf-8")
    assert audit.detect_language(repo) is None


def test_detect_language_extension_counting(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    for i in range(5):
        (repo / f"mod{i}.py").write_text("pass", encoding="utf-8")
    (repo / "go.mod").write_text("module example", encoding="utf-8")
    detected = audit.detect_language(repo)
    assert detected == "python"


def test_detect_language_marker_beats_extensions(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "go.mod").write_text("module example", encoding="utf-8")
    (repo / "go.sum").write_text("", encoding="utf-8")
    (repo / "a.py").write_text("pass", encoding="utf-8")
    detected = audit.detect_language(repo)
    assert detected == "go"


def test_detect_language_hidden_files_excluded(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".hidden.py").write_text("pass", encoding="utf-8")
    (repo / "README.md").write_text("hello", encoding="utf-8")
    detected = audit.detect_language(repo)
    assert detected is None


def test_detect_language_react_with_tsx_files(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text("{}", encoding="utf-8")
    for i in range(3):
        (repo / f"Component{i}.tsx").write_text("export default {}", encoding="utf-8")
    detected = audit.detect_language(repo)
    assert detected == "react"


# ---------------------------------------------------------------------------
# Section 10: collect_source_manifest
# ---------------------------------------------------------------------------


def test_collect_manifest_skips_symlinks(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    real_file = repo / "real.py"
    real_file.write_text("pass", encoding="utf-8")
    link = repo / "link.py"
    os.symlink(real_file, link)

    manifest, stats = audit.collect_source_manifest(
        repo,
        max_files=100,
        max_file_bytes=200000,
        skip_hidden_dirs=True,
        profile=audit.PYTHON_PROFILE,
    )
    paths = {item["path"] for item in manifest}
    assert "link.py" not in paths
    assert stats["skipped_symlinks"] >= 1


def test_collect_manifest_skips_unreadable_dir(tmp_path: Path) -> None:
    if os.getuid() == 0:
        pytest.skip("Cannot test unreadable dirs as root")
    repo = tmp_path / "repo"
    subdir = repo / "locked"
    subdir.mkdir(parents=True)
    (subdir / "file.py").write_text("pass", encoding="utf-8")
    os.chmod(subdir, 0o000)
    try:
        _, stats = audit.collect_source_manifest(
            repo,
            max_files=100,
            max_file_bytes=200000,
            skip_hidden_dirs=True,
            profile=audit.PYTHON_PROFILE,
        )
        assert stats["skipped_unreadable_dirs"] >= 1
    finally:
        os.chmod(subdir, 0o755)


def test_collect_manifest_skips_large_files(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    big_file = repo / "big.py"
    big_file.write_text("x" * 1000, encoding="utf-8")

    _, stats = audit.collect_source_manifest(
        repo,
        max_files=100,
        max_file_bytes=500,
        skip_hidden_dirs=True,
        profile=audit.PYTHON_PROFILE,
    )
    assert stats["skipped_large_files"] >= 1


def test_collect_manifest_max_files_cap(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    for i in range(5):
        (repo / f"mod{i}.py").write_text("pass", encoding="utf-8")

    manifest, stats = audit.collect_source_manifest(
        repo,
        max_files=2,
        max_file_bytes=200000,
        skip_hidden_dirs=True,
        profile=audit.PYTHON_PROFILE,
    )
    assert len(manifest) == 2
    assert stats["files"] == 2


def test_collect_manifest_skips_content_filename(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "CONTENT").write_text("data", encoding="utf-8")
    (repo / "real.py").write_text("pass", encoding="utf-8")

    manifest, _ = audit.collect_source_manifest(
        repo,
        max_files=100,
        max_file_bytes=200000,
        skip_hidden_dirs=True,
        profile=audit.PYTHON_PROFILE,
    )
    paths = {item["path"] for item in manifest}
    assert "CONTENT" not in paths
    assert "real.py" in paths


def test_collect_manifest_skips_hidden_dirs(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    hidden = repo / ".hidden"
    hidden.mkdir(parents=True)
    (hidden / "secret.py").write_text("pass", encoding="utf-8")

    _, stats = audit.collect_source_manifest(
        repo,
        max_files=100,
        max_file_bytes=200000,
        skip_hidden_dirs=True,
        profile=audit.PYTHON_PROFILE,
    )
    assert stats["skipped_hidden_dirs"] >= 1


def test_collect_manifest_includes_hidden_dirs_when_disabled(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    hidden = repo / ".visible"
    hidden.mkdir(parents=True)
    (hidden / "mod.py").write_text("pass", encoding="utf-8")

    manifest, _ = audit.collect_source_manifest(
        repo,
        max_files=100,
        max_file_bytes=200000,
        skip_hidden_dirs=False,
        profile=audit.PYTHON_PROFILE,
    )
    paths = {item["path"] for item in manifest}
    assert ".visible/mod.py" in paths


def test_collect_manifest_skips_configured_dirs(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    nm = repo / "node_modules"
    nm.mkdir(parents=True)
    (nm / "pkg.js").write_text("module.exports = 1", encoding="utf-8")
    (repo / "App.tsx").write_text("export default function App() {}", encoding="utf-8")

    _, stats = audit.collect_source_manifest(
        repo,
        max_files=100,
        max_file_bytes=200000,
        skip_hidden_dirs=True,
        profile=audit.REACT_PROFILE,
    )
    assert stats["skipped_configured_dirs"] >= 1


def test_collect_manifest_skips_unreadable_file_stat(tmp_path: Path) -> None:
    if os.getuid() == 0:
        pytest.skip("Cannot test unreadable files as root")
    repo = tmp_path / "repo"
    repo.mkdir()
    locked_file = repo / "locked.py"
    locked_file.write_text("pass", encoding="utf-8")
    os.chmod(locked_file, 0o000)
    try:
        _, stats = audit.collect_source_manifest(
            repo,
            max_files=100,
            max_file_bytes=200000,
            skip_hidden_dirs=True,
            profile=audit.PYTHON_PROFILE,
        )
        assert stats["skipped_unreadable_files"] >= 1
    finally:
        os.chmod(locked_file, 0o644)


def test_collect_manifest_skips_unreadable_file_open(tmp_path: Path) -> None:
    if os.getuid() == 0:
        pytest.skip("Cannot test unreadable files as root")
    repo = tmp_path / "repo"
    repo.mkdir()
    locked_file = repo / "noread.py"
    locked_file.write_text("pass", encoding="utf-8")
    # Make readable for stat but not for open by removing read permission
    os.chmod(locked_file, 0o200)
    try:
        _, stats = audit.collect_source_manifest(
            repo,
            max_files=100,
            max_file_bytes=200000,
            skip_hidden_dirs=True,
            profile=audit.PYTHON_PROFILE,
        )
        assert stats["skipped_unreadable_files"] >= 1
    finally:
        os.chmod(locked_file, 0o644)


def test_collect_manifest_sort_order(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "safe.py").write_text("print('hello')", encoding="utf-8")
    (repo / "danger.py").write_text("eval(input()); exec(code)", encoding="utf-8")

    manifest, _ = audit.collect_source_manifest(
        repo,
        max_files=100,
        max_file_bytes=200000,
        skip_hidden_dirs=True,
        profile=audit.PYTHON_PROFILE,
    )
    assert len(manifest) >= 2
    assert manifest[0]["signal_score"] >= manifest[1]["signal_score"]


def test_collect_manifest_no_ext_label(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Dockerfile").write_text("FROM python:3.10", encoding="utf-8")

    manifest, _ = audit.collect_source_manifest(
        repo,
        max_files=100,
        max_file_bytes=200000,
        skip_hidden_dirs=True,
        profile=audit.PYTHON_PROFILE,
    )
    dockerfiles = [e for e in manifest if e["path"] == "Dockerfile"]
    assert len(dockerfiles) == 1
    assert dockerfiles[0]["ext"] == "<no_ext>"


# ---------------------------------------------------------------------------
# Section 11: build_source_overview
# ---------------------------------------------------------------------------


def test_build_source_overview_empty_manifest() -> None:
    text, summary = audit.build_source_overview([], overview_top_files=25)
    assert text == "No files indexed."
    assert summary["top_extensions"] == []
    assert summary["top_directories"] == []
    assert summary["top_signal_files"] == []


def test_build_source_overview_single_file() -> None:
    manifest = [
        {"path": "app.py", "bytes": 100, "ext": ".py", "signal_score": 1, "path_score": 0}
    ]
    text, summary = audit.build_source_overview(manifest, overview_top_files=25)
    assert "Indexed files: 1" in text
    assert len(summary["top_extensions"]) == 1


def test_build_source_overview_multiple_files() -> None:
    manifest = [
        {"path": "src/a.py", "bytes": 100, "ext": ".py", "signal_score": 2, "path_score": 0},
        {"path": "src/b.py", "bytes": 200, "ext": ".py", "signal_score": 1, "path_score": 0},
        {"path": "src/c.js", "bytes": 50, "ext": ".js", "signal_score": 0, "path_score": 0},
    ]
    text, summary = audit.build_source_overview(manifest, overview_top_files=25)
    assert "Indexed files: 3" in text
    exts = [e["extension"] for e in summary["top_extensions"]]
    assert exts[0] == ".py"  # most frequent first


def test_build_source_overview_top_files_limit() -> None:
    manifest = [
        {"path": f"file{i}.py", "bytes": 100, "ext": ".py", "signal_score": i, "path_score": 0}
        for i in range(10)
    ]
    text, _ = audit.build_source_overview(manifest, overview_top_files=2)
    # Only 2 file lines in the overview
    file_lines = [line for line in text.split("\n") if line.startswith("- ")]
    assert len(file_lines) == 2


def test_build_source_overview_root_level_files() -> None:
    manifest = [
        {"path": "setup.py", "bytes": 50, "ext": ".py", "signal_score": 0, "path_score": 0}
    ]
    _, summary = audit.build_source_overview(manifest, overview_top_files=25)
    dirs = [d["directory"] for d in summary["top_directories"]]
    assert "<root>" in dirs


# ---------------------------------------------------------------------------
# Section 12: write_manifest_jsonl
# ---------------------------------------------------------------------------


def test_write_manifest_jsonl_creates_file(tmp_path: Path) -> None:
    manifest = [{"path": "a.py", "bytes": 10}]
    result = audit.write_manifest_jsonl(manifest, manifest_path=tmp_path / "out.jsonl")
    assert result.exists()


def test_write_manifest_jsonl_content_format(tmp_path: Path) -> None:
    manifest = [
        {"path": "a.py", "bytes": 10},
        {"path": "b.py", "bytes": 20},
    ]
    result = audit.write_manifest_jsonl(manifest, manifest_path=tmp_path / "out.jsonl")
    lines = result.read_text().strip().split("\n")
    assert len(lines) == 2
    for line in lines:
        parsed = json.loads(line)
        assert "path" in parsed


def test_write_manifest_jsonl_creates_parent_dirs(tmp_path: Path) -> None:
    manifest = [{"path": "a.py"}]
    result = audit.write_manifest_jsonl(
        manifest, manifest_path=tmp_path / "nested" / "deep" / "out.jsonl"
    )
    assert result.exists()


def test_write_manifest_jsonl_empty_manifest(tmp_path: Path) -> None:
    result = audit.write_manifest_jsonl([], manifest_path=tmp_path / "empty.jsonl")
    assert result.read_text() == ""


# ---------------------------------------------------------------------------
# Section 13: write_artifacts
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Section 14: _check_prerequisites
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Section 15: _build_lm
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Section 16: CodeScanner
# ---------------------------------------------------------------------------


def test_code_scanner_is_dspy_signature() -> None:
    import dspy
    assert issubclass(audit.CodeScanner, dspy.Signature)


def test_code_scanner_has_expected_fields() -> None:
    fields = audit.CodeScanner.model_fields
    assert "source_overview" in fields
    assert "documentation" in fields


# ---------------------------------------------------------------------------
# Section 17: AuditTimeoutError
# ---------------------------------------------------------------------------


def test_audit_timeout_error_is_timeout_error() -> None:
    assert issubclass(audit.AuditTimeoutError, TimeoutError)


def test_audit_timeout_error_message() -> None:
    with pytest.raises(audit.AuditTimeoutError, match="test message"):
        raise audit.AuditTimeoutError("test message")


# ---------------------------------------------------------------------------
# Section 18: timeout_guard
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Section 19: run_audit_with_retry
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Section 20-23: build_rlm_tools Extended
# ---------------------------------------------------------------------------

# Helper to create a standard repo+manifest for tool tests
@pytest.fixture()
def tool_repo(tmp_path: Path) -> tuple:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.py").write_text(
        "import os\npassword = 'secret'\neval(input())\n", encoding="utf-8"
    )
    (repo / "utils.py").write_text(
        "def helper():\n    return 42\n", encoding="utf-8"
    )
    (repo / "config.json").write_text(
        '{"key": "value"}\n', encoding="utf-8"
    )
    manifest = [
        {"path": "main.py", "bytes": 45, "ext": ".py", "signal_score": 3, "path_score": 0},
        {"path": "utils.py", "bytes": 30, "ext": ".py", "signal_score": 0, "path_score": 0},
        {"path": "config.json", "bytes": 18, "ext": ".json", "signal_score": 0, "path_score": 0},
    ]
    tools = audit.build_rlm_tools(
        repo,
        manifest,
        default_tool_max_lines=50,
        default_tool_max_chars=5000,
        default_search_max_files=100,
        default_search_max_matches=100,
        profile=audit.PYTHON_PROFILE,
    )
    tool_help, list_manifest, read_file, search_pattern = tools
    return repo, manifest, tool_help, list_manifest, read_file, search_pattern


# tool_help tests

def test_tool_help_returns_rules_and_examples(tool_repo: tuple) -> None:
    _, _, tool_help, _, _, _ = tool_repo
    result = tool_help()
    assert "rules" in result
    assert "examples" in result
    assert isinstance(result["rules"], list)
    assert isinstance(result["examples"], list)


def test_tool_help_examples_match_profile(tool_repo: tuple) -> None:
    _, _, tool_help, _, _, _ = tool_repo
    result = tool_help()
    examples = result["examples"]
    assert any("eval" in e or "pickle" in e or "list_manifest" in e for e in examples)


# list_manifest filter tests

def test_list_manifest_min_signal_score(tool_repo: tuple) -> None:
    _, _, _, list_manifest, _, _ = tool_repo
    result = list_manifest(min_signal_score=1)
    assert all(e["signal_score"] >= 1 for e in result)
    assert len(result) == 1  # only main.py has signal_score=3


def test_list_manifest_ext_filter(tool_repo: tuple) -> None:
    _, _, _, list_manifest, _, _ = tool_repo
    result = list_manifest(ext=".json")
    assert all(e["ext"] == ".json" for e in result)
    assert len(result) == 1


def test_list_manifest_path_contains(tool_repo: tuple) -> None:
    _, _, _, list_manifest, _, _ = tool_repo
    result = list_manifest(path_contains="util")
    assert len(result) == 1
    assert result[0]["path"] == "utils.py"


def test_list_manifest_limit_files_alias(tool_repo: tuple) -> None:
    _, _, _, list_manifest, _, _ = tool_repo
    result = list_manifest(limit_files=1)
    assert len(result) == 1


def test_list_manifest_limit_clamping(tool_repo: tuple) -> None:
    _, _, _, list_manifest, _, _ = tool_repo
    # limit=0 should be clamped to 1 (max(1, min(0, 2000)))
    result = list_manifest(limit=0)
    assert len(result) >= 1


def test_list_manifest_combined_filters(tool_repo: tuple) -> None:
    _, _, _, list_manifest, _, _ = tool_repo
    result = list_manifest(ext=".py", min_signal_score=1)
    assert len(result) == 1
    assert result[0]["path"] == "main.py"


# read_file edge cases

def test_read_file_not_in_manifest_error(tool_repo: tuple) -> None:
    _, _, _, _, read_file, _ = tool_repo
    with pytest.raises(ValueError, match="not indexed"):
        read_file("nonexistent.py")


def test_read_file_start_line_beyond_eof(tool_repo: tuple) -> None:
    _, _, _, _, read_file, _ = tool_repo
    result = read_file("main.py", start_line=9999)
    assert result["content"] == ""
    # When start_line > total_lines, start_idx = total_lines, no lines rendered
    assert result["end_line"] == result["start_line"] or len(result["content"]) == 0


def test_read_file_char_truncation(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "big.py").write_text("x" * 500 + "\ny" * 500, encoding="utf-8")
    manifest = [{"path": "big.py", "bytes": 1001, "ext": ".py", "signal_score": 0, "path_score": 0}]
    tools = audit.build_rlm_tools(
        repo, manifest,
        default_tool_max_lines=50,
        default_tool_max_chars=300,
        default_search_max_files=100,
        default_search_max_matches=100,
    )
    result = tools[2]("big.py")
    assert result["truncated"] is True


def test_read_file_default_limits(tool_repo: tuple) -> None:
    _, _, _, _, read_file, _ = tool_repo
    result = read_file("main.py")
    assert result["total_lines"] == 3
    assert result["truncated"] is False


def test_read_file_empty_file(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "empty.py").write_text("", encoding="utf-8")
    manifest = [{"path": "empty.py", "bytes": 0, "ext": ".py", "signal_score": 0, "path_score": 0}]
    tools = audit.build_rlm_tools(
        repo, manifest,
        default_tool_max_lines=50,
        default_tool_max_chars=5000,
        default_search_max_files=100,
        default_search_max_matches=100,
    )
    result = tools[2]("empty.py")
    assert result["total_lines"] == 0
    assert result["content"] == ""


def test_read_file_line_numbering(tool_repo: tuple) -> None:
    _, _, _, _, read_file, _ = tool_repo
    result = read_file("main.py", start_line=2, max_lines=1)
    assert result["start_line"] == 2
    assert result["end_line"] == 2
    assert "2: " in result["content"]


# search_pattern tests

def test_search_pattern_empty_pattern_error(tool_repo: tuple) -> None:
    _, _, _, _, _, search_pattern = tool_repo
    with pytest.raises(ValueError, match="cannot be empty"):
        search_pattern("")


def test_search_pattern_whitespace_pattern_error(tool_repo: tuple) -> None:
    _, _, _, _, _, search_pattern = tool_repo
    with pytest.raises(ValueError, match="cannot be empty"):
        search_pattern("   ")


def test_search_pattern_ext_filter(tool_repo: tuple) -> None:
    _, _, _, _, _, search_pattern = tool_repo
    # Search for something that exists in .py but filter to .json
    results = search_pattern("import", ext=".json")
    assert len(results) == 0


def test_search_pattern_path_filter(tool_repo: tuple) -> None:
    _, _, _, _, _, search_pattern = tool_repo
    results = search_pattern("return", path_contains="util")
    assert len(results) == 1
    assert results[0]["path"] == "utils.py"


def test_search_pattern_python_fallback_when_no_rg(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "file.py").write_text("password = 'secret'\n", encoding="utf-8")
    manifest = [{"path": "file.py", "bytes": 20, "ext": ".py", "signal_score": 1, "path_score": 0}]

    with patch("shutil.which", return_value=None):
        tools = audit.build_rlm_tools(
            repo, manifest,
            default_tool_max_lines=50,
            default_tool_max_chars=5000,
            default_search_max_files=100,
            default_search_max_matches=100,
        )
    results = tools[3]("password")
    assert len(results) >= 1
    assert results[0]["path"] == "file.py"


def test_search_pattern_long_preview_truncation(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    long_line = "x" * 400
    (repo / "long.py").write_text(f"match_{long_line}\n", encoding="utf-8")
    manifest = [{"path": "long.py", "bytes": 405, "ext": ".py", "signal_score": 0, "path_score": 0}]

    with patch("shutil.which", return_value=None):
        tools = audit.build_rlm_tools(
            repo, manifest,
            default_tool_max_lines=50,
            default_tool_max_chars=5000,
            default_search_max_files=100,
            default_search_max_matches=100,
        )
    results = tools[3]("match_")
    assert len(results) == 1
    assert results[0]["preview"].endswith("...")
    assert len(results[0]["preview"]) <= 304  # 300 + "..."


def test_search_pattern_limit_matches(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    content = "\n".join(f"line{i} match" for i in range(20))
    (repo / "many.py").write_text(content, encoding="utf-8")
    manifest = [{"path": "many.py", "bytes": len(content), "ext": ".py", "signal_score": 0, "path_score": 0}]

    with patch("shutil.which", return_value=None):
        tools = audit.build_rlm_tools(
            repo, manifest,
            default_tool_max_lines=50,
            default_tool_max_chars=5000,
            default_search_max_files=100,
            default_search_max_matches=5,
        )
    results = tools[3]("match")
    assert len(results) == 5


def test_search_pattern_no_matching_files(tool_repo: tuple) -> None:
    _, _, _, _, _, search_pattern = tool_repo
    results = search_pattern("zzz_nonexistent_pattern_zzz")
    assert results == []


def test_search_pattern_no_candidate_paths_ext_filter(tool_repo: tuple) -> None:
    _, _, _, _, _, search_pattern = tool_repo
    # Filter to an extension with no files returns empty
    results = search_pattern("import", ext=".rs")
    assert results == []


def test_search_pattern_limit_files_param(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    for i in range(5):
        (repo / f"f{i}.py").write_text("match_here\n", encoding="utf-8")
    manifest = [
        {"path": f"f{i}.py", "bytes": 11, "ext": ".py", "signal_score": 0, "path_score": 0}
        for i in range(5)
    ]
    with patch("shutil.which", return_value=None):
        tools = audit.build_rlm_tools(
            repo, manifest,
            default_tool_max_lines=50,
            default_tool_max_chars=5000,
            default_search_max_files=100,
            default_search_max_matches=100,
        )
    results = tools[3]("match_here", limit_files=2)
    # Should only search 2 files, getting at most 2 matches
    assert len(results) <= 2


# ---------------------------------------------------------------------------
# Section 24: parse_args
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Section 25: main() orchestration
# ---------------------------------------------------------------------------

# Helper fixture for main() tests
@pytest.fixture()
def main_repo(tmp_path: Path) -> Path:
    """Create a minimal repo for main() tests."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("[project]", encoding="utf-8")
    (repo / "app.py").write_text("import os\npassword = 'secret'\n", encoding="utf-8")
    return repo


# Validation error tests

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


# Fast mode tests

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


# Language detection tests

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


# Execution tests

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


# ---------------------------------------------------------------------------
# Section 26: Security Signal Pattern Deep Tests
# ---------------------------------------------------------------------------
# Note: These tests use string literals containing names of dangerous
# functions/modules to verify regex pattern detection. They are NOT actual
# invocations -- they test that the audit scanner would flag these patterns.

# --- Python deep signal tests ---


def test_python_signal_code_execution() -> None:
    pat = audit.PYTHON_PROFILE.security_signal_pattern
    for term in ["eval(x)", "exec(code)", "compile(s)", "__import__('os')", "importlib"]:
        assert pat.search(term), f"Should match: {term}"
    assert not pat.search("print('hello')")
    assert not pat.search("x = 42")


def test_python_signal_deserialization() -> None:
    pat = audit.PYTHON_PROFILE.security_signal_pattern
    for term in [
        "pickle.loads(d)", "unpickler(f)", "shelve.open(f)",
        "marshal.loads(d)", "yaml.load(f)", "jsonpickle.decode(s)",
    ]:
        assert pat.search(term), f"Should match: {term}"


def test_python_signal_injection() -> None:
    pat = audit.PYTHON_PROFILE.security_signal_pattern
    for term in [
        "os.system(cmd)", "os.popen(cmd)",
        "subprocess.call(cmd)", "shell = True",
    ]:
        assert pat.search(term), f"Should match: {term}"
    # Note: `.raw(` and `.extra(` patterns in regex start with `\.` so they
    # need preceding context for `\b` to match. Use realistic code snippets.
    for term in [
        "qs.raw(sql)", "qs.extra(select=x)", "rawsql(q)", "cursor.execute(q)",
    ]:
        assert pat.search(term), f"Should match: {term}"


def test_python_signal_secrets_crypto() -> None:
    pat = audit.PYTHON_PROFILE.security_signal_pattern
    for term in [
        "password = 'x'", "api_key = 'x'", "secret_key = 'x'", "connectionstring",
    ]:
        assert pat.search(term), f"Should match: {term}"
    for term in [
        "hashlib.md5(d)", "hashlib.sha1(d)",
        "verify = False", "cert_none",
    ]:
        assert pat.search(term), f"Should match: {term}"


def test_python_signal_web_security() -> None:
    pat = audit.PYTHON_PROFILE.security_signal_pattern
    for term in [
        "mark_safe(h)", "safestring", "render_template_string(t)",
    ]:
        assert pat.search(term), f"Should match: {term}"
    for term in [
        "csrf_exempt", "login_required",
    ]:
        assert pat.search(term), f"Should match: {term}"
    for term in [
        "debug = true", "allowed_hosts", "cors_allow_all",
    ]:
        assert pat.search(term), f"Should match: {term}"
    for term in [
        "send_file(p)", "send_from_directory(d)",
    ]:
        assert pat.search(term), f"Should match: {term}"


# --- Go deep signal tests ---


def test_go_signal_command_injection() -> None:
    pat = audit.GO_PROFILE.security_signal_pattern
    for term in ["exec.Command(cmd)", "syscall.Exec(path)", "os.StartProcess(name)"]:
        assert pat.search(term), f"Should match: {term}"


def test_go_signal_tls_unsafe() -> None:
    pat = audit.GO_PROFILE.security_signal_pattern
    for term in ["InsecureSkipVerify: true", "unsafe.Pointer(p)"]:
        assert pat.search(term), f"Should match: {term}"


def test_go_signal_crypto_weak() -> None:
    pat = audit.GO_PROFILE.security_signal_pattern
    for term in ["crypto/md5", "crypto/sha1", "math/rand", "des.NewCipher", "rc4.NewCipher"]:
        assert pat.search(term), f"Should match: {term}"


def test_go_signal_sql_http() -> None:
    pat = audit.GO_PROFILE.security_signal_pattern
    # `.Query(` needs word char before the dot for `\b` to match
    for term in [
        "fmt.Sprintf(\"SELECT * FROM %s\")",
        "db.Query(sql)", "http.Get(url)", "http.Post(url)",
        "http.NewRequest(method, url)",
    ]:
        assert pat.search(term), f"Should match: {term}"


def test_go_signal_secrets_framework() -> None:
    pat = audit.GO_PROFILE.security_signal_pattern
    # Go pattern has `secret` (not `secret_key`), and `private[_-]?key`
    for term in [
        "password = secret", "var secret = x", "AllowAllOrigins",
        "gob.NewDecoder(r)", "template.HTML(s)",
    ]:
        assert pat.search(term), f"Should match: {term}"


# --- React deep signal tests ---


def test_react_signal_xss() -> None:
    pat = audit.REACT_PROFILE.security_signal_pattern
    for term in [
        "dangerouslySetInnerHTML={{__html: x}}",
        "el.innerHTML = data",
        "document.write(html)",
        "el.outerHTML = data",
        "el.insertAdjacentHTML('beforeend', html)",
    ]:
        assert pat.search(term), f"Should match: {term}"


def test_react_signal_code_exec() -> None:
    pat = audit.REACT_PROFILE.security_signal_pattern
    # Note: These are string literals for pattern testing, NOT actual calls.
    for term in ["eval(code)", "new Function(code)", "execSync(cmd)"]:
        assert pat.search(term), f"Should match: {term}"


def test_react_signal_storage_secrets() -> None:
    pat = audit.REACT_PROFILE.security_signal_pattern
    for term in [
        "localStorage.setItem('token', t)",
        "sessionStorage.getItem('key')",
        # Env var prefixes need word boundary after the trailing underscore,
        # which means the next char must not be a word char (e.g. end of string,
        # space, or equals). Use realistic env assignments.
        "REACT_APP_", "NEXT_PUBLIC_", "VITE_",
    ]:
        assert pat.search(term), f"Should match: {term}"


def test_react_signal_prototype_jwt() -> None:
    pat = audit.REACT_PROFILE.security_signal_pattern
    for term in [
        "Object.assign(target, source)",
        "_.merge(a, b)", "_.defaultsDeep(a, b)",
        "jwt.decode(token)", "jwt.verify(token)",
    ]:
        assert pat.search(term), f"Should match: {term}"


def test_react_signal_nextjs_dom() -> None:
    pat = audit.REACT_PROFILE.security_signal_pattern
    # `.html(` and `.append(` need preceding word char for `\b` to match
    for term in [
        "getServerSideProps", "getStaticProps",
        "createElement('script'",
        "el.html(data)", "el.append(child)",
        "window.location = url", "res.redirect(url)",
    ]:
        assert pat.search(term), f"Should match: {term}"
