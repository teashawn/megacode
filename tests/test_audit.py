from __future__ import annotations

from pathlib import Path

import audit


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
    import sys
    original = sys.argv
    try:
        sys.argv = ["audit", "--language", "dotnet", "--source-root", "/tmp"]
        args = audit.parse_args()
        assert args.language == "dotnet"
    finally:
        sys.argv = original


def test_parse_args_language_auto_default() -> None:
    """--language defaults to auto."""
    import sys
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
