from __future__ import annotations

import json
import os
from pathlib import Path

import audit


# --- collect_source_manifest basic ---


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


# --- _score_manifest_entry ---


def test_score_manifest_entry_detects_security_signals() -> None:
    signal_score, path_score = audit._score_manifest_entry(
        "src/SecurityController.cs",
        "var password = \"p\"; var algo = \"MD5\"; var sql = \"FromSqlRaw\";",
        audit.DOTNET_PROFILE,
    )
    assert signal_score >= 2
    assert path_score >= 1


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


# --- collect_source_manifest edge cases ---


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
        import pytest
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
        import pytest
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
        import pytest
        pytest.skip("Cannot test unreadable files as root")
    repo = tmp_path / "repo"
    repo.mkdir()
    locked_file = repo / "noread.py"
    locked_file.write_text("pass", encoding="utf-8")
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


# --- build_source_overview ---


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


# --- write_manifest_jsonl ---


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
