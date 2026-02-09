from __future__ import annotations

from pathlib import Path

import audit


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


def test_detect_language_python(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("[project]", encoding="utf-8")
    (repo / "requirements.txt").write_text("django\n", encoding="utf-8")
    (repo / "app.py").write_text("import flask", encoding="utf-8")

    detected = audit.detect_language(repo)
    assert detected == "python"


def test_detect_language_go(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "go.mod").write_text("module example.com/app", encoding="utf-8")
    (repo / "go.sum").write_text("", encoding="utf-8")
    (repo / "main.go").write_text("package main", encoding="utf-8")

    detected = audit.detect_language(repo)
    assert detected == "go"


def test_detect_language_react(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        '{"dependencies":{"react":"^18.0.0"}}', encoding="utf-8"
    )
    (repo / "App.tsx").write_text("export default function App() {}", encoding="utf-8")

    detected = audit.detect_language(repo)
    assert detected == "react"


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
