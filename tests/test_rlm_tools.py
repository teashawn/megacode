from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

import audit


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


# --- basic tools ---


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


# --- tool_help ---


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


# --- list_manifest filters ---


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


# --- read_file ---


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


# --- search_pattern ---


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
