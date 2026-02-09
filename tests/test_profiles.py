from __future__ import annotations

import dataclasses

import pytest

import audit


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


def test_python_signal_pattern() -> None:
    pattern = audit.PYTHON_PROFILE.security_signal_pattern
    assert pattern.search("pickle.loads(data)")
    assert pattern.search("mark_safe(html)")
    assert pattern.search("hashlib.md5(data)")
    assert pattern.search("os.system(cmd)")
    assert not pattern.search("print('hello')")


def test_go_signal_pattern() -> None:
    pattern = audit.GO_PROFILE.security_signal_pattern
    assert pattern.search("InsecureSkipVerify: true")
    assert pattern.search("exec.Command(cmd)")
    assert pattern.search("unsafe.Pointer(p)")
    assert pattern.search("password = secret")
    assert not pattern.search("fmt.Println(x)")


def test_react_signal_pattern() -> None:
    pattern = audit.REACT_PROFILE.security_signal_pattern
    assert pattern.search("dangerouslySetInnerHTML={{__html: x}}")
    assert pattern.search("element.innerHTML = userInput")
    assert pattern.search("localStorage.setItem('token', jwt)")
    assert not pattern.search("console.log('hello')")
