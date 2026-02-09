# Plan: Add Python, Go, and React Support to Megacode

## Context

Megacode is an RLM-based security audit tool that currently only supports .NET repositories. All language-specific behavior is concentrated in hardcoded constants and a single DSPy signature docstring within `audit.py`. The RLM tools themselves (file reading, searching, manifest listing) are fully language-agnostic. This plan adds Python, Go, and React security audit profiles, each preceded by thorough online research.

## Critical Files

- `audit.py` — all language constants (lines 62-148), _is_audit_file (151), _score_manifest_entry (398), _extension_priority (405), collect_source_manifest (415), build_rlm_tools (617), CodeScanner signature (357), main (1011)
- `tests/test_audit.py` — 9 existing tests, 4 use the global constants being refactored
- `pyproject.toml` — project description and keywords
- `README.md` — user-facing docs
- `SKILL.md` — Claude Code skill description

---

## Step 1: Introduce LanguageProfile dataclass and refactor .NET constants

**Goal:** Create a LanguageProfile frozen dataclass and migrate existing .NET constants into a DOTNET_PROFILE instance. Thread the profile through all functions that currently read global constants. No new languages yet — existing behavior preserved exactly.

### 1.1 Add LanguageProfile dataclass (after imports, before constants)

Fields: name, display_name, include_extensions (frozenset), include_filenames (frozenset), skip_dirs (frozenset), security_path_hints (tuple), security_signal_pattern (re.Pattern), extension_priority (dict), scanner_instructions (str), tool_help_examples (tuple), detection_markers (frozenset), detection_extensions (frozenset). Use `@dataclasses.dataclass(frozen=True)` for immutability.

### 1.2 Extract common values shared across all profiles

Define _COMMON_SKIP_DIRS and _COMMON_PATH_HINTS. Each profile extends these with language-specific entries.

### 1.3 Create DOTNET_PROFILE from existing constants

Move INCLUDE_EXTENSIONS, INCLUDE_FILENAMES, SKIP_DIRS, SECURITY_PATH_HINTS, SECURITY_SIGNAL_PATTERN, EXTENSION_PRIORITY into a DOTNET_PROFILE instance. scanner_instructions gets the current CodeScanner docstring verbatim. Remove old module-level constants.

### 1.4 Add LANGUAGE_PROFILES registry dict

### 1.5 Add detect_language function

Scans top-level directory for detection markers and primary extensions. Returns profile name with strongest signal, or None if ambiguous.

### 1.6 Add --language CLI argument

Choices: profile names + "auto". Default: "auto". Update parser description to be language-agnostic.

### 1.7 Refactor functions to accept profile parameter

_is_audit_file, _score_manifest_entry, _extension_priority, collect_source_manifest, build_rlm_tools — all get a `profile` parameter instead of reading module-level constants.

### 1.8 Use CodeScanner.with_instructions for dynamic prompts

DSPy Signature.with_instructions classmethod returns a new Signature class with updated instructions. In main, after profile selection: `LanguageScanner = CodeScanner.with_instructions(profile.scanner_instructions)`. Change base CodeScanner output field description to generic "security audit report".

### 1.9 Update main orchestration

Resolve profile, pass it to collect_source_manifest and build_rlm_tools, use LanguageScanner for RLM, print detected language.

### 1.10 Update existing tests

Update 4 tests to pass DOTNET_PROFILE. Add tests for profile structure, language detection, and CLI flag parsing.

### Verification

`python -m pytest tests/` — all existing tests pass. `python audit.py --help` shows --language.

---

## Step 2: Research Python security vulnerabilities

**Goal:** Thorough online research about Python-specific security vulnerabilities before implementing the profile.

### Output

Save to `research/python_security_research.md` with vulnerability categories, CWE references, specific dangerous functions per category, regex patterns for detection, framework-specific concerns.

---

## Step 3: Implement Python language profile

**Goal:** Add PYTHON_PROFILE to audit.py using research from Step 2.

---

## Step 4: Research Go security vulnerabilities

**Goal:** Thorough online research about Go-specific security vulnerabilities.

### Output

Save to `research/go_security_research.md` with same structure as Python research.

---

## Step 5: Implement Go language profile

**Goal:** Add GO_PROFILE to audit.py using research from Step 4.

---

## Step 6: Research React/JavaScript/TypeScript security vulnerabilities

**Goal:** Thorough online research about React/JS/TS-specific security vulnerabilities.

### Output

Save to `research/react_security_research.md` with same structure.

---

## Step 7: Implement React language profile

**Goal:** Add REACT_PROFILE to audit.py using research from Step 6.

---

## Step 8: Update documentation and metadata

- **README.md:** Remove .NET-only framing, document --language flag, add usage examples per language
- **SKILL.md:** Broaden to "multi-language codebases (Python, Go, React, .NET)"
- **pyproject.toml:** Update description and keywords
- **CHANGELOG.md:** Add entry for multi-language support

---

## Final Verification

1. `python -m pytest tests/ -v` — all tests pass
2. `python -m py_compile audit.py` — no syntax errors
3. `ruff check audit.py` — no lint issues
4. `python audit.py --help` — shows --language flag with all choices
5. Manual smoke test with a real Python/Go/React repo if available
