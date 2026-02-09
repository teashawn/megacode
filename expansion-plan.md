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

**Reference:** `research/python_security_research.md`

### 3.1 Profile field values

- **include_extensions:** `.py`, `.pyx`, `.pyi`, `.cfg`, `.ini`, `.toml`, `.txt`, `.json`, `.yml`, `.yaml`, `.xml`, `.html`
- **include_filenames:** `pyproject.toml`, `setup.py`, `setup.cfg`, `requirements.txt`, `Pipfile`, `Pipfile.lock`, `.env`, `manage.py`, `wsgi.py`, `asgi.py`, `Dockerfile`, `alembic.ini`, `conftest.py`, `tox.ini`
- **skip_dirs:** `_COMMON_SKIP_DIRS` + `__pycache__`, `.tox`, `.mypy_cache`, `.pytest_cache`, `venv`, `.venv`, `env`, `site-packages`, `.eggs`, `node_modules`, `htmlcov`
- **security_path_hints:** `_COMMON_PATH_HINTS` + `views`, `routes`, `handlers`, `serializers`, `forms`, `models`, `schemas`, `permissions`, `decorators`, `validators`
- **extension_priority:** `.py: 10`, `.pyx: 8`, `.pyi: 5`, `.html: 6`, `.json: 5`, `.toml: 4`, `.xml: 4`, `.cfg: 3`, `.ini: 3`, `.yml: 3`, `.yaml: 3`, `.txt: 2`

### 3.2 Security signal pattern terms

| Category | Terms |
|----------|-------|
| Code running | `eval`, `compile`, `__import__`, `importlib` |
| Deserialization | `unpickler`, `shelve`, `marshal`, `yaml.load`, `jsonpickle` |
| Injection (command) | `os.system`, `os.popen`, `subprocess`, `shell=True` |
| Injection (SQL/template) | `.raw(`, `.extra(`, `rawsql`, `cursor.execute` |
| Secrets/crypto | `password`, `api_key`, `secret_key`, `connectionstring`, `hashlib.md5`, `hashlib.sha1`, `verify=False`, `cert_none` |
| Web security | `mark_safe`, `safestring`, `safetext`, `render_template_string` |
| Auth/config | `csrf_exempt`, `allowanonymous`, `login_required`, `debug=true`, `allowed_hosts`, `cors_allow_all` |
| Path traversal | `send_file`, `send_from_directory` |

### 3.3 Scanner instructions checklist

- Injection: SQL (raw, extra, RawSQL, cursor.execute with f-strings), Command (os.system, subprocess with shell=True), LDAP, Template (Jinja2, Mako)
- Code running: eval, compile, __import__, serialization modules
- Deserialization: yaml.load without SafeLoader, jsonpickle
- XSS: mark_safe, |safe filter, Markup, render_template_string
- Secrets: SECRET_KEY, DEBUG=True, ALLOWED_HOSTS=['*'], hardcoded passwords/keys
- Crypto: hashlib.md5/sha1, random module for security, verify=False, CERT_NONE
- Path traversal: open with user input, send_file, send_from_directory
- SSRF: requests/urllib/httpx with user-controlled URLs
- Auth: missing @login_required, csrf_exempt, permission_classes=[], JWT misuse
- Config: CORS_ALLOW_ALL_ORIGINS, SESSION_COOKIE_SECURE=False, app.run(debug=True)

### 3.4 Detection markers and extensions

- **detection_markers:** `pyproject.toml`, `setup.py`, `requirements.txt`, `Pipfile`, `manage.py`
- **detection_extensions:** `.py`

---

## Step 4: Research Go security vulnerabilities

**Goal:** Thorough online research about Go-specific security vulnerabilities.

### Output

Save to `research/go_security_research.md` with same structure as Python research.

---

## Step 5: Implement Go language profile

**Goal:** Add GO_PROFILE to audit.py using research from Step 4.

**Reference:** `research/go_security_research.md`

### 5.1 Profile field values

- **include_extensions:** `.go`, `.mod`, `.sum`, `.tmpl`, `.gohtml`, `.json`, `.yml`, `.yaml`, `.toml`
- **include_filenames:** `go.mod`, `go.sum`, `Makefile`, `Dockerfile`, `.goreleaser.yml`, `.goreleaser.yaml`, `config.yaml`, `config.json`, `config.toml`, `.env`
- **skip_dirs:** `_COMMON_SKIP_DIRS` + `vendor`, `testdata`
- **security_path_hints:** `_COMMON_PATH_HINTS` + `handler`, `router`, `server`, `cmd`, `internal`, `pkg`
- **extension_priority:** `.go: 10`, `.tmpl: 7`, `.gohtml: 7`, `.mod: 5`, `.json: 5`, `.toml: 4`, `.yaml: 3`, `.yml: 3`, `.sum: 2`

### 5.2 Security signal pattern terms

| Category | Terms |
|----------|-------|
| Command injection | `exec.Command`, `syscall.Exec`, `os.StartProcess` |
| TLS | `InsecureSkipVerify` |
| Unsafe | `unsafe.Pointer` |
| Weak crypto | `crypto/md5`, `crypto/sha1`, `math/rand`, `des.NewCipher`, `rc4.NewCipher` |
| Template confusion | `template.HTML`, `template.JS`, `template.CSS`, `text/template` |
| SQL/HTTP | `fmt.Sprintf` with SELECT/INSERT, `.Query(`, `.Exec(`, `.QueryRow(`, `http.Get`, `http.Post`, `http.NewRequest` |
| Path traversal | `filepath.Join`, `os.Open` |
| Secrets | `password`, `api_key`, `secret`, `private_key` |
| Framework (Gin/Echo/Chi) | `AllowAllOrigins` |
| Deserialization | `gob.NewDecoder` |

### 5.3 Scanner instructions checklist

- SQL injection: fmt.Sprintf in SQL queries, string concat in Query/Exec calls
- Command injection: exec.Command with shell, syscall.Exec, os.StartProcess
- Template confusion: text/template used for HTML (should use html/template), template.HTML/JS/CSS type casts bypassing auto-escaping
- TLS issues: InsecureSkipVerify:true, weak MinVersion, missing cert validation
- Unsafe package: unsafe.Pointer arithmetic, reflect for type bypass
- Race conditions: goroutine data races in auth/session, global map without mutex
- Crypto: crypto/md5, crypto/sha1, math/rand for security, DES/RC4
- Path traversal: filepath.Join with user input, os.Open with "../"
- SSRF: http.Get/Post/NewRequest with user-controlled URLs
- Secrets: hardcoded passwords, API keys, connection strings, private keys
- Error handling: swallowed errors on security functions (bcrypt, jwt, tls)
- Framework (Gin/Echo/Chi): AllowAllOrigins, debug mode, missing CSRF

### 5.4 Detection markers and extensions

- **detection_markers:** `go.mod`, `go.sum`
- **detection_extensions:** `.go`

---

## Step 6: Research React/JavaScript/TypeScript security vulnerabilities

**Goal:** Thorough online research about React/JS/TS-specific security vulnerabilities.

### Output

Save to `research/react_security_research.md` with same structure.

---

## Step 7: Implement React language profile

**Goal:** Add REACT_PROFILE to audit.py using research from Step 6.

**Reference:** `research/react_security_research.md`

### 7.1 Profile field values

- **include_extensions:** `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.html`, `.css`, `.scss`, `.json`, `.yml`, `.yaml`
- **include_filenames:** `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `tsconfig.json`, `next.config.js`, `next.config.mjs`, `next.config.ts`, `vite.config.ts`, `vite.config.js`, `webpack.config.js`, `.env`, `.env.local`, `.env.production`, `Dockerfile`
- **skip_dirs:** `_COMMON_SKIP_DIRS` + `node_modules`, `.next`, `.nuxt`, `.cache`, `coverage`, `.turbo`
- **security_path_hints:** `_COMMON_PATH_HINTS` + `components`, `pages`, `routes`, `hooks`, `context`, `services`, `utils`, `store`, `actions`
- **extension_priority:** `.tsx: 10`, `.ts: 10`, `.jsx: 9`, `.js: 9`, `.mjs: 8`, `.cjs: 8`, `.html: 6`, `.json: 5`, `.yml: 3`, `.yaml: 3`, `.css: 2`, `.scss: 2`

### 7.2 Security signal pattern terms

| Category | Terms |
|----------|-------|
| XSS / DOM APIs | `dangerouslySetInnerHTML`, `innerHTML`, `document.write`, `outerHTML`, `insertAdjacentHTML` |
| Code running | `eval`, Function constructor, `execSync` |
| Storage/secrets | `localStorage`, `sessionStorage`, `REACT_APP_`, `NEXT_PUBLIC_`, `VITE_`, `password`, `api_key`, `secret`, `private_key` |
| CORS | `access-control-allow-origin` |
| Redirects | `window.location`, `res.redirect` |
| jQuery DOM | `.html(`, `.append(` |
| JWT | `jwt.decode`, `jwt.verify` |
| Prototype pollution | `Object.assign`, `_.merge`, `_.defaultsDeep` |
| Next.js / SSR | `getServerSideProps`, `getStaticProps` |
| DOM creation | `createElement` + `script` |

### 7.3 Scanner instructions checklist

- XSS: dangerouslySetInnerHTML, innerHTML, document.write, outerHTML, insertAdjacentHTML, jQuery .html/.append
- Code running: eval, Function constructor, setTimeout/setInterval with strings, execSync/spawn via child process modules
- Prototype pollution: Object.assign, lodash merge/set/defaultsDeep
- JWT/Auth: localStorage/sessionStorage for tokens, jwt.decode without verify
- Secret exposure: REACT_APP_, NEXT_PUBLIC_, VITE_ env vars with secrets, hardcoded API keys/tokens in client code
- SSRF: fetch/axios with user-controlled URLs in API routes/SSR
- Open redirects: window.location with user input, res.redirect unvalidated
- CORS: Access-Control-Allow-Origin:*, credentials:true with wildcard
- Node.js server: fs with user input, SQL injection in queries
- React-specific: ref DOM manipulation, useEffect cleanup issues
- Next.js: API routes without auth, getServerSideProps data exposure

### 7.4 Detection markers and extensions

- **detection_markers:** `package.json`, `next.config.js`, `next.config.mjs`, `next.config.ts`, `vite.config.ts`, `vite.config.js`
- **detection_extensions:** `.jsx`, `.tsx`

---

## Step 8: Update documentation and metadata

- **README.md:** Remove .NET-only framing, document --language flag, add usage examples per language
- **SKILL.md:** Broaden to "multi-language codebases (Python, Go, React, .NET)"
- **pyproject.toml:** Update description and keywords
- **CHANGELOG.md:** Add entry for multi-language support

---

## Step 9: Comprehensive test suite

**Goal:** Document and maintain the 8-file test suite covering all profiles and functionality.

### Test file structure

| File | Tests | Focus |
|------|-------|-------|
| `test_profiles.py` | 13 | LanguageProfile structure, registry, immutability, cross-profile validation |
| `test_security_signals.py` | 24 | Deep signal pattern tests per profile (positive + negative/false-positive guards) |
| `test_detect_language.py` | 12 | Language auto-detection from markers and extensions |
| `test_manifest.py` | 32 | File collection, scoring, filtering, extension priority |
| `test_rlm_tools.py` | 26 | RLM tool construction and behavior |
| `test_main.py` | 33 | CLI argument parsing, main orchestration |
| `test_execution.py` | 26 | End-to-end execution paths |
| `test_utilities.py` | 26 | Helper functions, caching, regex compilation |

### Coverage targets

- Every profile (DOTNET, Python, Go, React) has deep signal pattern tests
- Each profile has negative tests to guard against false positives
- Cross-profile tests verify common skip dirs, path hints, scanner instruction format
- Total: ~192 tests

---

## Final Verification

1. `python -m pytest tests/ -v` — all tests pass
2. `python -m py_compile audit.py` — no syntax errors
3. `ruff check audit.py` — no lint issues
4. `python audit.py --help` — shows --language flag with all choices
5. Manual smoke test with a real Python/Go/React repo if available
