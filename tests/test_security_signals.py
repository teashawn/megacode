from __future__ import annotations

import audit

# Note: These tests use string literals containing names of dangerous
# functions/modules to verify regex pattern detection. They are NOT actual
# invocations -- they test that the audit scanner would flag these patterns.


# --- DOTNET deep signal tests ---


def test_dotnet_signal_injection() -> None:
    pat = audit.DOTNET_PROFILE.security_signal_pattern
    for term in [
        "FromSqlRaw(sql)", "ExecuteSqlRaw(conn, sql)",
        "var cmd = new SqlCommand(q)", "cmd.CommandText = q",
        "Process.Start(exe)", "ldap://host",
    ]:
        assert pat.search(term), f"Should match: {term}"


def test_dotnet_signal_auth_xss() -> None:
    pat = audit.DOTNET_PROFILE.security_signal_pattern
    for term in [
        "[AllowAnonymous]", "[Authorize]",
        "JWT bearer", "TokenValidation",
        "@Html.Raw(data)",
    ]:
        assert pat.search(term), f"Should match: {term}"


def test_dotnet_signal_deserialization() -> None:
    pat = audit.DOTNET_PROFILE.security_signal_pattern
    for term in [
        "new BinaryFormatter()", "TypeNameHandling.All",
        "Deserialize(stream)",
    ]:
        assert pat.search(term), f"Should match: {term}"


def test_dotnet_signal_secrets_crypto() -> None:
    pat = audit.DOTNET_PROFILE.security_signal_pattern
    for term in [
        "password = secret", "api_key = x", "var secret = val",
        "connectionstring = cs",
        "MD5.Create()", "SHA1.Create()",
        "AES.Create()", "RSA.Create()",
        "CertificateValidationCallback",
    ]:
        assert pat.search(term), f"Should match: {term}"


def test_dotnet_signal_network_path() -> None:
    pat = audit.DOTNET_PROFILE.security_signal_pattern
    for term in [
        "new HttpClient()", "WebRequest.Create(url)",
        "Server.MapPath(path)", "Path.Combine(a, b)",
        "upload file",
    ]:
        assert pat.search(term), f"Should match: {term}"


def test_dotnet_signal_negative() -> None:
    pat = audit.DOTNET_PROFILE.security_signal_pattern
    for term in [
        "Console.WriteLine(x)",
        "var count = 0",
        "string.Empty",
        "DateTime.Now",
        "List<int> items",
    ]:
        assert not pat.search(term), f"Should NOT match: {term}"


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


# --- Negative / false-positive guard tests ---


def test_python_signal_negative() -> None:
    pat = audit.PYTHON_PROFILE.security_signal_pattern
    for term in [
        "print('hello')",
        "math.sqrt(4)",
        "json.loads(data)",
        "hashlib.sha256(data)",
    ]:
        assert not pat.search(term), f"Should NOT match: {term}"


def test_go_signal_negative() -> None:
    pat = audit.GO_PROFILE.security_signal_pattern
    for term in [
        "fmt.Println(x)",
        "log.Fatal(err)",
        "http.ListenAndServe(addr, nil)",
    ]:
        assert not pat.search(term), f"Should NOT match: {term}"


def test_react_signal_negative() -> None:
    pat = audit.REACT_PROFILE.security_signal_pattern
    for term in [
        "console.log('hello')",
        "useState(0)",
        "useEffect(() => {})",
        "React.memo(Component)",
    ]:
        assert not pat.search(term), f"Should NOT match: {term}"
