# Python Security Vulnerability Research for Audit Tool Development

> Comprehensive reference for building a Python-focused static security analysis tool.
> Covers dangerous functions, CWE mappings, regex-matchable patterns, and vulnerable code examples.

---

## Table of Contents

1. [Injection Vulnerabilities](#1-injection-vulnerabilities)
2. [Arbitrary Code Execution](#2-arbitrary-code-execution)
3. [Authentication and Authorization Flaws](#3-authentication-and-authorization-flaws)
4. [Cross-Site Scripting (XSS)](#4-cross-site-scripting-xss)
5. [Secrets and Credential Exposure](#5-secrets-and-credential-exposure)
6. [Cryptographic Issues](#6-cryptographic-issues)
7. [Path Traversal](#7-path-traversal)
8. [Server-Side Request Forgery (SSRF)](#8-server-side-request-forgery-ssrf)
9. [Django-Specific Vulnerabilities](#9-django-specific-vulnerabilities)
10. [Flask-Specific Vulnerabilities](#10-flask-specific-vulnerabilities)
11. [FastAPI-Specific Vulnerabilities](#11-fastapi-specific-vulnerabilities)
12. [Deserialization Vulnerabilities (Expanded)](#12-deserialization-vulnerabilities-expanded)
13. [Regex-Based Detection Strategy](#13-regex-based-detection-strategy)

---

## 1. Injection Vulnerabilities

### 1.1 SQL Injection

**CWE References:** CWE-89 (SQL Injection), CWE-564 (SQL Injection: Hibernate/ORM)

#### Dangerous Functions / Patterns

| Function / Pattern | Framework | Risk Level |
|---|---|---|
| `cursor.execute(query)` where query is f-string/format/% | stdlib `sqlite3`, `psycopg2`, `mysql-connector` | Critical |
| `cursor.executemany(query, ...)` with string interpolation | stdlib | Critical |
| `connection.execute(text(...))` | SQLAlchemy | Critical |
| `engine.execute(...)` with raw string | SQLAlchemy | Critical |
| `session.execute(text(...))` | SQLAlchemy | Critical |
| `Model.objects.raw(...)` | Django ORM | High |
| `Model.objects.extra(where=[...])` | Django ORM (deprecated) | High |
| `RawSQL(...)` | Django ORM | High |
| `cursor.execute(...)` via `connection.cursor()` | Django DB | Critical |
| `.filter(**{key: val})` with user-controlled key | Django ORM | Medium |
| `QuerySet.annotate()` with `RawSQL` | Django ORM | High |

#### Regex Patterns for Detection

```python
# f-string SQL
r'''(?:execute|executemany)\s*\(\s*f["\']'''

# .format() SQL
r'''(?:execute|executemany)\s*\(\s*["\'].*\{.*\}.*["\']\.format\s*\('''

# % formatting SQL
r'''(?:execute|executemany)\s*\(\s*["\'].*%[sd].*["\']\s*%'''

# String concatenation SQL
r'''(?:execute|executemany)\s*\(\s*["\'].*["\']\s*\+'''

# Django raw queries
r'''\.objects\.raw\s*\(\s*f["\']'''
r'''\.objects\.raw\s*\(\s*["\'].*%'''
r'''\.objects\.extra\s*\('''
r'''RawSQL\s*\('''

# SQLAlchemy text() with interpolation
r'''text\s*\(\s*f["\']'''
r'''text\s*\(\s*["\'].*\{.*\}.*["\']\.format'''
r'''text\s*\(\s*["\'].*%[sd].*["\']\s*%'''
```

#### Vulnerable Code Examples

```python
# VULNERABLE: f-string SQL injection (sqlite3 / psycopg2)
def get_user(username):
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor.fetchone()

# VULNERABLE: %-formatting SQL injection
def search_products(term):
    query = "SELECT * FROM products WHERE name LIKE '%%%s%%'" % term
    cursor.execute(query)

# VULNERABLE: .format() SQL injection
def delete_record(record_id):
    cursor.execute("DELETE FROM records WHERE id = {}".format(record_id))

# VULNERABLE: Django ORM raw() with interpolation
def find_user(name):
    return User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{name}'")

# VULNERABLE: Django extra() (deprecated but still functional)
def filtered_query(where_clause):
    return MyModel.objects.extra(where=[where_clause])

# VULNERABLE: SQLAlchemy text() with f-string
from sqlalchemy import text
def query_db(session, table_name):
    return session.execute(text(f"SELECT * FROM {table_name}"))

# SAFE: Parameterized query
cursor.execute("SELECT * FROM users WHERE name = %s", (username,))

# SAFE: Django ORM raw with params
User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [name])

# SAFE: SQLAlchemy with bound params
session.execute(text("SELECT * FROM users WHERE name = :name"), {"name": name})
```

---

### 1.2 Command Injection / OS Command Injection

**CWE References:** CWE-78 (OS Command Injection), CWE-77 (Command Injection)

#### Dangerous Functions / Patterns

| Function | Risk | Notes |
|---|---|---|
| `os.system(cmd)` | Critical | Always runs through shell |
| `os.popen(cmd)` | Critical | Always runs through shell |
| `os.popen2/3/4(cmd)` | Critical | Deprecated but may exist |
| `subprocess.call(cmd, shell=True)` | Critical | Shell interpretation enabled |
| `subprocess.run(cmd, shell=True)` | Critical | Shell interpretation enabled |
| `subprocess.Popen(cmd, shell=True)` | Critical | Shell interpretation enabled |
| `subprocess.check_output(cmd, shell=True)` | Critical | Shell interpretation enabled |
| `subprocess.check_call(cmd, shell=True)` | Critical | Shell interpretation enabled |
| `subprocess.getoutput(cmd)` | Critical | Always uses shell |
| `subprocess.getstatusoutput(cmd)` | Critical | Always uses shell |
| `commands.getoutput(cmd)` | Critical | Python 2, deprecated |
| `commands.getstatusoutput(cmd)` | Critical | Python 2, deprecated |
| `os.execl/execle/execlp/execv/execve/execvp/execvpe(cmd)` | High | exec family |
| `os.spawnl/spawnle/spawnlp/spawnlpe/spawnv/spawnve/spawnvp/spawnvpe(cmd)` | High | spawn family |
| `pty.spawn(cmd)` | High | Pseudo-terminal spawn |
| `fabric.api.local(cmd)` | High | Fabric library |
| `paramiko.exec_command(cmd)` | High | SSH remote execution |
| `asyncio.create_subprocess_shell(cmd)` | Critical | Async shell execution |

#### Regex Patterns for Detection

```python
# os.system / os.popen with variable
r'''os\.(?:system|popen[234]?)\s*\((?!\s*["\'])'''
r'''os\.(?:system|popen[234]?)\s*\(\s*f["\']'''
r'''os\.(?:system|popen[234]?)\s*\(\s*["\'].*["\']\s*(?:%|\+|\.format)'''

# subprocess with shell=True
r'''subprocess\.(?:call|run|Popen|check_output|check_call)\s*\(.*shell\s*=\s*True'''

# subprocess always-shell functions
r'''subprocess\.(?:getoutput|getstatusoutput)\s*\('''

# asyncio shell subprocess
r'''asyncio\.create_subprocess_shell\s*\('''
```

#### Vulnerable Code Examples

```python
# VULNERABLE: os.system with user input
def ping_host(host):
    os.system(f"ping -c 3 {host}")  # host = "8.8.8.8; rm -rf /"

# VULNERABLE: subprocess with shell=True and string interpolation
def list_files(directory):
    subprocess.call(f"ls -la {directory}", shell=True)

# VULNERABLE: subprocess with shell=True and user-controlled string
def run_command(user_input):
    result = subprocess.run(user_input, shell=True, capture_output=True)

# VULNERABLE: os.popen with format string
def get_process_info(pid):
    return os.popen("ps -p %s" % pid).read()

# VULNERABLE: asyncio shell subprocess
async def async_cmd(cmd):
    proc = await asyncio.create_subprocess_shell(cmd)

# SAFE: subprocess with list arguments, no shell
subprocess.run(["ping", "-c", "3", host], shell=False)

# SAFE: shlex.quote for shell commands
import shlex
subprocess.run(f"ping -c 3 {shlex.quote(host)}", shell=True)
```

---

### 1.3 LDAP Injection

**CWE References:** CWE-90 (LDAP Injection)

#### Dangerous Functions / Patterns

| Function / Pattern | Library | Risk |
|---|---|---|
| `ldap.search_s(base, scope, filterstr)` | python-ldap | High |
| `ldap.search_ext_s(...)` | python-ldap | High |
| `Connection.search(search_filter=...)` | ldap3 | High |
| f-string/format in LDAP filter construction | Any | Critical |

#### Regex Patterns

```python
# LDAP filter with string interpolation
r'''search(?:_s|_ext_s|_ext)?\s*\(.*f["\'].*\('''
r'''search_filter\s*=\s*f["\']'''
r'''ldap_filter\s*=\s*["\'].*%[sd]'''
```

#### Vulnerable Code Examples

```python
# VULNERABLE: LDAP injection via f-string
import ldap
def find_user(username):
    conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE,
                  f"(uid={username})")  # username = "*)(|(password=*)"

# VULNERABLE: ldap3 with format string
from ldap3 import Connection
def auth_user(conn, username):
    conn.search("dc=example,dc=com",
                search_filter=f"(&(uid={username})(objectClass=person))")

# SAFE: Use ldap.filter.escape_filter_chars
from ldap.filter import escape_filter_chars
conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE,
              f"(uid={escape_filter_chars(username)})")
```

---

### 1.4 Template Injection (SSTI)

**CWE References:** CWE-1336 (Improper Neutralization of Special Elements Used in a Template Engine), CWE-94 (Code Injection)

#### Dangerous Functions / Patterns

| Function / Pattern | Library | Risk |
|---|---|---|
| `Template(user_input).render()` | Jinja2 | Critical |
| `Environment().from_string(user_input)` | Jinja2 | Critical |
| `Template(user_input).render()` | Mako | Critical |
| `string.Template(user_input).substitute()` | stdlib | Low-Medium |
| `render_template_string(user_input)` | Flask | Critical |
| `Template(user_input)` where user_input is variable | Django templates | High |
| `format_map()` with user-controlled format string | stdlib | Medium |

#### Regex Patterns

```python
# Jinja2 SSTI
r'''(?:Template|from_string)\s*\((?!\s*["\'])'''
r'''render_template_string\s*\((?!\s*["\'])'''

# Mako SSTI
r'''mako\.template\.Template\s*\((?!\s*["\'])'''

# Django template from user string
r'''django\.template\.Template\s*\((?!\s*["\'])'''

# format_map with user input
r'''\.format_map\s*\('''
```

#### Vulnerable Code Examples

```python
# VULNERABLE: Jinja2 SSTI
from jinja2 import Template
def render_page(user_template):
    return Template(user_template).render()
    # user_template = "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"

# VULNERABLE: Flask render_template_string
from flask import render_template_string, request
@app.route("/page")
def page():
    template = request.args.get("template")
    return render_template_string(template)

# VULNERABLE: Mako template injection
from mako.template import Template
def render(user_input):
    return Template(user_input).render()

# VULNERABLE: format_map exploitation
class Config:
    SECRET = "supersecret"
"{0.__class__.__init__.__globals__}".format_map({0: Config()})

# SAFE: Render from file with context variables
return render_template("page.html", content=user_input)
```

---

## 2. Arbitrary Code Execution

### 2.1 eval() and exec()

**CWE References:** CWE-95 (Eval Injection), CWE-94 (Code Injection)

#### Dangerous Functions

| Function | Risk | Notes |
|---|---|---|
| `eval(expr)` | Critical | Evaluates arbitrary Python expressions |
| `exec(code)` | Critical | Executes arbitrary Python statements |
| `compile(source, ...)` | High | Compiles source into code object for exec/eval |
| `ast.literal_eval(expr)` | Low | Safe for literals only, but check usage |

#### Regex Patterns

```python
# eval/exec with non-literal argument
r'''\beval\s*\((?!\s*["\'])'''
r'''\bexec\s*\((?!\s*["\'])'''

# eval/exec with f-string or format
r'''\beval\s*\(\s*f["\']'''
r'''\bexec\s*\(\s*f["\']'''

# compile with variable source
r'''\bcompile\s*\((?!\s*["\'])'''

# General eval/exec (broad match, needs triage)
r'''\b(?:eval|exec)\s*\('''
```

#### Vulnerable Code Examples

```python
# VULNERABLE: eval with user input
def calculate(expression):
    return eval(expression)  # expression = "__import__('os').system('rm -rf /')"

# VULNERABLE: exec with user input
def run_user_code(code):
    exec(code)

# VULNERABLE: eval with "sanitized" input (easily bypassed)
def safe_eval(expr):
    if "import" not in expr:  # Trivially bypassed
        return eval(expr)

# VULNERABLE: compile + exec chain
code = compile(user_input, "<string>", "exec")
exec(code)

# VULNERABLE: eval in class attribute calculation
def set_attribute(obj, attr, value_expr):
    setattr(obj, attr, eval(value_expr))

# SAFE: ast.literal_eval for literal-only evaluation
import ast
result = ast.literal_eval("[1, 2, 3]")

# SAFE: restricted eval with empty globals (still not fully safe)
eval(expr, {"__builtins__": {}})  # Can still be bypassed!
```

---

### 2.2 Deserialization / Pickle

**CWE References:** CWE-502 (Deserialization of Untrusted Data)

#### Dangerous Functions

| Function | Risk | Notes |
|---|---|---|
| `pickle.loads(data)` | Critical | Arbitrary code execution via `__reduce__` |
| `pickle.load(file)` | Critical | Same |
| `pickle.Unpickler(file).load()` | Critical | Same |
| `cPickle.loads(data)` | Critical | Python 2, C implementation |
| `shelve.open(filename)` | Critical | Uses pickle internally |
| `marshal.loads(data)` | High | Can crash interpreter |
| `yaml.load(data)` | Critical | Without `Loader=SafeLoader` |
| `yaml.load(data, Loader=yaml.Loader)` | Critical | Unsafe loader |
| `yaml.load(data, Loader=yaml.FullLoader)` | Medium | Some restrictions but still risky |
| `yaml.unsafe_load(data)` | Critical | Explicitly unsafe |
| `jsonpickle.decode(data)` | Critical | Deserializes Python objects |
| `dill.loads(data)` | Critical | Extended pickle |
| `joblib.load(filename)` | Critical | Uses pickle internally |
| `numpy.load(file, allow_pickle=True)` | Critical | Pickle in numpy format |
| `pandas.read_pickle(filepath)` | Critical | Uses pickle |
| `torch.load(filepath)` | Critical | Uses pickle by default |

#### Regex Patterns

```python
# Pickle
r'''\bpickle\.(?:loads?|Unpickler)\s*\('''
r'''\bcPickle\.(?:loads?|Unpickler)\s*\('''

# Shelve
r'''\bshelve\.open\s*\('''

# Marshal
r'''\bmarshal\.loads?\s*\('''

# YAML unsafe loading
r'''\byaml\.load\s*\((?!.*Loader\s*=\s*(?:yaml\.)?SafeLoader)'''
r'''\byaml\.unsafe_load\s*\('''
r'''\byaml\.full_load\s*\('''

# jsonpickle
r'''\bjsonpickle\.decode\s*\('''

# dill
r'''\bdill\.loads?\s*\('''

# joblib
r'''\bjoblib\.load\s*\('''

# numpy with pickle
r'''\bnumpy\.load\s*\(.*allow_pickle\s*=\s*True'''
r'''\bnp\.load\s*\(.*allow_pickle\s*=\s*True'''

# pandas pickle
r'''\bpd\.read_pickle\s*\('''
r'''\bpandas\.read_pickle\s*\('''

# PyTorch
r'''\btorch\.load\s*\((?!.*weights_only\s*=\s*True)'''
```

#### Vulnerable Code Examples

```python
# VULNERABLE: pickle deserialization from network
import pickle
def handle_request(data):
    obj = pickle.loads(data)  # RCE via crafted pickle payload

# VULNERABLE: yaml.load without SafeLoader
import yaml
config = yaml.load(open("config.yml"))  # Default loader is unsafe in older PyYAML

# VULNERABLE: yaml.load with FullLoader (still partially unsafe)
config = yaml.load(data, Loader=yaml.FullLoader)

# VULNERABLE: torch.load without weights_only
import torch
model = torch.load("model.pt")  # Pickle-based deserialization

# VULNERABLE: numpy with allow_pickle
import numpy as np
data = np.load("data.npy", allow_pickle=True)

# VULNERABLE: shelve (uses pickle internally)
import shelve
db = shelve.open("mydb")
value = db["key"]  # Deserializes using pickle

# SAFE: yaml with SafeLoader
config = yaml.load(data, Loader=yaml.SafeLoader)
# or
config = yaml.safe_load(data)

# SAFE: torch.load with weights_only
model = torch.load("model.pt", weights_only=True)

# SAFE: json for data serialization
import json
data = json.loads(json_string)
```

---

### 2.3 Dynamic Import and Code Loading

**CWE References:** CWE-94 (Code Injection), CWE-98 (Improper Control of Filename for Include/Require)

#### Dangerous Functions

| Function | Risk | Notes |
|---|---|---|
| `__import__(name)` | High | Dynamic module import |
| `importlib.import_module(name)` | High | Dynamic module import |
| `importlib.__import__(name)` | High | Dynamic module import |
| `__builtins__.__import__(name)` | High | Builtins import |
| `globals()[name]` | Medium | Dynamic global access |
| `getattr(module, name)` | Medium | Dynamic attribute access |

#### Regex Patterns

```python
r'''\b__import__\s*\((?!\s*["\'])'''
r'''\bimportlib\.import_module\s*\((?!\s*["\'])'''
r'''\bglobals\s*\(\s*\)\s*\[(?!\s*["\'])'''
```

#### Vulnerable Code Examples

```python
# VULNERABLE: Dynamic import from user input
def load_plugin(plugin_name):
    module = __import__(plugin_name)  # User controls module name
    return module

# VULNERABLE: importlib with user input
import importlib
def get_handler(module_name):
    return importlib.import_module(module_name)

# SAFE: Whitelist allowed modules
ALLOWED_PLUGINS = {"plugin_a", "plugin_b", "plugin_c"}
def load_plugin(name):
    if name not in ALLOWED_PLUGINS:
        raise ValueError("Unknown plugin")
    return importlib.import_module(f"plugins.{name}")
```

---

## 3. Authentication and Authorization Flaws

### 3.1 Django Auth Bypass Patterns

**CWE References:** CWE-287 (Improper Authentication), CWE-862 (Missing Authorization), CWE-863 (Incorrect Authorization)

#### Dangerous Patterns

| Pattern | Risk | Notes |
|---|---|---|
| `@csrf_exempt` | High | Disables CSRF protection |
| Missing `@login_required` on views | High | Unauthenticated access |
| Missing `LoginRequiredMixin` on CBVs | High | Unauthenticated access |
| `CSRF_COOKIE_SECURE = False` | Medium | CSRF token over HTTP |
| `SESSION_COOKIE_SECURE = False` | Medium | Session cookie over HTTP |
| `SESSION_COOKIE_HTTPONLY = False` | Medium | JS access to session cookie |
| `check_password()` not using constant-time comparison | Medium | Timing attack |
| Custom authentication backends with flawed logic | High | Auth bypass |
| `.filter(is_superuser=True)` exposed | High | Privilege escalation vectors |
| `permission_classes = []` or `AllowAny` without intent | High | DRF: No auth on endpoint |

#### Regex Patterns

```python
# CSRF exemption
r'''@csrf_exempt'''
r'''csrf_exempt\s*\('''

# DRF permission bypass
r'''permission_classes\s*=\s*\[\s*\]'''
r'''permission_classes\s*=\s*\[\s*AllowAny\s*\]'''
r'''authentication_classes\s*=\s*\[\s*\]'''

# Insecure session settings
r'''SESSION_COOKIE_SECURE\s*=\s*False'''
r'''SESSION_COOKIE_HTTPONLY\s*=\s*False'''
r'''CSRF_COOKIE_SECURE\s*=\s*False'''
r'''CSRF_COOKIE_HTTPONLY\s*=\s*False'''
```

#### Vulnerable Code Examples

```python
# VULNERABLE: CSRF-exempt view handling sensitive data
@csrf_exempt
def transfer_funds(request):
    amount = request.POST.get("amount")
    to_account = request.POST.get("to_account")
    # ... processes transfer without CSRF protection

# VULNERABLE: No authentication on sensitive view
def admin_dashboard(request):  # Missing @login_required
    return render(request, "admin/dashboard.html", {"users": User.objects.all()})

# VULNERABLE: DRF view with no permissions
class UserListView(generics.ListAPIView):
    permission_classes = []  # Anyone can list all users
    queryset = User.objects.all()
    serializer_class = UserSerializer

# SAFE: Proper decorators
@login_required
@permission_required("app.view_sensitive_data")
def sensitive_view(request):
    ...

# SAFE: DRF with proper permissions
class UserListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
```

---

### 3.2 JWT Misuse

**CWE References:** CWE-347 (Improper Verification of Cryptographic Signature), CWE-345 (Insufficient Verification of Data Authenticity)

#### Dangerous Patterns

| Pattern | Risk | Notes |
|---|---|---|
| `jwt.decode(token, algorithms=["none"])` | Critical | No signature verification |
| `jwt.decode(token, options={"verify_signature": False})` | Critical | Signature bypass |
| `jwt.decode(token, options={"verify_exp": False})` | High | Expired token accepted |
| `jwt.decode(token, options={"verify_aud": False})` | Medium | Audience not checked |
| Using symmetric key (HS256) where asymmetric expected | High | Algorithm confusion |
| Hardcoded JWT secret | Critical | Anyone can forge tokens |
| `jwt.decode(token, key, algorithms=["HS256", "RS256"])` | High | Algorithm confusion attack |

#### Regex Patterns

```python
# JWT none algorithm
r'''jwt\.decode\s*\(.*algorithms\s*=\s*\[.*["\']none["\']'''
r'''jwt\.decode\s*\(.*algorithms\s*=\s*\[.*["\']None["\']'''

# Disabled verification
r'''jwt\.decode\s*\(.*verify_signature["\']?\s*:\s*False'''
r'''jwt\.decode\s*\(.*verify_exp["\']?\s*:\s*False'''
r'''jwt\.decode\s*\(.*verify\s*=\s*False'''

# Multiple algorithm types (algorithm confusion)
r'''jwt\.decode\s*\(.*algorithms\s*=\s*\[.*HS.*RS'''
r'''jwt\.decode\s*\(.*algorithms\s*=\s*\[.*RS.*HS'''
```

#### Vulnerable Code Examples

```python
# VULNERABLE: No signature verification
import jwt
decoded = jwt.decode(token, options={"verify_signature": False})

# VULNERABLE: 'none' algorithm accepted
decoded = jwt.decode(token, algorithms=["none", "HS256"])

# VULNERABLE: Algorithm confusion - accepting both symmetric and asymmetric
decoded = jwt.decode(token, public_key, algorithms=["HS256", "RS256"])
# Attacker signs with public key using HS256

# VULNERABLE: Expired tokens accepted
decoded = jwt.decode(token, secret, algorithms=["HS256"],
                     options={"verify_exp": False})

# SAFE: Strict algorithm and full verification
decoded = jwt.decode(token, secret_key, algorithms=["HS256"])

# SAFE: RSA with explicit algorithm
decoded = jwt.decode(token, public_key, algorithms=["RS256"])
```

---

### 3.3 Session Handling Flaws

**CWE References:** CWE-384 (Session Fixation), CWE-613 (Insufficient Session Expiration), CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute)

#### Dangerous Patterns

```python
# Flask: permanent session without expiry
r'''session\.permanent\s*=\s*True(?!.*PERMANENT_SESSION_LIFETIME)'''

# Flask: missing secret key configuration
r'''app\.secret_key\s*=\s*["\']["\']'''  # Empty secret key

# Insecure cookie settings
r'''response\.set_cookie\s*\(.*secure\s*=\s*False'''
r'''response\.set_cookie\s*\(.*httponly\s*=\s*False'''
```

---

## 4. Cross-Site Scripting (XSS)

**CWE References:** CWE-79 (Cross-Site Scripting), CWE-80 (Basic XSS)

### 4.1 Django XSS Vectors

#### Dangerous Functions / Patterns

| Pattern | Risk | Notes |
|---|---|---|
| `mark_safe(user_input)` | Critical | Marks string as safe HTML |
| `format_html()` misuse | Medium | If used with pre-formatted user content |
| `{% autoescape off %}` | High | Disables template auto-escaping |
| `{{ var\|safe }}` | High | Disables escaping for variable |
| `SafeString(user_data)` / `SafeText(user_data)` | Critical | Same as mark_safe |
| `HttpResponse(user_data)` without content_type | Medium | Default is text/html |
| `@xframe_options_exempt` | Medium | Clickjacking vector |

#### Regex Patterns

```python
# Django mark_safe / SafeString
r'''\bmark_safe\s*\('''
r'''\bSafeString\s*\('''
r'''\bSafeText\s*\('''

# Template filters
r'''\|\s*safe\b'''
r'''\{%\s*autoescape\s+off\s*%\}'''

# X-Frame-Options exempt
r'''@xframe_options_exempt'''
r'''X_FRAME_OPTIONS\s*=\s*["\'](?:ALLOW|ALLOWALL)'''
```

### 4.2 Flask XSS Vectors

#### Dangerous Functions / Patterns

| Pattern | Risk | Notes |
|---|---|---|
| `Markup(user_input)` | Critical | Marks string as safe HTML |
| `{{ var\|safe }}` in Jinja2 | High | Disables escaping |
| `{% autoescape false %}` | High | Disables auto-escaping |
| `make_response(user_input)` | Medium | Raw HTML response |
| `Response(user_input, content_type="text/html")` | Medium | Raw HTML |

#### Regex Patterns

```python
# Flask Markup
r'''\bMarkup\s*\((?!\s*["\'])'''
r'''\bMarkup\s*\(\s*f["\']'''

# Jinja2 autoescape off
r'''\{%[-\s]*autoescape\s+false\s*[-\s]*%\}'''
```

#### Vulnerable Code Examples

```python
# VULNERABLE: Django mark_safe with user input
from django.utils.safestring import mark_safe
def render_comment(comment_text):
    return mark_safe(f"<div class='comment'>{comment_text}</div>")
    # comment_text = "<script>alert('XSS')</script>"

# VULNERABLE: Django template with |safe filter
# In template: {{ user_bio|safe }}

# VULNERABLE: Flask Markup with user input
from markupsafe import Markup
@app.route("/profile")
def profile():
    bio = request.args.get("bio")
    return Markup(f"<p>{bio}</p>")

# VULNERABLE: Raw HttpResponse with user data
from django.http import HttpResponse
def echo(request):
    user_input = request.GET.get("q")
    return HttpResponse(f"<h1>Search: {user_input}</h1>")

# SAFE: Django auto-escaping (default)
# In template: {{ user_bio }}  -- auto-escaped

# SAFE: format_html for safe formatting
from django.utils.html import format_html
return format_html("<div class='comment'>{}</div>", comment_text)

# SAFE: Flask/Jinja2 auto-escaping (default)
return render_template("profile.html", bio=bio)
```

---

## 5. Secrets and Credential Exposure

**CWE References:** CWE-798 (Use of Hardcoded Credentials), CWE-312 (Cleartext Storage of Sensitive Information), CWE-319 (Cleartext Transmission), CWE-532 (Information Exposure Through Log Files)

### 5.1 Hardcoded Secrets

#### Dangerous Patterns

| Pattern | Risk | Notes |
|---|---|---|
| `password = "..."` / `PASSWORD = "..."` | Critical | Hardcoded password |
| `secret_key = "..."` / `SECRET_KEY = "..."` | Critical | Hardcoded secret key |
| `api_key = "..."` / `API_KEY = "..."` | Critical | Hardcoded API key |
| `token = "..."` / `TOKEN = "..."` | High | Hardcoded token |
| `aws_access_key_id = "AKI..."` | Critical | AWS credentials |
| `aws_secret_access_key = "..."` | Critical | AWS credentials |
| Connection strings with embedded credentials | Critical | Database URLs |
| `.env` files committed to repository | Critical | Environment secrets |
| `private_key = "-----BEGIN RSA PRIVATE KEY-----"` | Critical | Embedded private key |

#### Regex Patterns

```python
# Generic secrets
r'''(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']'''
r'''(?:secret[_-]?key|SECRET[_-]?KEY)\s*=\s*["\'][^"\']{4,}["\']'''
r'''(?:api[_-]?key|API[_-]?KEY)\s*=\s*["\'][^"\']{4,}["\']'''
r'''(?:access[_-]?token|ACCESS[_-]?TOKEN)\s*=\s*["\'][^"\']{4,}["\']'''
r'''(?:auth[_-]?token|AUTH[_-]?TOKEN)\s*=\s*["\'][^"\']{4,}["\']'''

# AWS keys
r'''(?:aws_access_key_id|AWS_ACCESS_KEY_ID)\s*=\s*["\']?AKI[A-Z0-9]{16}["\']?'''
r'''(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*=\s*["\'][^"\']{30,}["\']'''

# Connection strings with credentials
r'''(?:mysql|postgres|postgresql|mongodb|redis|amqp)://\w+:[^@\s]+@'''
r'''(?:DATABASE_URL|DB_URL|REDIS_URL|MONGO_URL)\s*=\s*["\'].*://.*:.*@'''

# Private keys
r'''-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'''

# Django SECRET_KEY hardcoded
r'''SECRET_KEY\s*=\s*["\'][^"\']{10,}["\']'''

# GitHub tokens
r'''gh[ps]_[A-Za-z0-9_]{36,}'''

# Generic API tokens (hex, base64-like)
r'''(?:token|TOKEN)\s*=\s*["\'][A-Za-z0-9+/=_-]{20,}["\']'''

# Slack tokens
r'''xox[baprs]-[0-9]{10,}-[A-Za-z0-9-]+'''

# Stripe keys
r'''(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}'''

# Google API keys
r'''AIza[0-9A-Za-z_-]{35}'''

# SendGrid API keys
r'''SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'''
```

#### Vulnerable Code Examples

```python
# VULNERABLE: Hardcoded credentials
DATABASE_URL = "postgresql://admin:supersecret@db.example.com:5432/production"
SECRET_KEY = "django-insecure-my-very-secret-key-12345"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
API_KEY = "sk_live_EXAMPLE_REDACTED..."

# VULNERABLE: Password in source code
def connect_db():
    return psycopg2.connect(
        host="db.example.com",
        user="admin",
        password="P@ssw0rd!23"  # Hardcoded
    )

# VULNERABLE: Secret logged
import logging
logger = logging.getLogger(__name__)
def authenticate(api_key):
    logger.debug(f"Authenticating with key: {api_key}")  # CWE-532

# SAFE: Environment variables
import os
SECRET_KEY = os.environ.get("SECRET_KEY")
DATABASE_URL = os.environ["DATABASE_URL"]

# SAFE: Using python-decouple or django-environ
from decouple import config
SECRET_KEY = config("SECRET_KEY")
```

---

## 6. Cryptographic Issues

**CWE References:** CWE-327 (Use of Broken Crypto Algorithm), CWE-328 (Use of Weak Hash), CWE-330 (Use of Insufficiently Random Values), CWE-295 (Improper Certificate Validation), CWE-326 (Inadequate Encryption Strength)

### 6.1 Weak Hashing

#### Dangerous Functions

| Function | Risk | Notes |
|---|---|---|
| `hashlib.md5(...)` | High | Broken for security uses |
| `hashlib.sha1(...)` | Medium | Deprecated for security uses |
| `hashlib.new("md5", ...)` | High | Dynamic weak hash |
| `hashlib.new("sha1", ...)` | Medium | Dynamic weak hash |
| `md5(...)` from various libs | High | Weak hash |
| Using MD5/SHA1 for password hashing | Critical | Must use bcrypt/scrypt/argon2 |

#### Regex Patterns

```python
# Weak hash algorithms
r'''\bhashlib\.md5\s*\('''
r'''\bhashlib\.sha1\s*\('''
r'''\bhashlib\.new\s*\(\s*["\']md5["\']'''
r'''\bhashlib\.new\s*\(\s*["\']sha1?["\']'''

# Password hashing with weak algorithm
r'''(?:password|passwd).*(?:md5|sha1|sha256)\s*\('''
r'''(?:md5|sha1)\s*\(.*(?:password|passwd)'''
```

### 6.2 Weak Random Number Generation

#### Dangerous Functions

| Function | Risk for Security | Notes |
|---|---|---|
| `random.random()` | High | Predictable PRNG (Mersenne Twister) |
| `random.randint(a, b)` | High | Not cryptographically secure |
| `random.choice(seq)` | High | Not cryptographically secure |
| `random.choices(...)` | High | Not cryptographically secure |
| `random.getrandbits(n)` | High | Not cryptographically secure |
| `random.sample(...)` | High | Not cryptographically secure |
| `random.shuffle(...)` | Medium | Predictable shuffling |

#### Regex Patterns

```python
# random module for security-sensitive operations
r'''(?:token|secret|password|key|nonce|salt|otp|session_id|csrf)\s*=\s*.*\brandom\.'''
r'''\brandom\.(?:random|randint|choice|choices|getrandbits|sample|uniform)\s*\('''
```

### 6.3 SSL/TLS Certificate Verification Disabled

#### Dangerous Patterns

| Pattern | Risk | Notes |
|---|---|---|
| `verify=False` in requests | Critical | Disables SSL verification |
| `ssl.create_default_context()` + `check_hostname = False` | Critical | Disables hostname check |
| `ssl._create_unverified_context()` | Critical | No verification |
| `ssl.CERT_NONE` | Critical | No certificate verification |
| `urllib3.disable_warnings()` | Medium | Hides SSL warnings |
| `REQUESTS_CA_BUNDLE=""` | High | Empty CA bundle |
| `CURL_CA_BUNDLE=""` | High | Empty CA bundle |

#### Regex Patterns

```python
# requests verify=False
r'''requests\.(?:get|post|put|delete|patch|head|options)\s*\(.*verify\s*=\s*False'''
r'''\.(?:get|post|put|delete|patch|head|options)\s*\(.*verify\s*=\s*False'''

# SSL context insecure
r'''ssl\._create_unverified_context\s*\('''
r'''ssl\.CERT_NONE'''
r'''check_hostname\s*=\s*False'''
r'''verify_mode\s*=\s*ssl\.CERT_NONE'''

# urllib3 warning suppression
r'''urllib3\.disable_warnings'''
r'''InsecureRequestWarning'''

# httpx verify=False
r'''httpx\.(?:Client|AsyncClient)\s*\(.*verify\s*=\s*False'''
```

### 6.4 PyCrypto / PyCryptodome Misuse

#### Dangerous Patterns

| Pattern | Risk | Notes |
|---|---|---|
| `DES.new(...)` | High | Weak cipher (56-bit key) |
| `DES3.new(...)` with short key | Medium | 2-key 3DES is weak |
| `ARC4.new(...)` | High | RC4 is broken |
| `Blowfish.new(...)` | Medium | 64-bit block size issues |
| `AES.new(key, AES.MODE_ECB)` | High | ECB mode preserves patterns |
| `AES.new(key, AES.MODE_CBC)` with static IV | Medium | Predictable IV |
| `RSA.generate(1024)` | High | Key too short |
| `RSA.generate(512)` | Critical | Key far too short |

#### Regex Patterns

```python
# Weak ciphers
r'''\bDES\.new\s*\('''
r'''\bARC4\.new\s*\('''
r'''\bBlowfish\.new\s*\('''
r'''\bRC2\.new\s*\('''

# ECB mode
r'''MODE_ECB'''
r'''AES\.new\s*\(.*AES\.MODE_ECB'''

# Weak RSA key size
r'''RSA\.generate\s*\(\s*(?:512|768|1024)\s*\)'''

# Static / empty IV
r'''AES\.new\s*\(.*iv\s*=\s*b["\']\\x00'''
```

#### Vulnerable Code Examples

```python
# VULNERABLE: ECB mode
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(plaintext)

# VULNERABLE: Weak RSA key
from Crypto.PublicKey import RSA
key = RSA.generate(1024)

# VULNERABLE: MD5 for password hashing
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()

# VULNERABLE: random for token generation
import random
token = ''.join(random.choices('abcdef0123456789', k=32))

# VULNERABLE: SSL verification disabled
import requests
response = requests.get("https://api.example.com", verify=False)

# VULNERABLE: Unverified SSL context
import ssl
context = ssl._create_unverified_context()

# SAFE: AES-GCM
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)

# SAFE: secrets module for tokens
import secrets
token = secrets.token_hex(32)

# SAFE: bcrypt for passwords
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

---

## 7. Path Traversal

**CWE References:** CWE-22 (Path Traversal), CWE-23 (Relative Path Traversal), CWE-36 (Absolute Path Traversal), CWE-73 (External Control of File Name or Path)

### Dangerous Functions / Patterns

| Function / Pattern | Risk | Notes |
|---|---|---|
| `open(user_input)` | Critical | Direct path traversal |
| `open(os.path.join(base, user_input))` | High | os.path.join drops base on absolute input |
| `os.path.join("/base", user_input)` | High | `user_input="/etc/passwd"` replaces base |
| `pathlib.Path(base) / user_input` | Medium | Somewhat safer but still vulnerable |
| `shutil.copy(src, dst)` where src/dst user-controlled | High | File exfiltration/overwrite |
| `shutil.move(src, dst)` | High | File manipulation |
| `os.rename(src, dst)` | High | File manipulation |
| `os.remove(user_input)` / `os.unlink(user_input)` | Critical | Arbitrary file deletion |
| `send_file(user_path)` | Critical | Flask file serving |
| `send_from_directory(dir, user_filename)` | Medium | Can be bypassed with `../` |
| `FileResponse(user_path)` | Critical | Django/Starlette file serving |
| `zipfile.extractall(path)` | High | Zip slip vulnerability |
| `tarfile.extractall(path)` | Critical | Tar slip (symlink attacks) |
| `tempfile.mktemp()` | Medium | Race condition (use mkstemp) |

### Regex Patterns

```python
# open() with variable (not string literal)
r'''\bopen\s*\((?!\s*["\'])'''
r'''\bopen\s*\(\s*(?:os\.path\.join|Path)\s*\('''

# os.path.join with user-controlled component
r'''os\.path\.join\s*\(.*request\.'''
r'''os\.path\.join\s*\(.*(?:filename|filepath|path|name|file)'''

# File operations with variables
r'''(?:shutil\.(?:copy|copy2|move)|os\.(?:rename|remove|unlink))\s*\((?!\s*["\'])'''

# Flask send_file/send_from_directory
r'''\bsend_file\s*\((?!\s*["\'])'''
r'''\bsend_from_directory\s*\('''

# Zip/tar extraction
r'''\.extractall\s*\('''
r'''\.extract\s*\('''

# Django FileResponse
r'''\bFileResponse\s*\((?!\s*["\'])'''

# tempfile.mktemp (race condition)
r'''\btempfile\.mktemp\s*\('''
```

### Vulnerable Code Examples

```python
# VULNERABLE: Direct open with user input
def read_file(request):
    filename = request.GET.get("file")
    with open(filename, "r") as f:  # filename = "/etc/passwd"
        return HttpResponse(f.read())

# VULNERABLE: os.path.join with absolute path bypass
def download(request):
    filename = request.GET.get("name")
    filepath = os.path.join("/app/uploads", filename)
    # If filename = "/etc/passwd", filepath = "/etc/passwd" (base is ignored!)
    return FileResponse(open(filepath, "rb"))

# VULNERABLE: Flask send_file
@app.route("/download")
def download_file():
    filename = request.args.get("file")
    return send_file(f"/app/files/{filename}")

# VULNERABLE: Zip slip
import zipfile
def extract_upload(zip_path, dest):
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(dest)  # Archive may contain "../../../etc/cron.d/evil"

# VULNERABLE: Tar slip (even worse - symlinks)
import tarfile
def extract_tar(tar_path, dest):
    with tarfile.open(tar_path) as t:
        t.extractall(dest)  # Can write anywhere via symlinks

# SAFE: Validate and sanitize path
import os
def safe_read(request):
    filename = request.GET.get("file")
    base_dir = "/app/uploads"
    filepath = os.path.realpath(os.path.join(base_dir, filename))
    if not filepath.startswith(base_dir):
        raise PermissionError("Path traversal detected")
    with open(filepath, "r") as f:
        return HttpResponse(f.read())

# SAFE: Flask send_from_directory (with some caveats)
from flask import send_from_directory
@app.route("/download/<filename>")
def download(filename):
    return send_from_directory("/app/uploads", filename)

# SAFE: Sanitize zip extraction
def safe_extract(zip_path, dest):
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            target = os.path.realpath(os.path.join(dest, info.filename))
            if not target.startswith(os.path.realpath(dest)):
                raise ValueError("Zip slip detected")
        z.extractall(dest)
```

---

## 8. Server-Side Request Forgery (SSRF)

**CWE References:** CWE-918 (Server-Side Request Forgery)

### Dangerous Functions / Patterns

| Function | Library | Risk |
|---|---|---|
| `requests.get(user_url)` | requests | Critical |
| `requests.post(user_url, ...)` | requests | Critical |
| `requests.request(method, user_url)` | requests | Critical |
| `urllib.request.urlopen(user_url)` | stdlib | Critical |
| `urllib.request.urlretrieve(user_url)` | stdlib | Critical |
| `urllib.request.Request(user_url)` | stdlib | Critical |
| `http.client.HTTPConnection(user_host)` | stdlib | Critical |
| `httpx.get(user_url)` | httpx | Critical |
| `httpx.AsyncClient().get(user_url)` | httpx | Critical |
| `aiohttp.ClientSession().get(user_url)` | aiohttp | Critical |
| `urllib3.PoolManager().request(...)` | urllib3 | Critical |
| `socket.create_connection((user_host, port))` | stdlib | High |
| `paramiko.SSHClient().connect(user_host)` | paramiko | High |
| `ftplib.FTP(user_host)` | stdlib | High |
| `smtplib.SMTP(user_host)` | stdlib | High |
| `xmlrpc.client.ServerProxy(user_url)` | stdlib | High |

### Regex Patterns

```python
# requests library with variable URL
r'''requests\.(?:get|post|put|delete|patch|head|options|request)\s*\((?!\s*["\']https?://)'''

# urllib
r'''urllib\.request\.(?:urlopen|urlretrieve|Request)\s*\((?!\s*["\'])'''

# httpx
r'''httpx\.(?:get|post|put|delete|patch|head|options|request|Client|AsyncClient)\s*\((?!\s*["\'])'''

# aiohttp
r'''(?:aiohttp\.ClientSession|session)\.(?:get|post|put|delete|patch|head|options|request|ws_connect)\s*\((?!\s*["\'])'''

# Generic: URL from request/user input passed to HTTP function
r'''(?:url|uri|link|endpoint|target|redirect|callback|webhook)\s*=\s*request\.'''
```

### Vulnerable Code Examples

```python
# VULNERABLE: Direct SSRF
import requests
@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")
    response = requests.get(url)  # url = "http://169.254.169.254/latest/meta-data/"
    return response.text

# VULNERABLE: SSRF via redirect
def fetch_image(image_url):
    response = requests.get(image_url, allow_redirects=True)
    # Initial URL may be valid, but redirects to internal service

# VULNERABLE: urllib SSRF
import urllib.request
def proxy_request(url):
    return urllib.request.urlopen(url).read()  # url = "file:///etc/passwd"
    # urllib supports file:// scheme!

# VULNERABLE: SSRF in webhook functionality
def send_webhook(webhook_url, data):
    requests.post(webhook_url, json=data)  # webhook_url = "http://internal-service:8080/admin"

# SAFE: URL allowlisting
from urllib.parse import urlparse
ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}
def safe_fetch(url):
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Scheme not allowed")
    return requests.get(url)

# SAFE: Block internal IPs
import ipaddress
def is_internal_ip(hostname):
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(hostname))
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except (socket.gaierror, ValueError):
        return True  # Block on resolution failure
```

---

## 9. Django-Specific Vulnerabilities

### 9.1 Django Settings Misconfigurations

**CWE References:** CWE-16 (Configuration), CWE-215 (Insertion of Sensitive Information Into Debugging Code), CWE-942 (Permissive Cross-domain Policy)

#### Dangerous Settings

| Setting | Vulnerable Value | CWE | Risk |
|---|---|---|---|
| `DEBUG` | `True` (in production) | CWE-215 | Critical |
| `SECRET_KEY` | Hardcoded / default / short | CWE-798 | Critical |
| `ALLOWED_HOSTS` | `['*']` | CWE-16 | High |
| `CORS_ALLOW_ALL_ORIGINS` | `True` | CWE-942 | High |
| `CORS_ORIGIN_ALLOW_ALL` | `True` | CWE-942 | High (older django-cors-headers) |
| `CORS_ALLOW_CREDENTIALS` | `True` (with allow all) | CWE-942 | Critical |
| `SECURE_SSL_REDIRECT` | `False` | CWE-319 | Medium |
| `SECURE_HSTS_SECONDS` | `0` or absent | CWE-16 | Medium |
| `SECURE_BROWSER_XSS_FILTER` | `False` | CWE-16 | Low |
| `SECURE_CONTENT_TYPE_NOSNIFF` | `False` | CWE-16 | Medium |
| `SESSION_COOKIE_SECURE` | `False` | CWE-614 | Medium |
| `CSRF_COOKIE_SECURE` | `False` | CWE-614 | Medium |
| `SESSION_COOKIE_HTTPONLY` | `False` | CWE-1004 | Medium |
| `X_FRAME_OPTIONS` | `'ALLOW'` | CWE-1021 | Medium |
| `CSRF_TRUSTED_ORIGINS` | Overly broad domains | CWE-352 | Medium |
| `AUTH_PASSWORD_VALIDATORS` | `[]` | CWE-521 | High |

#### Regex Patterns

```python
# DEBUG in production
r'''DEBUG\s*=\s*True'''

# Insecure ALLOWED_HOSTS
r'''ALLOWED_HOSTS\s*=\s*\[\s*["\']?\*["\']?\s*\]'''
r'''ALLOWED_HOSTS\s*=\s*\[\s*\]'''  # Empty (only safe with DEBUG=True)

# CORS issues
r'''CORS_ALLOW_ALL_ORIGINS\s*=\s*True'''
r'''CORS_ORIGIN_ALLOW_ALL\s*=\s*True'''
r'''CORS_ALLOW_CREDENTIALS\s*=\s*True'''

# Missing security headers
r'''SECURE_SSL_REDIRECT\s*=\s*False'''
r'''SECURE_HSTS_SECONDS\s*=\s*0'''
r'''SECURE_CONTENT_TYPE_NOSNIFF\s*=\s*False'''
r'''SESSION_COOKIE_SECURE\s*=\s*False'''
r'''CSRF_COOKIE_SECURE\s*=\s*False'''
r'''SESSION_COOKIE_HTTPONLY\s*=\s*False'''

# Empty password validators
r'''AUTH_PASSWORD_VALIDATORS\s*=\s*\[\s*\]'''

# Default/insecure SECRET_KEY
r'''SECRET_KEY\s*=\s*["\']django-insecure-'''
```

### 9.2 Django View Vulnerabilities

#### Additional Django-Specific Patterns

```python
# Unsafe redirect
r'''HttpResponseRedirect\s*\(\s*request\.(?:GET|POST|META)'''
r'''redirect\s*\(\s*request\.(?:GET|POST)'''

# Open redirect
r'''(?:redirect|HttpResponseRedirect)\s*\(\s*(?![\"\']/)(?!\s*reverse)'''

# Raw SQL in Django
r'''connection\.cursor\(\)'''
r'''cursor\.execute\s*\(.*(?:f["\']|\.format|%)'''
```

### Vulnerable Code Examples

```python
# VULNERABLE: DEBUG in production settings
# settings/production.py
DEBUG = True  # Should ALWAYS be False in production

# VULNERABLE: Wildcard allowed hosts
ALLOWED_HOSTS = ['*']

# VULNERABLE: CORS allow all with credentials
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True  # Combined = credential theft

# VULNERABLE: Open redirect
def login_redirect(request):
    next_url = request.GET.get("next")
    return redirect(next_url)  # next_url = "https://evil.com"

# SAFE: Django's built-in url_has_allowed_host_and_scheme
from django.utils.http import url_has_allowed_host_and_scheme
def safe_redirect(request):
    next_url = request.GET.get("next", "/")
    if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
        next_url = "/"
    return redirect(next_url)
```

---

## 10. Flask-Specific Vulnerabilities

**CWE References:** CWE-215 (Debug Info Exposure), CWE-798 (Hardcoded Credentials), CWE-434 (Unrestricted File Upload)

### 10.1 Flask Configuration Issues

#### Dangerous Patterns

| Pattern | Risk | Notes |
|---|---|---|
| `app.run(debug=True)` | Critical | Werkzeug debugger = RCE in production |
| `app.debug = True` | Critical | Same |
| `DEBUG = True` in Flask config | Critical | Same |
| `app.secret_key = "..."` in source | Critical | Hardcoded secret key |
| `app.config['SECRET_KEY'] = "..."` | Critical | Hardcoded secret key |
| Missing `SECRET_KEY` | High | Sessions are insecure |
| `app.config['SESSION_COOKIE_SECURE'] = False` | Medium | Session over HTTP |

#### Regex Patterns

```python
# Debug mode
r'''app\.run\s*\(.*debug\s*=\s*True'''
r'''app\.debug\s*=\s*True'''
r'''FLASK_DEBUG\s*=\s*(?:1|True|true)'''

# Hardcoded secret key
r'''app\.secret_key\s*=\s*["\'][^"\']+["\']'''
r'''app\.config\s*\[\s*["\']SECRET_KEY["\']\s*\]\s*=\s*["\'][^"\']+["\']'''
r'''SECRET_KEY\s*=\s*["\'][^"\']+["\']'''

# Insecure session config
r'''SESSION_COOKIE_SECURE["\']?\s*[\]=:]\s*False'''
r'''SESSION_COOKIE_HTTPONLY["\']?\s*[\]=:]\s*False'''
```

### 10.2 Unsafe File Uploads

#### Dangerous Patterns

```python
# Using user-supplied filename directly
r'''file\.save\s*\(.*file\.filename'''
r'''request\.files\[.*\.filename'''

# Missing secure_filename
r'''\.save\s*\((?!.*secure_filename)'''
```

#### Vulnerable Code Examples

```python
# VULNERABLE: Debug mode in production
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
    # Werkzeug debugger allows arbitrary code execution

# VULNERABLE: Hardcoded secret key
app = Flask(__name__)
app.secret_key = "super-secret-key-123"

# VULNERABLE: Unsafe file upload
@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]
    file.save(os.path.join("/uploads", file.filename))
    # filename = "../../../etc/cron.d/malicious"

# SAFE: Secure file upload
from werkzeug.utils import secure_filename
ALLOWED_EXTENSIONS = {"png", "jpg", "gif", "pdf"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

# VULNERABLE: Returning arbitrary file
@app.route("/files/<path:filename>")
def serve_file(filename):
    return send_file(filename)  # Path traversal

# SAFE: Use send_from_directory
@app.route("/files/<path:filename>")
def serve_file(filename):
    return send_from_directory("/app/static/files", filename)
```

---

## 11. FastAPI-Specific Vulnerabilities

**CWE References:** CWE-20 (Improper Input Validation), CWE-862 (Missing Authorization), CWE-285 (Improper Authorization)

### 11.1 Missing Security Dependencies

#### Dangerous Patterns

| Pattern | Risk | Notes |
|---|---|---|
| Endpoint without `Depends(...)` for auth | High | No authentication |
| Missing `Security(...)` dependency | High | No authorization check |
| `OAuth2PasswordBearer` without actual validation | High | Token accepted but not verified |
| Route without response_model (data leakage) | Medium | May expose internal fields |
| `allow_origins=["*"]` in CORSMiddleware | High | Open CORS |
| `allow_credentials=True` with `allow_origins=["*"]` | Critical | Credential theft |

#### Regex Patterns

```python
# CORS misconfiguration
r'''allow_origins\s*=\s*\[\s*["\']?\*["\']?\s*\]'''
r'''allow_credentials\s*=\s*True'''

# Missing Depends on routes (heuristic)
r'''@app\.(?:get|post|put|delete|patch)\s*\((?!.*Depends)'''

# Debug mode
r'''uvicorn\.run\s*\(.*reload\s*=\s*True'''  # Not dangerous per se, but indicates dev mode

# Missing response_model
r'''@app\.(?:get|post|put|delete|patch)\s*\([^)]*\)\s*\n\s*(?:async\s+)?def\s+\w+\s*\([^)]*\)(?!\s*->)'''
```

### 11.2 Pydantic Validation Bypass

#### Dangerous Patterns

| Pattern | Risk | Notes |
|---|---|---|
| `model.dict()` / `model.model_dump()` without `exclude` | Medium | May include sensitive fields |
| Using `Any` type in Pydantic models | Medium | No validation |
| `model_config = ConfigDict(extra="allow")` | Medium | Accepts arbitrary fields |
| Raw dict access instead of Pydantic model | High | Bypasses validation |
| `@validator` with `pre=True, always=True` pitfalls | Medium | Complex validation issues |

#### Regex Patterns

```python
# Pydantic allowing extra fields
r'''extra\s*=\s*["\']allow["\']'''
r'''extra\s*=\s*Extra\.allow'''
r'''model_config\s*=\s*ConfigDict\s*\(.*extra\s*=\s*["\']allow["\']'''

# Any type in models
r''':\s*Any\b'''

# Raw body without validation
r'''await\s+request\.json\s*\(\s*\)'''
r'''await\s+request\.body\s*\(\s*\)'''
```

#### Vulnerable Code Examples

```python
# VULNERABLE: No authentication dependency
from fastapi import FastAPI
app = FastAPI()

@app.get("/admin/users")
async def list_users():  # No Depends(get_current_user) !
    return get_all_users()

# VULNERABLE: CORS allow all with credentials
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,  # Combined with * = security issue
    allow_methods=["*"],
    allow_headers=["*"],
)

# VULNERABLE: Using raw request body instead of Pydantic model
@app.post("/items")
async def create_item(request: Request):
    data = await request.json()  # No validation!
    return db.items.insert(data)  # Potential NoSQL injection too

# VULNERABLE: Pydantic model allowing extra fields
from pydantic import BaseModel, ConfigDict
class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str
    # Attacker can send {"name": "test", "is_admin": true}

# VULNERABLE: Exposing internal model directly
class UserInternal(BaseModel):
    id: int
    name: str
    password_hash: str  # Sensitive!
    email: str

@app.get("/users/{user_id}")
async def get_user(user_id: int) -> UserInternal:  # Exposes password_hash!
    return db.get_user(user_id)

# SAFE: Proper auth dependency
from fastapi import Depends, Security
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    user = verify_token(token)
    if not user:
        raise HTTPException(status_code=401)
    return user

@app.get("/admin/users")
async def list_users(current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403)
    return get_all_users()

# SAFE: Separate response model
class UserResponse(BaseModel):
    id: int
    name: str
    email: str

@app.get("/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: int):
    return db.get_user(user_id)
```

---

## 12. Deserialization Vulnerabilities (Expanded)

**CWE References:** CWE-502 (Deserialization of Untrusted Data), CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)

### XML External Entity (XXE)

**CWE References:** CWE-611 (Improper Restriction of XML External Entity Reference)

#### Dangerous Functions

| Function | Library | Risk |
|---|---|---|
| `xml.etree.ElementTree.parse(source)` | stdlib | Medium (defused in Python 3.8+) |
| `xml.sax.parse(source)` | stdlib | High |
| `xml.dom.minidom.parse(source)` | stdlib | High |
| `xml.dom.pulldom.parse(source)` | stdlib | High |
| `lxml.etree.parse(source)` | lxml | High (if resolving entities) |
| `lxml.etree.fromstring(source)` | lxml | High |
| `xmlrpc.client.ServerProxy(url)` | stdlib | Medium |
| `xml.etree.ElementTree.iterparse(source)` | stdlib | Medium |

#### Regex Patterns

```python
# XML parsing (all potentially vulnerable)
r'''\bxml\.etree\.ElementTree\.(?:parse|fromstring|iterparse)\s*\('''
r'''\bxml\.sax\.(?:parse|parseString|make_parser)\s*\('''
r'''\bxml\.dom\.minidom\.(?:parse|parseString)\s*\('''
r'''\bxml\.dom\.pulldom\.(?:parse|parseString)\s*\('''
r'''\blxml\.etree\.(?:parse|fromstring|XML|iterparse)\s*\('''

# Safe alternative detection (positive signal)
r'''\bdefusedxml\.\w+\.(?:parse|fromstring)\s*\('''
```

#### Vulnerable Code Examples

```python
# VULNERABLE: lxml with entity resolution
from lxml import etree
def parse_xml(xml_data):
    parser = etree.XMLParser(resolve_entities=True)
    tree = etree.fromstring(xml_data, parser=parser)
    # XML payload: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>

# VULNERABLE: stdlib xml parsing
import xml.etree.ElementTree as ET
tree = ET.parse(user_uploaded_file)  # XXE in older Python

# SAFE: defusedxml
import defusedxml.ElementTree as ET
tree = ET.parse(user_uploaded_file)

# SAFE: lxml with entity resolution disabled
parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.fromstring(xml_data, parser=parser)
```

---

## 13. Regex-Based Detection Strategy

### Priority Classification

For building a practical security audit tool, categorize findings into severity tiers:

#### Tier 1 - Critical (Almost Always Vulnerable)

These patterns almost always indicate a security vulnerability:

```python
CRITICAL_PATTERNS = {
    "CWE-78": [  # OS Command Injection
        r'os\.system\s*\(\s*f["\']',
        r'os\.popen\s*\(\s*f["\']',
        r'subprocess\.(?:call|run|Popen|check_output)\s*\(.*shell\s*=\s*True',
    ],
    "CWE-95": [  # Eval Injection
        r'\beval\s*\(\s*request\.',
        r'\bexec\s*\(\s*request\.',
    ],
    "CWE-502": [  # Deserialization
        r'pickle\.loads?\s*\(',
        r'yaml\.load\s*\((?!.*SafeLoader)',
        r'yaml\.unsafe_load\s*\(',
    ],
    "CWE-798": [  # Hardcoded Credentials
        r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}',
        r'AKIA[0-9A-Z]{16}',
    ],
    "CWE-79": [  # XSS
        r'mark_safe\s*\(\s*f["\']',
        r'Markup\s*\(\s*f["\']',
        r'render_template_string\s*\(\s*request\.',
    ],
    "CWE-89": [  # SQL Injection
        r'\.execute\s*\(\s*f["\']',
        r'\.raw\s*\(\s*f["\']',
    ],
}
```

#### Tier 2 - High (Likely Vulnerable, Needs Context)

```python
HIGH_PATTERNS = {
    "CWE-89": [  # SQL Injection
        r'\.execute\s*\(\s*["\'].*%',
        r'\.execute\s*\(\s*["\'].*\.format\s*\(',
        r'\.objects\.extra\s*\(',
        r'RawSQL\s*\(',
    ],
    "CWE-22": [  # Path Traversal
        r'open\s*\(\s*(?:os\.path\.join|request\.)',
        r'send_file\s*\((?!\s*["\'])',
        r'\.extractall\s*\(',
    ],
    "CWE-918": [  # SSRF
        r'requests\.(?:get|post)\s*\(\s*(?:url|request\.|user)',
        r'urllib\.request\.urlopen\s*\((?!\s*["\'])',
    ],
    "CWE-327": [  # Weak Crypto
        r'hashlib\.md5\s*\(',
        r'AES\.MODE_ECB',
        r'DES\.new\s*\(',
    ],
    "CWE-295": [  # Certificate Validation
        r'verify\s*=\s*False',
        r'ssl\._create_unverified_context',
        r'ssl\.CERT_NONE',
    ],
    "CWE-215": [  # Debug Information
        r'DEBUG\s*=\s*True',
        r'app\.run\s*\(.*debug\s*=\s*True',
    ],
}
```

#### Tier 3 - Medium (Potential Issue, Requires Review)

```python
MEDIUM_PATTERNS = {
    "CWE-330": [  # Weak Random
        r'random\.(?:random|randint|choice|choices)\s*\(',
    ],
    "CWE-16": [  # Configuration
        r'ALLOWED_HOSTS\s*=\s*\[\s*["\']?\*',
        r'CORS_ALLOW_ALL_ORIGINS\s*=\s*True',
        r'allow_origins\s*=\s*\[\s*["\']?\*',
    ],
    "CWE-532": [  # Log Injection / Info Leak
        r'logging\..*(?:password|secret|token|key|credential)',
        r'print\s*\(.*(?:password|secret|token|key)',
    ],
    "CWE-352": [  # CSRF
        r'@csrf_exempt',
    ],
}
```

### False Positive Mitigation Strategies

1. **Context-Aware Analysis**: Check if the variable passed to dangerous functions comes from user input (request, argv, stdin, file read) vs internal constants.

2. **Ignore Test Files**: Patterns in `test_*.py`, `*_test.py`, `conftest.py`, and `tests/` directories are lower priority.

3. **Check for Sanitization Nearby**: Look for sanitization functions within N lines before the dangerous call:
   - `shlex.quote()` before `subprocess` calls
   - `escape_filter_chars()` before LDAP queries
   - `bleach.clean()` before `mark_safe()`
   - `secure_filename()` before `file.save()`
   - Parameterized queries (`%s`, `:param`) in SQL strings
   - `os.path.realpath()` + `.startswith()` before `open()`

4. **Configuration File Detection**: Flag settings issues only in files matching `settings*.py`, `config*.py`, `.env`, `*.cfg`, `*.ini`, `*.yaml`, `*.toml`.

5. **Comment / Docstring Exclusion**: Exclude matches found inside comments (`#`) or docstrings (`"""..."""`).

### Comprehensive Dangerous Function Reference (Quick Lookup)

```
INJECTION:
  cursor.execute()      cursor.executemany()    Model.objects.raw()
  Model.objects.extra()  RawSQL()               text() [SQLAlchemy]
  os.system()           os.popen()              subprocess.*(shell=True)
  subprocess.getoutput() asyncio.create_subprocess_shell()
  ldap.search_s()       render_template_string() Template().render()
  Environment.from_string()

CODE EXECUTION:
  eval()                exec()                  compile()
  __import__()          importlib.import_module()
  pickle.load/loads()   shelve.open()           marshal.load/loads()
  yaml.load()           yaml.unsafe_load()      jsonpickle.decode()
  dill.load/loads()     torch.load()            joblib.load()
  numpy.load(allow_pickle=True)                 pandas.read_pickle()

AUTHENTICATION:
  @csrf_exempt          jwt.decode(verify=False) permission_classes=[]

XSS:
  mark_safe()           Markup()                |safe filter
  {% autoescape off %}  SafeString()            SafeText()

CRYPTO:
  hashlib.md5()         hashlib.sha1()          random.random()
  random.randint()      DES.new()               ARC4.new()
  AES.MODE_ECB          RSA.generate(1024)

NETWORK:
  requests.get()        urllib.request.urlopen() httpx.get()
  verify=False          ssl._create_unverified_context()
  ssl.CERT_NONE

FILES:
  open()                send_file()             send_from_directory()
  FileResponse()        .extractall()           shutil.copy/move()
  os.remove()           os.rename()             tempfile.mktemp()

XML:
  xml.etree.ElementTree.parse()                 xml.sax.parse()
  xml.dom.minidom.parse()                       lxml.etree.parse()
  lxml.etree.fromstring()
```

### CWE Quick Reference Table

| CWE | Name | Primary Python Vectors |
|---|---|---|
| CWE-22 | Path Traversal | `open()`, `os.path.join()`, `send_file()` |
| CWE-78 | OS Command Injection | `os.system()`, `subprocess(shell=True)` |
| CWE-79 | XSS | `mark_safe()`, `Markup()`, `\|safe` |
| CWE-89 | SQL Injection | `cursor.execute()`, `objects.raw()`, `text()` |
| CWE-90 | LDAP Injection | `ldap.search_s()`, `Connection.search()` |
| CWE-94 | Code Injection | `eval()`, `exec()`, `compile()` |
| CWE-95 | Eval Injection | `eval()` with user input |
| CWE-98 | Remote File Include | `__import__()`, `importlib` |
| CWE-215 | Debug Info Exposure | `DEBUG=True`, `app.run(debug=True)` |
| CWE-287 | Improper Auth | Missing `@login_required`, empty permissions |
| CWE-295 | Cert Validation | `verify=False`, `CERT_NONE` |
| CWE-312 | Cleartext Storage | Logging passwords, hardcoded secrets |
| CWE-326 | Inadequate Encryption | `DES`, `RC4`, small RSA keys |
| CWE-327 | Broken Crypto | `MD5`, `SHA1` for security |
| CWE-328 | Weak Hash | `hashlib.md5()` for passwords |
| CWE-330 | Weak Random | `random` module for security |
| CWE-345 | Insufficient Verification | JWT `verify=False` |
| CWE-347 | Improper Crypto Sig Verification | JWT `algorithms=["none"]` |
| CWE-352 | CSRF | `@csrf_exempt` |
| CWE-384 | Session Fixation | Missing session rotation |
| CWE-434 | Unrestricted Upload | Missing `secure_filename()` |
| CWE-502 | Insecure Deserialization | `pickle`, `yaml.load()`, `torch.load()` |
| CWE-521 | Weak Password Policy | Empty `AUTH_PASSWORD_VALIDATORS` |
| CWE-532 | Log Info Exposure | Logging secrets/passwords |
| CWE-611 | XXE | `xml.etree`, `lxml.etree`, `xml.sax` |
| CWE-613 | Insufficient Session Expiry | Missing session timeout |
| CWE-614 | Insecure Cookie | `SESSION_COOKIE_SECURE=False` |
| CWE-798 | Hardcoded Credentials | Passwords/keys in source code |
| CWE-862 | Missing Authorization | No auth decorators on views |
| CWE-918 | SSRF | `requests.get(user_url)` |
| CWE-942 | Permissive CORS | `CORS_ALLOW_ALL_ORIGINS=True` |
| CWE-1004 | No HttpOnly Cookie | `SESSION_COOKIE_HTTPONLY=False` |
| CWE-1021 | Improper Restriction of Rendered UI | `X_FRAME_OPTIONS='ALLOW'` |
| CWE-1336 | Template Injection | `Template(user_input)`, SSTI |

---

*This document was compiled for building a Python-focused static security analysis tool. All regex patterns are designed for single-line matching and should be tested against representative codebases before deployment. For production use, consider combining regex detection with AST-based analysis for higher accuracy.*
