# Go Security Vulnerability Research for Static Analysis / Audit Tooling

> Compiled for building regex-based and AST-aware security scanners targeting Go source code.
> Each category includes CWE references, dangerous identifiers suitable for pattern matching,
> and concrete vulnerable code examples.

---

## Table of Contents

1. [SQL Injection](#1-sql-injection)
2. [Command Injection](#2-command-injection)
3. [Template Confusion / XSS](#3-template-confusion--xss)
4. [TLS / Certificate Issues](#4-tls--certificate-issues)
5. [Deserialization / Unsafe Unmarshalling](#5-deserialization--unsafe-unmarshalling)
6. [Unsafe Package Misuse](#6-unsafe-package-misuse)
7. [Race Conditions](#7-race-conditions)
8. [Weak Cryptography](#8-weak-cryptography)
9. [Path Traversal](#9-path-traversal)
10. [Server-Side Request Forgery (SSRF)](#10-server-side-request-forgery-ssrf)
11. [Hardcoded Secrets](#11-hardcoded-secrets)
12. [Framework-Specific (Gin / Echo / Chi)](#12-framework-specific-gin--echo--chi)
13. [Error Handling](#13-error-handling)

---

## 1. SQL Injection

### CWE References
| CWE | Name |
|-----|------|
| CWE-89 | Improper Neutralization of Special Elements used in an SQL Command ("SQL Injection") |
| CWE-564 | SQL Injection: Hibernate (analogous for GORM/sqlx) |
| CWE-943 | Improper Neutralization of Special Elements in Data Query Logic |

### Dangerous Functions / Patterns

**Standard library (`database/sql`):**
- `db.Query(fmt.Sprintf(...))` -- formatted string passed as query
- `db.QueryRow(fmt.Sprintf(...))` -- same for single row
- `db.Exec(fmt.Sprintf(...))` -- same for exec
- `db.Query("SELECT ... " + userInput)` -- string concatenation in query
- `db.QueryRow("SELECT ... " + userInput)`
- `db.Exec("DELETE ... " + userInput)`
- Any call to `db.Query`, `db.QueryRow`, `db.Exec`, `db.Prepare` where the first argument is not a string literal but a variable or expression

**ORM / query-builder libraries:**
- `gorm.DB.Raw(fmt.Sprintf(...))` -- raw SQL with formatting
- `gorm.DB.Exec(fmt.Sprintf(...))`
- `gorm.DB.Where(fmt.Sprintf(...))`  -- Where with formatted string instead of placeholder
- `gorm.DB.Order(userInput)` -- ORDER BY injection
- `gorm.DB.Group(userInput)` -- GROUP BY injection
- `sqlx.DB.Select(..., fmt.Sprintf(...))`
- `sqlx.DB.Get(..., fmt.Sprintf(...))`
- `squirrel` builder with `.Suffix(userInput)` or `.Prefix(userInput)`

**Regex patterns for detection:**
```
# Pattern 1: fmt.Sprintf used in SQL context
fmt\.Sprintf\s*\(\s*["'](?i)(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|UNION|MERGE)\b

# Pattern 2: String concatenation in SQL query functions
\.(Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext)\s*\([^)]*\+

# Pattern 3: fmt.Sprintf passed to query functions
\.(Query|QueryRow|Exec)\s*\(\s*fmt\.Sprintf

# Pattern 4: GORM raw/where with formatting
\.(Raw|Exec|Where|Having|Order|Group)\s*\(\s*fmt\.Sprintf

# Pattern 5: Variable (non-literal) as first arg to query
\.(Query|QueryRow|Exec)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[,)]
```

### Vulnerable Code Examples

```go
// VULNERABLE: String concatenation in Query
func getUser(db *sql.DB, username string) (*User, error) {
    query := "SELECT id, name, email FROM users WHERE username = '" + username + "'"
    row := db.QueryRow(query)
    // ...
}

// VULNERABLE: fmt.Sprintf in Query
func searchProducts(db *sql.DB, category string) (*sql.Rows, error) {
    query := fmt.Sprintf("SELECT * FROM products WHERE category = '%s'", category)
    return db.Query(query)
}

// VULNERABLE: fmt.Sprintf for ORDER BY
func listUsers(db *sql.DB, sortCol string) (*sql.Rows, error) {
    query := fmt.Sprintf("SELECT * FROM users ORDER BY %s", sortCol)
    return db.Query(query)
}

// VULNERABLE: GORM Raw with Sprintf
func findByName(db *gorm.DB, name string) ([]User, error) {
    var users []User
    db.Raw(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)).Scan(&users)
    return users, nil
}

// VULNERABLE: GORM Where with string formatting
func findUser(db *gorm.DB, email string) User {
    var user User
    db.Where(fmt.Sprintf("email = '%s'", email)).First(&user)
    return user
}

// SAFE: Parameterized query
func getUser(db *sql.DB, username string) (*User, error) {
    row := db.QueryRow("SELECT id, name, email FROM users WHERE username = $1", username)
    // ...
}

// SAFE: GORM with placeholder
func findUser(db *gorm.DB, email string) User {
    var user User
    db.Where("email = ?", email).First(&user)
    return user
}
```

---

## 2. Command Injection

### CWE References
| CWE | Name |
|-----|------|
| CWE-78 | Improper Neutralization of Special Elements used in an OS Command ("OS Command Injection") |
| CWE-88 | Improper Neutralization of Argument Delimiters in a Command ("Argument Injection") |
| CWE-77 | Improper Neutralization of Special Elements used in a Command ("Command Injection") |

### Dangerous Functions / Patterns

**Primary dangerous calls:**
- `exec.Command("sh", "-c", userInput)` -- shell invocation with user input
- `exec.Command("bash", "-c", userInput)`
- `exec.Command("/bin/sh", "-c", userInput)`
- `exec.Command(userInput)` -- user controls the binary name
- `exec.Command(binary, userInput...)` -- user controls arguments
- `exec.CommandContext(ctx, "sh", "-c", userInput)`
- `syscall.Exec(userInput, ...)` -- direct syscall with user input
- `syscall.StartProcess(userInput, ...)`
- `os.StartProcess(userInput, ...)`
- `exec.Command("cmd", "/c", userInput)` -- Windows variant

**Concatenation in command strings:**
- `exec.Command("sh", "-c", "command " + userInput)`
- `exec.Command("sh", "-c", fmt.Sprintf("command %s", userInput))`

**Regex patterns for detection:**
```
# Pattern 1: Shell invocation with variable argument
exec\.Command\s*\(\s*["'](sh|bash|/bin/sh|/bin/bash|cmd|cmd\.exe|powershell)["']\s*,\s*["']-c["']\s*,

# Pattern 2: exec.Command with fmt.Sprintf
exec\.Command\s*\([^)]*fmt\.Sprintf

# Pattern 3: exec.Command with string concatenation
exec\.Command\s*\([^)]*\+

# Pattern 4: exec.Command where first arg is a variable (user controls binary)
exec\.Command\s*\(\s*[a-z_][a-zA-Z0-9_]*\s*[,)]

# Pattern 5: syscall.Exec / os.StartProcess
(syscall\.Exec|syscall\.StartProcess|os\.StartProcess)\s*\(

# Pattern 6: CommandContext with shell
exec\.CommandContext\s*\([^,]+,\s*["'](sh|bash|/bin/sh|/bin/bash)["']
```

### Vulnerable Code Examples

```go
// VULNERABLE: Shell invocation with user input
func runCommand(userInput string) ([]byte, error) {
    cmd := exec.Command("sh", "-c", userInput)
    return cmd.Output()
}

// VULNERABLE: String concatenation in shell command
func ping(host string) ([]byte, error) {
    cmd := exec.Command("sh", "-c", "ping -c 4 " + host)
    return cmd.Output()
}

// VULNERABLE: fmt.Sprintf in shell command
func lookupDNS(domain string) ([]byte, error) {
    cmdStr := fmt.Sprintf("nslookup %s", domain)
    cmd := exec.Command("bash", "-c", cmdStr)
    return cmd.Output()
}

// VULNERABLE: User controls binary path
func execTool(toolPath string, args ...string) error {
    cmd := exec.Command(toolPath, args...)
    return cmd.Run()
}

// VULNERABLE: Argument injection (no shell but user controls args)
func gitClone(repoURL string) error {
    // repoURL could be "--upload-pack=malicious" or contain shell metacharacters
    cmd := exec.Command("git", "clone", repoURL)
    return cmd.Run()
}

// SAFE: Hardcoded command, separate validated arguments
func ping(host string) ([]byte, error) {
    // Validate host is an IP or hostname only
    if !isValidHostname(host) {
        return nil, fmt.Errorf("invalid hostname")
    }
    cmd := exec.Command("ping", "-c", "4", host)
    return cmd.Output()
}
```

---

## 3. Template Confusion / XSS

### CWE References
| CWE | Name |
|-----|------|
| CWE-79 | Improper Neutralization of Input During Web Page Generation ("Cross-site Scripting") |
| CWE-80 | Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) |
| CWE-116 | Improper Encoding or Escaping of Output |

### Dangerous Functions / Patterns

**The core issue:** Go has two template packages:
- `text/template` -- NO auto-escaping (intended for plain text)
- `html/template` -- contextual auto-escaping (intended for HTML)

Using `text/template` to render HTML is inherently dangerous.

**Dangerous imports and calls:**
- `import "text/template"` in HTTP handler code (should be `html/template`)
- `template.HTML(userInput)` -- casts string to `template.HTML`, bypassing escaping
- `template.JS(userInput)` -- casts string to `template.JS`, bypassing JS escaping
- `template.CSS(userInput)` -- casts string to `template.CSS`, bypassing CSS escaping
- `template.HTMLAttr(userInput)` -- bypasses attribute escaping
- `template.URL(userInput)` -- bypasses URL escaping
- `template.Srcset(userInput)` -- bypasses srcset escaping

**Regex patterns for detection:**
```
# Pattern 1: text/template import (potential misuse for HTML)
import\s+["']text/template["']
import\s*\(\s*[^)]*["']text/template["']

# Pattern 2: Dangerous type conversions that bypass escaping
template\.HTML\s*\(
template\.JS\s*\(
template\.CSS\s*\(
template\.HTMLAttr\s*\(
template\.URL\s*\(
template\.Srcset\s*\(

# Pattern 3: Direct Write of user input (no template, manual HTML construction)
(w\.Write|io\.WriteString|fmt\.Fprintf)\s*\([^)]*\.(?:FormValue|URL\.Query|Header\.Get)

# Pattern 4: ResponseWriter Write with string concat containing user data
w\.Write\s*\(\s*\[\]byte\s*\(\s*["']<[^>]*["']\s*\+
```

### Vulnerable Code Examples

```go
// VULNERABLE: Using text/template for HTML output
import "text/template"

func handler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    tmpl := template.Must(template.New("page").Parse("<h1>Hello {{.Name}}</h1>"))
    tmpl.Execute(w, map[string]string{"Name": name})
    // Input: name=<script>alert(1)</script> -> XSS
}

// VULNERABLE: template.HTML() bypass
import "html/template"

func handler(w http.ResponseWriter, r *http.Request) {
    comment := r.FormValue("comment")
    data := map[string]interface{}{
        "Comment": template.HTML(comment), // Bypasses auto-escaping!
    }
    tmpl.Execute(w, data)
}

// VULNERABLE: template.JS() bypass
func handler(w http.ResponseWriter, r *http.Request) {
    callback := r.URL.Query().Get("callback")
    data := map[string]interface{}{
        "Callback": template.JS(callback), // Bypasses JS escaping
    }
    tmpl.Execute(w, data)
}

// VULNERABLE: Direct write of user input into response
func handler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    w.Header().Set("Content-Type", "text/html")
    fmt.Fprintf(w, "<h1>Hello %s</h1>", name) // XSS
}

// SAFE: html/template with no type casting bypass
import "html/template"

func handler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    tmpl := template.Must(template.New("page").Parse("<h1>Hello {{.Name}}</h1>"))
    tmpl.Execute(w, map[string]string{"Name": name})
    // Auto-escaped: <script> becomes &lt;script&gt;
}
```

---

## 4. TLS / Certificate Issues

### CWE References
| CWE | Name |
|-----|------|
| CWE-295 | Improper Certificate Validation |
| CWE-297 | Improper Validation of Certificate with Host Mismatch |
| CWE-319 | Cleartext Transmission of Sensitive Information |
| CWE-326 | Inadequate Encryption Strength |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm |
| CWE-757 | Selection of Less-Secure Algorithm During Negotiation ("Algorithm Downgrade") |

### Dangerous Functions / Patterns

**InsecureSkipVerify:**
- `tls.Config{InsecureSkipVerify: true}` -- disables certificate verification entirely
- `&tls.Config{InsecureSkipVerify: true}`

**Missing MinVersion (allows TLS 1.0/1.1):**
- `tls.Config{}` without `MinVersion: tls.VersionTLS12` (or 1.3)
- `tls.Config{MinVersion: tls.VersionTLS10}` -- explicitly allows old TLS
- `tls.Config{MinVersion: tls.VersionTLS11}` -- TLS 1.1 is deprecated

**Weak cipher suites:**
- `tls.TLS_RSA_WITH_RC4_128_SHA`
- `tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA`
- `tls.TLS_RSA_WITH_AES_128_CBC_SHA` (no forward secrecy)
- `tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA`
- `tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA`
- Any cipher suite containing `RC4`, `3DES`, or `DES` in the name

**Other TLS misconfigurations:**
- `tls.Config{MaxVersion: tls.VersionTLS11}` -- caps at old version
- Custom `VerifyPeerCertificate` that always returns nil
- Custom `VerifyConnection` that always returns nil

**Regex patterns for detection:**
```
# Pattern 1: InsecureSkipVerify
InsecureSkipVerify\s*:\s*true

# Pattern 2: Weak MinVersion
MinVersion\s*:\s*tls\.VersionTLS1[01]\b
MinVersion\s*:\s*tls\.VersionSSL30

# Pattern 3: Weak cipher suites
tls\.TLS_.*RC4
tls\.TLS_.*3DES
tls\.TLS_RSA_WITH_AES_\d+_CBC

# Pattern 4: MaxVersion capping at old TLS
MaxVersion\s*:\s*tls\.VersionTLS1[01]

# Pattern 5: Empty VerifyPeerCertificate (noop verification)
VerifyPeerCertificate\s*:\s*func\s*\([^)]*\)\s*error\s*\{\s*return\s+nil\s*\}

# Pattern 6: tls.Config without MinVersion (heuristic -- look for tls.Config literal without MinVersion)
tls\.Config\s*\{[^}]*\}
# (then check if MinVersion is absent -- requires multi-line analysis)
```

### Vulnerable Code Examples

```go
// VULNERABLE: InsecureSkipVerify disables cert validation
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true, // MITM possible
        },
    },
}

// VULNERABLE: Allows TLS 1.0
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS10,
}

// VULNERABLE: Weak cipher suites
tlsConfig := &tls.Config{
    CipherSuites: []uint16{
        tls.TLS_RSA_WITH_RC4_128_SHA,
        tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    },
}

// VULNERABLE: No MinVersion set (defaults to TLS 1.0 in older Go, TLS 1.2 in Go 1.18+)
// Still flagged as explicit is better than implicit
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
}

// VULNERABLE: Noop certificate verification
tlsConfig := &tls.Config{
    VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
        return nil // Always passes -- defeats purpose of TLS
    },
}

// SAFE: Proper TLS configuration
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS12,
    CipherSuites: []uint16{
        tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
        tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
    },
}
```

---

## 5. Deserialization / Unsafe Unmarshalling

### CWE References
| CWE | Name |
|-----|------|
| CWE-502 | Deserialization of Untrusted Data |
| CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| CWE-843 | Access of Resource Using Incompatible Type ("Type Confusion") |

### Dangerous Functions / Patterns

**encoding/gob:**
- `gob.NewDecoder(r).Decode(&target)` where `r` comes from untrusted source
- `gob.Register(...)` with broad interface types
- Gob can instantiate arbitrary registered types -- if an attacker controls the gob stream and types are registered broadly, they can cause unexpected behavior

**encoding/json with interface{}:**
- `json.Unmarshal(data, &map[string]interface{})` -- type confusion risks
- `json.NewDecoder(r.Body).Decode(&interface{})` -- decoding into empty interface
- Unchecked type assertions after decoding: `result["key"].(string)` -- panics on wrong type

**encoding/xml:**
- `xml.NewDecoder(r).Decode(&target)` -- XML external entity (XXE) is NOT a default risk in Go's xml package (it doesn't process external entities), but billion-laughs DoS is possible
- `xml.Decoder` without `xml.Decoder.Strict` considerations

**Other serialization:**
- `encoding/gob` -- arbitrary type instantiation
- `encoding/binary.Read` with user-controlled size fields -- potential DoS
- Third-party: `github.com/vmihailenco/msgpack`, `github.com/ugorji/go/codec` -- same risks as gob

**Regex patterns for detection:**
```
# Pattern 1: gob decoding from untrusted sources
gob\.NewDecoder\s*\(

# Pattern 2: json.Unmarshal into interface{}
json\.Unmarshal\s*\([^,]+,\s*&?(?:interface\{\}|map\[string\]interface\{\})

# Pattern 3: json.Decoder from HTTP body
json\.NewDecoder\s*\(\s*r\.Body\s*\)

# Pattern 4: Unsafe type assertions (no ok check)
\.\(\s*(?:string|int|float64|bool|\[\]interface\{\}|map\[string\]interface\{\})\s*\)(?!\s*;?\s*(?:if|;))
# (Heuristic: type assertion without comma-ok pattern)

# Pattern 5: yaml.Unmarshal (gopkg.in/yaml.v2 had code execution via !!python/object)
yaml\.Unmarshal\s*\(
```

### Vulnerable Code Examples

```go
// VULNERABLE: gob decoding from network
func handleConnection(conn net.Conn) {
    var msg Message
    dec := gob.NewDecoder(conn)
    err := dec.Decode(&msg) // Attacker controls bytes
    if err != nil {
        log.Println(err)
        return
    }
    processMessage(msg)
}

// VULNERABLE: JSON into interface{} with unchecked type assertion
func handleJSON(w http.ResponseWriter, r *http.Request) {
    var data map[string]interface{}
    json.NewDecoder(r.Body).Decode(&data)

    // PANIC if "age" is not a float64 (JSON numbers are float64)
    age := data["age"].(int)    // Will panic -- type confusion
    name := data["name"].(string) // Will panic if nil or wrong type
    _ = age
    _ = name
}

// VULNERABLE: No size limit on decoded data -- DoS
func handleRequest(w http.ResponseWriter, r *http.Request) {
    var payload LargeStruct
    // No limit on r.Body size
    json.NewDecoder(r.Body).Decode(&payload)
}

// SAFE: Type assertion with ok check
func handleJSON(w http.ResponseWriter, r *http.Request) {
    var data map[string]interface{}
    if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&data); err != nil {
        http.Error(w, "bad request", 400)
        return
    }
    name, ok := data["name"].(string)
    if !ok {
        http.Error(w, "invalid name field", 400)
        return
    }
    _ = name
}
```

---

## 6. Unsafe Package Misuse

### CWE References
| CWE | Name |
|-----|------|
| CWE-822 | Untrusted Pointer Dereference |
| CWE-823 | Use of Out-of-range Pointer Offset |
| CWE-843 | Access of Resource Using Incompatible Type ("Type Confusion") |
| CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer |
| CWE-787 | Out-of-bounds Write |

### Dangerous Functions / Patterns

**unsafe package:**
- `import "unsafe"` -- any usage is a flag worth reviewing
- `unsafe.Pointer(...)` -- arbitrary pointer casting
- `unsafe.Sizeof(...)` -- used in unsafe arithmetic
- `unsafe.Offsetof(...)` -- struct field offset
- `unsafe.Alignof(...)` -- alignment queries
- `unsafe.Add(ptr, offset)` -- pointer arithmetic (Go 1.17+)
- `unsafe.Slice(ptr, len)` -- create slice from pointer (Go 1.17+)
- `unsafe.SliceData(s)` -- get pointer from slice (Go 1.20+)
- `unsafe.String(ptr, len)` -- create string from pointer (Go 1.20+)
- `unsafe.StringData(s)` -- get pointer from string (Go 1.20+)
- `uintptr(unsafe.Pointer(...))` -- dangerous: GC can move the object between conversion

**reflect package for type safety bypass:**
- `reflect.NewAt(...)` -- create value at arbitrary memory
- `reflect.ValueOf(...).Pointer()` -- extract raw pointer
- `reflect.ValueOf(...).UnsafeAddr()` -- get address
- `reflect.SliceHeader` -- manual slice manipulation (deprecated in Go 1.20+)
- `reflect.StringHeader` -- manual string manipulation (deprecated in Go 1.20+)
- `reflect.Value.SetString/SetInt/etc` on unexported fields via `reflect.Value.UnsafeAddr()`

**cgo:**
- `// #include` with `import "C"` -- cgo can introduce memory safety issues
- `C.CString(...)` -- must be freed, leak risk
- `C.GoString(...)`, `C.GoBytes(...)` -- boundary crossing

**Regex patterns for detection:**
```
# Pattern 1: unsafe import
import\s+["']unsafe["']
import\s*\(\s*[^)]*["']unsafe["']

# Pattern 2: unsafe.Pointer usage
unsafe\.Pointer\s*\(
uintptr\s*\(\s*unsafe\.Pointer

# Pattern 3: unsafe.Add / unsafe.Slice (Go 1.17+)
unsafe\.Add\s*\(
unsafe\.Slice\s*\(
unsafe\.String\s*\(

# Pattern 4: reflect for bypassing type safety
reflect\.NewAt\s*\(
reflect\.SliceHeader
reflect\.StringHeader
\.UnsafeAddr\s*\(

# Pattern 5: cgo usage
import\s+"C"
```

### Vulnerable Code Examples

```go
// VULNERABLE: unsafe.Pointer to bypass type system
func unsafeCast(i int64) float64 {
    return *(*float64)(unsafe.Pointer(&i))
}

// VULNERABLE: Pointer arithmetic with uintptr (GC-unsafe)
func readField(s *MyStruct) int {
    // If GC moves s between uintptr conversion and dereference, this is UB
    p := uintptr(unsafe.Pointer(s)) + unsafe.Offsetof(s.Field)
    return *(*int)(unsafe.Pointer(p)) // BUG: uintptr is not a pointer, GC can move s
}

// VULNERABLE: reflect to modify unexported fields
func modifyUnexported(obj interface{}, fieldName string, newVal interface{}) {
    v := reflect.ValueOf(obj).Elem()
    f := v.FieldByName(fieldName)
    // Bypass read-only restriction on unexported field
    ptr := unsafe.Pointer(f.UnsafeAddr())
    reflect.NewAt(f.Type(), ptr).Elem().Set(reflect.ValueOf(newVal))
}

// VULNERABLE: SliceHeader manipulation
func stringToBytes(s string) []byte {
    sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
    bh := reflect.SliceHeader{
        Data: sh.Data,
        Len:  sh.Len,
        Cap:  sh.Len,
    }
    return *(*[]byte)(unsafe.Pointer(&bh))
    // Modifying the returned slice mutates an "immutable" string
}

// SAFE: If unsafe is truly needed, keep the pointer conversion in one expression
func readFieldSafe(s *MyStruct) int {
    // Single expression: no uintptr escaping to a variable
    return *(*int)(unsafe.Pointer(uintptr(unsafe.Pointer(s)) + unsafe.Offsetof(s.Field)))
}
```

---

## 7. Race Conditions

### CWE References
| CWE | Name |
|-----|------|
| CWE-362 | Concurrent Execution using Shared Resource with Improper Synchronization ("Race Condition") |
| CWE-366 | Race Condition within a Thread |
| CWE-367 | Time-of-check Time-of-use (TOCTOU) Race Condition |
| CWE-662 | Improper Synchronization |
| CWE-820 | Missing Synchronization |

### Dangerous Patterns

**Unprotected shared state in goroutines:**
- Global maps accessed from multiple goroutines without `sync.Mutex` or `sync.RWMutex`
- Session stores, rate limiters, auth caches shared across HTTP handlers
- `go func() { ... sharedVar ... }` -- closure captures shared variable

**Specific patterns:**
- Map read/write without mutex in concurrent code (`map[string]...` accessed in `go func`)
- `go func()` capturing loop variables (classic Go gotcha, fixed in Go 1.22)
- Channel misuse: unbuffered channel causing deadlock, or goroutine leak
- `sync.WaitGroup` misuse: calling `wg.Add` inside goroutine instead of before
- Read-modify-write on non-atomic variables: `counter++` in goroutine without sync

**Auth/session specific race conditions:**
- Session token generation/validation with shared state
- Double-spending in transaction handling
- TOCTOU in file permission checks before file operations

**Regex patterns for detection:**
```
# Pattern 1: go func with common shared state patterns
go\s+func\s*\(

# Pattern 2: Global map declaration (potential concurrent access)
var\s+\w+\s+(=\s*)?map\[

# Pattern 3: Missing mutex around map operations -- heuristic
# Look for map access in files that also have goroutine launches
# (Requires cross-reference analysis)

# Pattern 4: Non-atomic increment in concurrent context
\w+\+\+  # or \w+ \+= 1  (heuristic -- flag for review if goroutines present)

# Pattern 5: sync.WaitGroup Add inside goroutine
go\s+func[^{]*\{[^}]*wg\.Add\s*\(
```

### Vulnerable Code Examples

```go
// VULNERABLE: Concurrent map access without synchronization
var sessions = make(map[string]*Session)

func handleLogin(w http.ResponseWriter, r *http.Request) {
    token := generateToken()
    sessions[token] = &Session{User: r.FormValue("user")} // DATA RACE
    http.SetCookie(w, &http.Cookie{Name: "session", Value: token})
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
    cookie, _ := r.Cookie("session")
    session := sessions[cookie.Value] // DATA RACE -- concurrent map read
    if session == nil {
        http.Error(w, "unauthorized", 401)
        return
    }
}

// VULNERABLE: Race condition in balance check
var balance int64 = 1000

func withdraw(amount int64) bool {
    if balance >= amount { // TOCTOU: check
        balance -= amount // TOCTOU: use -- another goroutine may have changed balance
        return true
    }
    return false
}

// VULNERABLE: Loop variable capture (pre Go 1.22)
func processItems(items []string) {
    for _, item := range items {
        go func() {
            process(item) // Captures loop variable -- always sees last value
        }()
    }
}

// SAFE: Mutex-protected session store
var (
    sessions   = make(map[string]*Session)
    sessionsMu sync.RWMutex
)

func handleLogin(w http.ResponseWriter, r *http.Request) {
    token := generateToken()
    sessionsMu.Lock()
    sessions[token] = &Session{User: r.FormValue("user")}
    sessionsMu.Unlock()
    http.SetCookie(w, &http.Cookie{Name: "session", Value: token})
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
    cookie, _ := r.Cookie("session")
    sessionsMu.RLock()
    session := sessions[cookie.Value]
    sessionsMu.RUnlock()
    // ...
}

// SAFE: Atomic operations for counters
var counter int64

func increment() {
    atomic.AddInt64(&counter, 1)
}
```

---

## 8. Weak Cryptography

### CWE References
| CWE | Name |
|-----|------|
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm |
| CWE-328 | Use of Weak Hash |
| CWE-330 | Use of Insufficiently Random Values |
| CWE-331 | Insufficient Entropy |
| CWE-338 | Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) |
| CWE-916 | Use of Password Hash With Insufficient Computational Effort |

### Dangerous Functions / Patterns

**Weak hash functions:**
- `crypto/md5` -- `md5.New()`, `md5.Sum()` -- broken, collision attacks practical
- `crypto/sha1` -- `sha1.New()`, `sha1.Sum()` -- broken, collision attacks demonstrated (SHAttered)
- `crypto/des` -- DES and 3DES, both broken
- `crypto/rc4` -- `rc4.NewCipher()` -- broken stream cipher

**Weak PRNG:**
- `math/rand` -- `rand.Intn()`, `rand.Int()`, `rand.Read()` -- NOT cryptographically secure
- `math/rand.NewSource()` -- seeded PRNG, predictable
- `math/rand.Seed()` -- common pattern with `time.Now().UnixNano()` -- predictable seed
- `math/rand/v2` -- still not crypto-secure (Go 1.22+)

**Insufficient password hashing:**
- Using `sha256.Sum256([]byte(password))` for password storage
- Using any single-pass hash for passwords (should use bcrypt/scrypt/argon2)

**Weak encryption modes:**
- `cipher.NewCBCEncrypter` without proper IV handling
- `cipher.NewCFBEncrypter` -- less preferred than GCM
- ECB mode (manual block-by-block encryption without chaining)

**Regex patterns for detection:**
```
# Pattern 1: Weak hash imports
import\s+["']crypto/md5["']
import\s+["']crypto/sha1["']
import\s+["']crypto/des["']
import\s+["']crypto/rc4["']

# Pattern 2: Weak hash function calls
md5\.New\s*\(
md5\.Sum\s*\(
sha1\.New\s*\(
sha1\.Sum\s*\(
des\.NewCipher\s*\(
des\.NewTripleDESCipher\s*\(
rc4\.NewCipher\s*\(

# Pattern 3: math/rand usage (not crypto-safe)
import\s+["']math/rand["']
math/rand

# Pattern 4: Predictable seed
rand\.Seed\s*\(\s*time\.Now\(\)

# Pattern 5: math/rand for security-sensitive operations
rand\.(Intn|Int63|Int31|Float64|Read)\s*\(

# Pattern 6: Weak password hashing (single-pass hash of password)
(sha256|sha512|md5|sha1)\.(Sum|New)\s*\(.*(?i)(password|passwd|secret|token)
```

### Vulnerable Code Examples

```go
// VULNERABLE: MD5 for integrity checking
import "crypto/md5"

func hashPassword(password string) string {
    h := md5.Sum([]byte(password))
    return hex.EncodeToString(h[:]) // MD5 is broken
}

// VULNERABLE: SHA1 for signatures
import "crypto/sha1"

func signData(data []byte) []byte {
    h := sha1.Sum(data)
    return h[:] // SHA1 has known collisions
}

// VULNERABLE: math/rand for token generation
import "math/rand"

func generateToken() string {
    const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    b := make([]byte, 32)
    for i := range b {
        b[i] = chars[rand.Intn(len(chars))] // Predictable!
    }
    return string(b)
}

// VULNERABLE: math/rand seeded with time
func init() {
    rand.Seed(time.Now().UnixNano()) // Predictable seed
}

// VULNERABLE: DES encryption
import "crypto/des"

func encrypt(key, plaintext []byte) ([]byte, error) {
    block, err := des.NewCipher(key) // DES is broken (56-bit key)
    // ...
}

// VULNERABLE: RC4
import "crypto/rc4"

func encryptRC4(key, data []byte) ([]byte, error) {
    c, _ := rc4.NewCipher(key) // RC4 has known biases
    dst := make([]byte, len(data))
    c.XORKeyStream(dst, data)
    return dst, nil
}

// VULNERABLE: SHA256 for password storage (not iterated/salted)
func hashPassword(password string) string {
    h := sha256.Sum256([]byte(password))
    return hex.EncodeToString(h[:]) // Too fast, no salt, no iterations
}

// SAFE: crypto/rand for token generation
import "crypto/rand"

func generateToken() string {
    b := make([]byte, 32)
    _, err := crypto_rand.Read(b)
    if err != nil {
        panic(err)
    }
    return base64.URLEncoding.EncodeToString(b)
}

// SAFE: bcrypt for password hashing
import "golang.org/x/crypto/bcrypt"

func hashPassword(password string) (string, error) {
    hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    return string(hash), err
}
```

---

## 9. Path Traversal

### CWE References
| CWE | Name |
|-----|------|
| CWE-22 | Improper Limitation of a Pathname to a Restricted Directory ("Path Traversal") |
| CWE-23 | Relative Path Traversal |
| CWE-36 | Absolute Path Traversal |
| CWE-73 | External Control of File Name or Path |

### Dangerous Functions / Patterns

**Key insight:** `filepath.Join` does NOT prevent traversal. `filepath.Join("/safe/dir", "../../../etc/passwd")` resolves to `/etc/passwd`.

**Dangerous functions:**
- `filepath.Join(baseDir, userInput)` -- does not sanitize `..`
- `os.Open(userInput)` -- unrestricted file open
- `os.ReadFile(userInput)` -- unrestricted file read
- `os.Create(userInput)` -- unrestricted file create
- `os.OpenFile(userInput, ...)` -- unrestricted file open
- `os.Remove(userInput)` -- unrestricted file delete
- `os.Mkdir(userInput, ...)` -- unrestricted directory create
- `os.MkdirAll(userInput, ...)` -- unrestricted directory create
- `os.Rename(userInput, ...)` -- unrestricted file rename
- `os.Stat(userInput)` -- information disclosure
- `ioutil.ReadFile(userInput)` -- deprecated but still used
- `http.ServeFile(w, r, userInput)` -- serve arbitrary file
- `http.Dir(userInput)` -- create file server rooted at user input
- `io.Copy(dst, os.Open(userInput))` -- read arbitrary file
- `os.Symlink(userInput, ...)` -- symlink attacks

**Regex patterns for detection:**
```
# Pattern 1: filepath.Join with non-literal second arg
filepath\.Join\s*\([^)]*,\s*[a-z_][a-zA-Z0-9_.]*

# Pattern 2: os.Open/ReadFile/Create with variable
(os\.Open|os\.ReadFile|os\.Create|os\.OpenFile|os\.Remove|os\.Stat|os\.Mkdir)\s*\(\s*[a-z_]

# Pattern 3: http.ServeFile with variable path
http\.ServeFile\s*\([^,]+,[^,]+,\s*[a-z_]

# Pattern 4: ioutil.ReadFile with variable
ioutil\.ReadFile\s*\(\s*[a-z_]

# Pattern 5: Direct use of request path for file operations
r\.URL\.Path|r\.URL\.Query\(\)\.Get|r\.FormValue
# (when followed by file operations -- requires context analysis)

# Pattern 6: Absence of filepath.Clean or strings check after Join
# (Heuristic: filepath.Join not followed by a check like strings.HasPrefix)
```

### Vulnerable Code Examples

```go
// VULNERABLE: filepath.Join does NOT prevent traversal
func serveFile(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("file")
    path := filepath.Join("/var/www/static", filename)
    // filename = "../../../etc/passwd" -> path = "/etc/passwd"
    http.ServeFile(w, r, path)
}

// VULNERABLE: Direct user input in os.Open
func readConfig(w http.ResponseWriter, r *http.Request) {
    configName := r.URL.Query().Get("config")
    data, err := os.ReadFile(configName) // Arbitrary file read!
    if err != nil {
        http.Error(w, "not found", 404)
        return
    }
    w.Write(data)
}

// VULNERABLE: filepath.Clean is NOT sufficient alone
func serveFile(w http.ResponseWriter, r *http.Request) {
    filename := filepath.Clean(r.URL.Query().Get("file"))
    // filepath.Clean("../../../etc/passwd") = "../../../etc/passwd" -- still traverses!
    path := filepath.Join("/var/www/static", filename)
    http.ServeFile(w, r, path)
}

// SAFE: Validate the resolved path is within the expected directory
func serveFile(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("file")
    path := filepath.Join("/var/www/static", filename)
    path = filepath.Clean(path)

    // Critical check: ensure resolved path is within base directory
    if !strings.HasPrefix(path, "/var/www/static/") {
        http.Error(w, "forbidden", 403)
        return
    }
    http.ServeFile(w, r, path)
}

// SAFE (Go 1.16+): Use os.DirFS + fs.FS for sandboxed file access
func serveFiles() http.Handler {
    fsys := os.DirFS("/var/www/static")
    return http.FileServer(http.FS(fsys))
    // os.DirFS prevents traversal outside the root
}
```

---

## 10. Server-Side Request Forgery (SSRF)

### CWE References
| CWE | Name |
|-----|------|
| CWE-918 | Server-Side Request Forgery (SSRF) |
| CWE-441 | Unintended Proxy or Intermediary ("Confused Deputy") |
| CWE-601 | URL Redirection to Untrusted Site ("Open Redirect") |

### Dangerous Functions / Patterns

**HTTP clients with user-controlled URLs:**
- `http.Get(userURL)` -- fetches arbitrary URL
- `http.Post(userURL, ...)` -- posts to arbitrary URL
- `http.NewRequest("GET", userURL, nil)` -- creates request to arbitrary URL
- `http.NewRequestWithContext(ctx, method, userURL, body)`
- `client.Do(req)` where `req.URL` is user-controlled
- `client.Get(userURL)`

**No redirect validation:**
- Default `http.Client` follows redirects (up to 10) -- can be redirected to internal services
- `http.Client{CheckRedirect: nil}` -- default behavior, follows redirects
- Missing `CheckRedirect` function to validate redirect targets

**DNS rebinding:**
- URL validation at request time but DNS resolves to internal IP at connection time

**Regex patterns for detection:**
```
# Pattern 1: http.Get/Post/Head with variable URL
http\.(Get|Post|Head|PostForm)\s*\(\s*[a-z_][a-zA-Z0-9_]*

# Pattern 2: http.NewRequest with variable URL
http\.NewRequest\s*\([^,]+,\s*[a-z_][a-zA-Z0-9_]*

# Pattern 3: http.NewRequestWithContext with variable URL
http\.NewRequestWithContext\s*\([^,]+,\s*[^,]+,\s*[a-z_][a-zA-Z0-9_]*

# Pattern 4: URL from request parameters used in outbound request
(r\.URL\.Query\(\)\.Get|r\.FormValue|r\.PostFormValue)\s*\([^)]*\)
# (when result is used in http.Get/NewRequest -- requires data flow analysis)

# Pattern 5: url.Parse with user input (often precedes SSRF)
url\.Parse\s*\(\s*[a-z_]

# Pattern 6: Client without CheckRedirect
http\.Client\s*\{[^}]*\}
# (check if CheckRedirect is absent)
```

### Vulnerable Code Examples

```go
// VULNERABLE: User-controlled URL with no validation
func fetchURL(w http.ResponseWriter, r *http.Request) {
    targetURL := r.URL.Query().Get("url")
    resp, err := http.Get(targetURL) // Can access internal services!
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    defer resp.Body.Close()
    io.Copy(w, resp.Body)
}

// VULNERABLE: Follows redirects to internal services
func proxyRequest(w http.ResponseWriter, r *http.Request) {
    targetURL := r.URL.Query().Get("url")
    // Even if targetURL is validated, redirect can go to http://169.254.169.254/
    client := &http.Client{} // Default: follows up to 10 redirects
    resp, _ := client.Get(targetURL)
    defer resp.Body.Close()
    io.Copy(w, resp.Body)
}

// VULNERABLE: URL scheme not validated (file://, gopher://)
func fetchResource(w http.ResponseWriter, r *http.Request) {
    targetURL := r.URL.Query().Get("url")
    parsedURL, _ := url.Parse(targetURL)
    // parsedURL.Scheme could be "file" -> file:///etc/passwd
    req, _ := http.NewRequest("GET", parsedURL.String(), nil)
    client := &http.Client{}
    resp, _ := client.Do(req)
    defer resp.Body.Close()
    io.Copy(w, resp.Body)
}

// SAFE: Validate URL scheme, host, and block internal IPs
func fetchURL(w http.ResponseWriter, r *http.Request) {
    targetURL := r.URL.Query().Get("url")
    parsedURL, err := url.Parse(targetURL)
    if err != nil {
        http.Error(w, "invalid URL", 400)
        return
    }

    // Only allow http/https
    if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
        http.Error(w, "invalid scheme", 400)
        return
    }

    // Resolve and check for internal IPs
    host := parsedURL.Hostname()
    ips, err := net.LookupIP(host)
    if err != nil {
        http.Error(w, "cannot resolve host", 400)
        return
    }
    for _, ip := range ips {
        if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
            http.Error(w, "forbidden target", 403)
            return
        }
    }

    // Use client with redirect validation
    client := &http.Client{
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            // Validate each redirect target
            return validateURL(req.URL)
        },
        Timeout: 10 * time.Second,
    }
    resp, err := client.Get(targetURL)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    defer resp.Body.Close()
    io.Copy(w, io.LimitReader(resp.Body, 1<<20)) // Limit response size
}
```

---

## 11. Hardcoded Secrets

### CWE References
| CWE | Name |
|-----|------|
| CWE-798 | Use of Hard-coded Credentials |
| CWE-259 | Use of Hard-coded Password |
| CWE-321 | Use of Hard-coded Cryptographic Key |
| CWE-547 | Use of Hard-coded, Security-relevant Constants |

### Dangerous Patterns

**Variable name patterns (case-insensitive):**
- `password`, `passwd`, `pwd`
- `secret`, `secretKey`, `secret_key`
- `apiKey`, `api_key`, `apikey`
- `token`, `accessToken`, `access_token`, `authToken`
- `privateKey`, `private_key`
- `connectionString`, `connStr`, `dsn`
- `credentials`, `cred`
- `awsSecretAccessKey`, `aws_secret_access_key`
- `bearer`

**Specific patterns:**
- `const password = "..."` -- hardcoded password constant
- `var apiKey = "..."` -- hardcoded API key variable
- `"Authorization", "Bearer <token>"` -- hardcoded bearer token in header
- Connection strings: `postgres://user:pass@host/db`, `mysql://user:pass@host/db`
- AWS keys: strings matching `AKIA[0-9A-Z]{16}`
- Private keys: `-----BEGIN RSA PRIVATE KEY-----` or `-----BEGIN EC PRIVATE KEY-----`
- GitHub tokens: `ghp_[a-zA-Z0-9]{36}`, `gho_`, `ghu_`, `ghs_`, `ghr_`
- Generic high-entropy strings assigned to secret-like variables

**Regex patterns for detection:**
```
# Pattern 1: Variable assignments with secret-like names
(?i)(password|passwd|pwd|secret|api_?key|token|private_?key|conn_?str|dsn|credentials?)\s*[:=]\s*["'][^"']{8,}["']

# Pattern 2: Hardcoded connection strings
["'](postgres|mysql|mongodb|redis|amqp)://[^"']*:[^"']*@[^"']*["']

# Pattern 3: AWS access keys
AKIA[0-9A-Z]{16}

# Pattern 4: Private key blocks
-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----

# Pattern 5: GitHub tokens
gh[pousr]_[A-Za-z0-9_]{36,}

# Pattern 6: Bearer tokens in code
["']Bearer\s+[A-Za-z0-9\-._~+/]+=*["']

# Pattern 7: Base64 encoded secrets assigned to variables
(?i)(secret|key|token|password)\s*[:=]\s*["'][A-Za-z0-9+/]{40,}=*["']

# Pattern 8: Slack tokens
xox[bpors]-[0-9]{10,13}-[0-9]{10,13}(-[a-zA-Z0-9]{24,34})?

# Pattern 9: Generic API key patterns
["'][A-Za-z0-9]{32,}["']  # (heuristic -- requires context)

# Pattern 10: Hardcoded in struct literal
(?i)(Password|Secret|APIKey|Token|PrivateKey)\s*:\s*["'][^"']{8,}["']
```

### Vulnerable Code Examples

```go
// VULNERABLE: Hardcoded database password
const dbPassword = "super_secret_password_123"

func connectDB() (*sql.DB, error) {
    dsn := fmt.Sprintf("postgres://admin:%s@localhost/mydb", dbPassword)
    return sql.Open("postgres", dsn)
}

// VULNERABLE: Hardcoded API key
var apiKey = "sk-1234567890abcdef1234567890abcdef"

func callAPI() (*http.Response, error) {
    req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
    req.Header.Set("Authorization", "Bearer "+apiKey)
    return http.DefaultClient.Do(req)
}

// VULNERABLE: Hardcoded connection string
func getDB() (*sql.DB, error) {
    return sql.Open("mysql", "root:p@ssw0rd@tcp(db.internal:3306)/production")
}

// VULNERABLE: Hardcoded JWT signing key
var jwtSecret = []byte("my-super-secret-jwt-key-dont-tell-anyone")

func generateToken(userID string) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "user_id": userID,
        "exp":     time.Now().Add(24 * time.Hour).Unix(),
    })
    return token.SignedString(jwtSecret)
}

// VULNERABLE: AWS credentials in source
const (
    awsAccessKeyID     = "AKIAIOSFODNN7EXAMPLE"
    awsSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

// VULNERABLE: Private key embedded in source
const privateKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2a2rwplBQXz...
-----END RSA PRIVATE KEY-----`

// SAFE: Read from environment
func connectDB() (*sql.DB, error) {
    dsn := os.Getenv("DATABASE_URL")
    if dsn == "" {
        return nil, fmt.Errorf("DATABASE_URL not set")
    }
    return sql.Open("postgres", dsn)
}
```

---

## 12. Framework-Specific (Gin / Echo / Chi)

### CWE References
| CWE | Name |
|-----|------|
| CWE-352 | Cross-Site Request Forgery (CSRF) |
| CWE-942 | Permissive Cross-domain Policy with Untrusted Domains |
| CWE-489 | Active Debug Code |
| CWE-693 | Protection Mechanism Failure |
| CWE-16 | Configuration |

### Dangerous Patterns

#### Gin Framework (`github.com/gin-gonic/gin`)

**Debug mode in production:**
- `gin.SetMode(gin.DebugMode)` -- verbose error output, stack traces
- Absence of `gin.SetMode(gin.ReleaseMode)` in production code

**Permissive CORS:**
- CORS middleware with `AllowAllOrigins: true`
- `AllowOrigins: []string{"*"}`
- `AllowCredentials: true` combined with permissive origins

**Missing CSRF:**
- No CSRF middleware registered (harder to detect statically -- look for absence)

**Binding without validation:**
- `c.ShouldBindJSON(&obj)` without struct validation tags
- `c.Bind(&obj)` ignoring errors

**Trusted proxies:**
- `router.SetTrustedProxies(nil)` -- trusts all proxies (IP spoofing)
- Missing `SetTrustedProxies` configuration

#### Echo Framework (`github.com/labstack/echo`)

**Debug mode:**
- `e.Debug = true` -- exposes stack traces

**Permissive CORS:**
- `middleware.CORSWithConfig(middleware.CORSConfig{AllowOrigins: []string{"*"}})`

**Missing CSRF:**
- No `middleware.CSRF()` in middleware chain

**Missing rate limiting:**
- No `middleware.RateLimiter()` for auth endpoints

#### Chi Router (`github.com/go-chi/chi`)

**Missing middleware:**
- No CSRF middleware
- No rate limiting
- `chi.URLParam(r, "id")` used directly in SQL without validation

#### General net/http

**Missing security headers:**
- No `Strict-Transport-Security`
- No `X-Content-Type-Options: nosniff`
- No `X-Frame-Options`
- No `Content-Security-Policy`

**Regex patterns for detection:**
```
# Pattern 1: Gin debug mode
gin\.SetMode\s*\(\s*gin\.DebugMode\s*\)

# Pattern 2: Gin permissive CORS
AllowAllOrigins\s*:\s*true
AllowOrigins\s*:\s*\[\]string\s*\{\s*["']\*["']\s*\}

# Pattern 3: CORS with credentials and wildcard
AllowCredentials\s*:\s*true

# Pattern 4: Echo debug mode
\.Debug\s*=\s*true

# Pattern 5: Trusted proxies disabled
SetTrustedProxies\s*\(\s*nil\s*\)

# Pattern 6: Gin binding without error check
\.(ShouldBind|ShouldBindJSON|ShouldBindQuery|Bind)\s*\([^)]*\)\s*$
# (line ends without error capture)

# Pattern 7: Framework-specific URL param used directly in SQL
(c\.Param|c\.Query|chi\.URLParam|c\.QueryParam|c\.FormValue)\s*\([^)]*\)
# (flag when result flows into SQL -- requires data flow analysis)

# Pattern 8: Missing security headers (absence detection)
# Look for HTTP handler registration without security header middleware
```

### Vulnerable Code Examples

```go
// VULNERABLE: Gin debug mode in production
func main() {
    gin.SetMode(gin.DebugMode) // Exposes stack traces to users
    r := gin.Default()
    // ...
}

// VULNERABLE: Permissive CORS in Gin
func main() {
    r := gin.Default()
    r.Use(cors.New(cors.Config{
        AllowAllOrigins:  true,
        AllowCredentials: true, // Dangerous with AllowAllOrigins
        AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
    }))
}

// VULNERABLE: Echo permissive CORS
func main() {
    e := echo.New()
    e.Debug = true // Stack traces in responses
    e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
        AllowOrigins: []string{"*"},
        AllowCredentials: true,
    }))
}

// VULNERABLE: No CSRF protection, no rate limiting
func main() {
    r := gin.Default()
    // No CSRF middleware!
    r.POST("/transfer", func(c *gin.Context) {
        amount := c.PostForm("amount")
        to := c.PostForm("to")
        // Process transfer without CSRF validation
        transfer(amount, to)
    })
}

// VULNERABLE: URL param directly in database query
func getUser(c *gin.Context) {
    id := c.Param("id") // No validation
    var user User
    db.Raw("SELECT * FROM users WHERE id = " + id).Scan(&user) // SQL injection + no validation
    c.JSON(200, user)
}

// VULNERABLE: Trusting all proxies
func main() {
    r := gin.Default()
    r.SetTrustedProxies(nil) // Trusts ALL proxies -- X-Forwarded-For spoofable
}

// VULNERABLE: Binding without error handling
func createUser(c *gin.Context) {
    var user User
    c.ShouldBindJSON(&user) // Error ignored -- partial/malformed data processed
    db.Create(&user)
    c.JSON(200, user)
}

// SAFE: Proper Gin configuration
func main() {
    gin.SetMode(gin.ReleaseMode)
    r := gin.Default()
    r.SetTrustedProxies([]string{"10.0.0.0/8"})

    r.Use(cors.New(cors.Config{
        AllowOrigins:     []string{"https://myapp.example.com"},
        AllowMethods:     []string{"GET", "POST"},
        AllowCredentials: true,
    }))

    // Add CSRF middleware, security headers, rate limiting
    r.Use(csrf.Middleware())
    r.Use(securityHeaders())
    r.Use(rateLimiter())
}
```

---

## 13. Error Handling

### CWE References
| CWE | Name |
|-----|------|
| CWE-390 | Detection of Error Condition Without Action |
| CWE-391 | Unchecked Error Condition |
| CWE-755 | Improper Handling of Exceptional Conditions |
| CWE-754 | Improper Check for Unusual or Exceptional Conditions |
| CWE-248 | Uncaught Exception (panic in Go context) |
| CWE-209 | Generation of Error Message Containing Sensitive Information |

### Dangerous Patterns

**Swallowed errors (security-critical):**
- `_ = someSecurityFunction()` -- explicitly discarding security-relevant error
- `err := authenticate(); // err never checked`
- `if err != nil { log.Println(err) }` followed by continuing execution as if success
- Missing error check after `tls.Dial`, `x509.ParseCertificate`, `bcrypt.CompareHashAndPassword`

**Panic in HTTP handlers:**
- `panic(...)` in HTTP handler -- crashes the goroutine (and potentially the server if no recovery middleware)
- Missing `defer recover()` in HTTP handlers
- `log.Fatal(...)` in HTTP handler -- calls `os.Exit(1)`, kills entire server

**Information disclosure in errors:**
- `http.Error(w, err.Error(), 500)` -- leaks internal error details
- `c.JSON(500, gin.H{"error": err.Error()})` -- leaks internal state
- `fmt.Fprintf(w, "Error: %v", err)` -- leaks error to client

**Critical functions whose errors should never be ignored:**
- `bcrypt.CompareHashAndPassword()` -- password verification
- `crypto/*.Verify()` -- signature verification
- `tls.Dial()` -- TLS connection
- `x509.Certificate.Verify()` -- certificate validation
- `jwt.Parse()` -- JWT validation
- `sql.DB.Begin()` -- transaction start
- `rows.Err()` -- after iterating sql.Rows
- `resp.Body.Close()` -- resource leak (less security, more reliability)
- `os.Chmod()`, `os.Chown()` -- permission changes
- `http.ListenAndServeTLS()` -- TLS server start

**Regex patterns for detection:**
```
# Pattern 1: Blank identifier discarding error
_\s*=\s*\w+\.\w+\s*\(

# Pattern 2: Error not checked (function call without assignment)
# Hard to detect with regex alone -- requires checking return types

# Pattern 3: Panic in HTTP handler context
func\s+\w+\s*\(\s*w\s+http\.ResponseWriter.*\{[^}]*panic\s*\(

# Pattern 4: log.Fatal in handler
func\s+\w+\s*\(\s*w\s+http\.ResponseWriter.*\{[^}]*log\.Fatal

# Pattern 5: Error details exposed to client
http\.Error\s*\(\s*w\s*,\s*err\.Error\(\)
http\.Error\s*\(\s*w\s*,\s*fmt\.Sprintf\s*\([^)]*err
\.JSON\s*\([^,]*,\s*[^)]*err\.Error\(\)

# Pattern 6: Swallowed error after security function
(CompareHashAndPassword|Verify|ParseWithClaims|CheckSignature)\s*\([^)]*\)\s*$
# (call without capturing return value)

# Pattern 7: Error checked but execution continues anyway (heuristic)
if\s+err\s*!=\s*nil\s*\{\s*(log\.(Print|Warn|Info)[^}]*)\s*\}
# (log only, no return/break/continue)

# Pattern 8: Missing rows.Err() check
for\s+\w+\.Next\(\)\s*\{[^}]*\}\s*(?!.*\.Err\(\))

# Pattern 9: Missing defer resp.Body.Close()
(http\.(Get|Post|Head|Do)|client\.(Get|Post|Do))\s*\([^)]*\)
# (check if resp.Body.Close() follows)
```

### Vulnerable Code Examples

```go
// VULNERABLE: Swallowed authentication error
func loginHandler(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")

    user, _ := getUserByUsername(username) // Error ignored!
    _ = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) // Error ignored!

    // Proceeds as if authentication succeeded
    session := createSession(user.ID)
    http.SetCookie(w, &http.Cookie{Name: "session", Value: session})
}

// VULNERABLE: Error logged but execution continues
func verifyToken(w http.ResponseWriter, r *http.Request) {
    tokenStr := r.Header.Get("Authorization")
    token, err := jwt.Parse(tokenStr, keyFunc)
    if err != nil {
        log.Printf("token parse error: %v", err)
        // BUG: no return! continues with invalid/nil token
    }
    claims := token.Claims.(jwt.MapClaims)
    userID := claims["user_id"].(string)
    // ...
}

// VULNERABLE: Panic in HTTP handler
func handler(w http.ResponseWriter, r *http.Request) {
    data := fetchData() // might return nil
    result := data.Process() // PANIC: nil pointer dereference
    json.NewEncoder(w).Encode(result)
}

// VULNERABLE: log.Fatal in HTTP handler
func handler(w http.ResponseWriter, r *http.Request) {
    db, err := sql.Open("postgres", connStr)
    if err != nil {
        log.Fatal(err) // Kills entire server!
    }
}

// VULNERABLE: Internal error details leaked to client
func handler(w http.ResponseWriter, r *http.Request) {
    result, err := db.Query("SELECT ...")
    if err != nil {
        http.Error(w, err.Error(), 500)
        // Leaks: "pq: relation \"users\" does not exist" -- reveals DB schema info
    }
}

// VULNERABLE: Missing rows.Err() check
func getUsers(db *sql.DB) ([]User, error) {
    rows, err := db.Query("SELECT id, name FROM users")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var users []User
    for rows.Next() {
        var u User
        rows.Scan(&u.ID, &u.Name) // Scan error ignored
        users = append(users, u)
    }
    // Missing: rows.Err() check -- iteration errors silently lost
    return users, nil
}

// SAFE: Proper error handling
func loginHandler(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")

    user, err := getUserByUsername(username)
    if err != nil {
        // Generic message, no internal details
        http.Error(w, "invalid credentials", 401)
        return
    }

    err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
    if err != nil {
        http.Error(w, "invalid credentials", 401)
        return
    }

    session := createSession(user.ID)
    http.SetCookie(w, &http.Cookie{Name: "session", Value: session})
}

// SAFE: Recovery middleware for panics
func recoveryMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        defer func() {
            if err := recover(); err != nil {
                log.Printf("panic recovered: %v\n%s", err, debug.Stack())
                http.Error(w, "internal server error", 500)
            }
        }()
        next.ServeHTTP(w, r)
    })
}
```

---

## Appendix A: Consolidated Regex Patterns for Scanner Implementation

Below is a consolidated summary of all high-confidence regex patterns organized by severity for use in a static analysis scanner. These patterns are designed to minimize false positives while catching the most dangerous patterns.

### Critical Severity

```
# SQL Injection
fmt\.Sprintf\s*\(\s*["'](?i)(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|UNION)\b
\.(Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext)\s*\([^)]*\+
\.(Query|QueryRow|Exec)\s*\(\s*fmt\.Sprintf
\.(Raw|Where|Having)\s*\(\s*fmt\.Sprintf

# Command Injection
exec\.Command\s*\(\s*["'](sh|bash|/bin/sh|/bin/bash|cmd)["']\s*,\s*["']-c["']\s*,
exec\.Command\s*\([^)]*fmt\.Sprintf
exec\.Command\s*\([^)]*\+

# Hardcoded Secrets
(?i)(password|passwd|secret|api_?key|private_?key)\s*[:=]\s*["'][^"']{8,}["']
AKIA[0-9A-Z]{16}
-----BEGIN\s+(RSA\s+|EC\s+)?PRIVATE\s+KEY-----
["'](postgres|mysql|mongodb|redis)://[^"']*:[^"']*@[^"']*["']
```

### High Severity

```
# TLS Misconfiguration
InsecureSkipVerify\s*:\s*true

# Template XSS
template\.HTML\s*\(
template\.JS\s*\(
import\s+["']text/template["']

# Weak Crypto
import\s+["']crypto/(md5|sha1|des|rc4)["']
import\s+["']math/rand["']

# Path Traversal
filepath\.Join\s*\([^)]*,\s*(r\.|req\.|c\.|ctx\.)
http\.ServeFile\s*\([^,]+,[^,]+,\s*[a-z_]

# SSRF
http\.(Get|Post|Head)\s*\(\s*[a-z_][a-zA-Z0-9_]*\s*\)
http\.NewRequest(WithContext)?\s*\([^,]+,\s*[a-z_][a-zA-Z0-9_]*
```

### Medium Severity

```
# Unsafe Package
import\s+["']unsafe["']
unsafe\.Pointer\s*\(

# Error Handling
_\s*=\s*\w+\.(CompareHashAndPassword|Verify|Parse|Dial|CheckSignature)\s*\(
http\.Error\s*\(\s*w\s*,\s*err\.Error\(\)
log\.Fatal\s*\(

# Race Conditions (heuristic)
var\s+\w+\s*=\s*make\s*\(\s*map\[

# Framework Misconfig
gin\.SetMode\s*\(\s*gin\.DebugMode\s*\)
\.Debug\s*=\s*true
AllowAllOrigins\s*:\s*true
SetTrustedProxies\s*\(\s*nil\s*\)

# Deserialization
gob\.NewDecoder\s*\(
```

### Low Severity / Informational

```
# Potential issues requiring manual review
go\s+func\s*\(
reflect\.(NewAt|SliceHeader|StringHeader)
import\s+"C"
MinVersion\s*:\s*tls\.VersionTLS1[01]
```

---

## Appendix B: CWE Cross-Reference Table

| Category | Primary CWE | Additional CWEs |
|----------|-------------|-----------------|
| SQL Injection | CWE-89 | CWE-564, CWE-943 |
| Command Injection | CWE-78 | CWE-77, CWE-88 |
| Template / XSS | CWE-79 | CWE-80, CWE-116 |
| TLS Issues | CWE-295 | CWE-297, CWE-319, CWE-326, CWE-757 |
| Deserialization | CWE-502 | CWE-915, CWE-843 |
| Unsafe Package | CWE-822 | CWE-823, CWE-843, CWE-119, CWE-787 |
| Race Conditions | CWE-362 | CWE-366, CWE-367, CWE-662, CWE-820 |
| Weak Crypto | CWE-327 | CWE-328, CWE-330, CWE-338, CWE-916 |
| Path Traversal | CWE-22 | CWE-23, CWE-36, CWE-73 |
| SSRF | CWE-918 | CWE-441, CWE-601 |
| Hardcoded Secrets | CWE-798 | CWE-259, CWE-321, CWE-547 |
| Framework Config | CWE-352 | CWE-942, CWE-489, CWE-693 |
| Error Handling | CWE-390 | CWE-391, CWE-755, CWE-754, CWE-248, CWE-209 |

---

## Appendix C: Go-Specific Static Analysis Tool Landscape

For reference, these existing tools cover some of the patterns above:

| Tool | Coverage |
|------|----------|
| `go vet` | Basic issues, printf format strings, unreachable code |
| `staticcheck` (honnef.co) | Broad static analysis including some security patterns |
| `gosec` (securego) | Security-focused scanner, covers many CWEs listed here |
| `golangci-lint` | Meta-linter aggregating multiple tools |
| `semgrep` | Pattern-based with Go support, custom rules possible |
| `govulncheck` | Known vulnerability checking in dependencies |
| `-race` flag | Runtime data race detector (not static) |
| `errcheck` | Finds unchecked errors |
| `bodyclose` | Finds unclosed HTTP response bodies |

Gaps in existing tooling that a custom scanner could fill:
- Cross-function data flow for SSRF and SQL injection (most regex tools are single-line)
- Framework-specific misconfigurations (Gin/Echo/Chi CSRF, CORS, debug mode)
- Context-aware secret detection (distinguishing test data from real secrets)
- TLS configuration completeness (checking for absence of MinVersion)
- Auth-specific race conditions in session management
- Combined analysis (e.g., `math/rand` used specifically for security tokens vs. test data)

---

## Appendix D: Detection Strategy Recommendations

### Tier 1: Regex-Based (Fast, Line-Level)
Best for: hardcoded secrets, dangerous imports, known-bad function calls, configuration flags.
Apply all patterns from Appendix A.

### Tier 2: AST-Based (Accurate, Function-Level)
Best for: data flow from HTTP input to sinks (SQL, exec, file ops), type assertion safety, error handling chains.
Parse Go AST, track variable assignments, check if tainted data reaches dangerous sinks.

### Tier 3: Cross-File Analysis (Comprehensive, Project-Level)
Best for: missing middleware detection, CSRF absence, race conditions across packages, secret propagation.
Requires building a call graph across the project.

### False Positive Reduction
- Allow `//nolint:` or `// #nosec` annotations to suppress findings
- Distinguish test files (`_test.go`) from production code
- Check if `InsecureSkipVerify` is in test code or has an adjacent comment explaining why
- For hardcoded secrets, check if the value looks like a placeholder (`"changeme"`, `"TODO"`, `"xxx"`)
- For `math/rand`, check if it's used in test files or for non-security purposes
