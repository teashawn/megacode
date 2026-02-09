# React / JavaScript / TypeScript Security Vulnerability Research

## Comprehensive Reference for Security Audit Tooling

This document catalogs security vulnerabilities specific to React, JavaScript, TypeScript, Node.js, and Next.js applications. Each category includes CWE references, regex-matchable patterns, and example vulnerable code.

NOTE: All code examples in this document are intentionally vulnerable for educational and audit-pattern-matching purposes. Do not use them in production.

---

## Table of Contents

1. [Cross-Site Scripting (XSS)](#1-cross-site-scripting-xss)
2. [Dynamic Code Execution](#2-dynamic-code-execution)
3. [Prototype Pollution](#3-prototype-pollution)
4. [JWT and Authentication Issues](#4-jwt-and-authentication-issues)
5. [Secret Exposure in Client Bundles](#5-secret-exposure-in-client-bundles)
6. [SSRF in Server-Side Rendering](#6-ssrf-in-server-side-rendering)
7. [Open Redirects](#7-open-redirects)
8. [CORS Misconfiguration](#8-cors-misconfiguration)
9. [Node.js Server-Side Vulnerabilities](#9-nodejs-server-side-vulnerabilities)
10. [Dependency Risks](#10-dependency-risks)
11. [React-Specific Vulnerabilities](#11-react-specific-vulnerabilities)
12. [Next.js-Specific Vulnerabilities](#12-nextjs-specific-vulnerabilities)

---

## 1. Cross-Site Scripting (XSS)

### CWE References

| CWE | Name |
|-----|------|
| CWE-79 | Improper Neutralization of Input During Web Page Generation (XSS) |
| CWE-80 | Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) |
| CWE-83 | Improper Neutralization of Script in Attributes in a Web Page |
| CWE-87 | Improper Neutralization of Alternate XSS Syntax |
| CWE-116 | Improper Encoding or Escaping of Output |

### Dangerous Functions / Patterns for Regex Matching

```
dangerouslySetInnerHTML
__html
innerHTML
outerHTML
document.write
document.writeln
insertAdjacentHTML
.html(                    # jQuery .html()
.append(                  # jQuery .append() with HTML strings
.prepend(                 # jQuery .prepend() with HTML strings
.after(                   # jQuery .after() with HTML strings
.before(                  # jQuery .before() with HTML strings
.replaceWith(             # jQuery .replaceWith() with HTML strings
eval(
Function(
setTimeout(               # when first arg is a string
setInterval(              # when first arg is a string
createContextualFragment
Range.createContextualFragment
DOMParser.parseFromString
srcdoc=
javascript:              # in href attributes
```

### Regex Patterns

```regex
# dangerouslySetInnerHTML with any variable (not a static string)
dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!['"`][^'"`]*['"`]\s*\})

# innerHTML assignment
\.innerHTML\s*=\s*(?!['"`]<)

# outerHTML assignment
\.outerHTML\s*=

# document.write/writeln
document\.write(ln)?\s*\(

# insertAdjacentHTML
\.insertAdjacentHTML\s*\(

# jQuery .html() with variable argument
\.\s*html\s*\(\s*(?!['"`]|$\()

# eval with variable
\beval\s*\(

# Function constructor
new\s+Function\s*\(

# setTimeout/setInterval with string argument
(setTimeout|setInterval)\s*\(\s*['"`]

# href with javascript: protocol (React JSX)
href\s*=\s*\{.*javascript\s*:

# createContextualFragment
createContextualFragment\s*\(

# srcdoc attribute with variable
srcdoc\s*=\s*\{
```

### Vulnerable Code Examples

#### React dangerouslySetInnerHTML

```jsx
// VULNERABLE: User input directly in dangerouslySetInnerHTML
function Comment({ userComment }) {
  return <div dangerouslySetInnerHTML={{ __html: userComment }} />;
}

// VULNERABLE: Markdown rendered without sanitization
function MarkdownPreview({ markdown }) {
  const html = marked(markdown); // marked does not sanitize by default
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

// VULNERABLE: Template literal building HTML
function UserProfile({ user }) {
  const markup = `<h1>${user.name}</h1><p>${user.bio}</p>`;
  return <div dangerouslySetInnerHTML={{ __html: markup }} />;
}
```

#### innerHTML Direct Manipulation

```javascript
// VULNERABLE: innerHTML with user input
document.getElementById('output').innerHTML = userInput;

// VULNERABLE: innerHTML via ref in React
function MyComponent({ content }) {
  const ref = useRef();
  useEffect(() => {
    ref.current.innerHTML = content; // Bypasses React's XSS protection
  }, [content]);
  return <div ref={ref} />;
}
```

#### document.write

```javascript
// VULNERABLE: document.write with user-controlled data
document.write('<div>' + userInput + '</div>');

// VULNERABLE: Third-party script injection pattern
document.write('<script src="' + url + '"><\/script>');
```

#### jQuery XSS

```javascript
// VULNERABLE: jQuery .html() with user input
$('#output').html(userInput);

// VULNERABLE: jQuery .append() with unsanitized HTML
$('#list').append('<li>' + userName + '</li>');

// VULNERABLE: jQuery selector injection
$(userInput); // If userInput is '<img src=x onerror=alert(1)>'
```

#### setTimeout / setInterval String Execution

```javascript
// VULNERABLE: String argument acts like eval
setTimeout("alert(document.cookie)", 1000);
setInterval("doSomething('" + userInput + "')", 5000);
```

#### href javascript: Protocol

```jsx
// VULNERABLE: User-controlled href can run JavaScript
function UserLink({ url }) {
  return <a href={url}>Click here</a>;
  // If url = "javascript:alert(document.cookie)"
}
```

---

## 2. Dynamic Code Execution

### CWE References

| CWE | Name |
|-----|------|
| CWE-94 | Improper Control of Generation of Code (Code Injection) |
| CWE-95 | Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection) |
| CWE-78 | Improper Neutralization of Special Elements used in an OS Command (OS Command Injection) |

### Dangerous Functions / Patterns for Regex Matching

```
eval(
new Function(
Function(
vm.runInNewContext
vm.runInThisContext
vm.runInContext
vm.compileFunction
vm.Script
child_process.exec         # use execFile instead (see note)
child_process.execSync     # use execFileSync instead
child_process.spawn        # with shell: true is dangerous
child_process.execFile     # with shell: true is dangerous
execSync(
spawnSync(
require('child_process')
import.*child_process
```

NOTE: For safe alternatives to child_process.exec, use execFile or execFileSync which do not invoke a shell and are not vulnerable to shell metacharacter injection. Spawn should not use `shell: true` with untrusted input.

### Regex Patterns

```regex
# eval usage
\beval\s*\(

# new Function constructor
new\s+Function\s*\(

# vm module usage
\bvm\.(runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(
new\s+vm\.Script\s*\(

# child_process exec with variable/user-input (string concatenation or template literal)
(exec|execSync)\s*\(\s*(`[^`]*\$\{|['"][^'"]*\+)

# spawn with shell option
spawn\s*\(.*shell\s*:\s*true

# require child_process
require\s*\(\s*['"`]child_process['"`]\s*\)

# import child_process
import\s+.*from\s+['"`]child_process['"`]
import\s+.*from\s+['"`]node:child_process['"`]

# Dynamic require
require\s*\(\s*(?!['"`])

# Template literal in exec-family functions
(exec|execSync|execFile|execFileSync)\s*\(\s*`[^`]*\$\{
```

### Vulnerable Code Examples

#### eval() with User Input

```javascript
// VULNERABLE: eval with user-controlled input
app.get('/calculate', (req, res) => {
  const result = eval(req.query.expression);  // RCE!
  res.json({ result });
});

// VULNERABLE: eval in template processing
function processTemplate(template, data) {
  return eval('`' + template + '`');
}
```

#### new Function() Constructor

```javascript
// VULNERABLE: Function constructor with user input
function createFilter(filterExpression) {
  const filterFn = new Function('item', `return ${filterExpression}`);
  return data.filter(filterFn);
}

// VULNERABLE: Dynamic function creation from user config
const handler = new Function('req', 'res', userProvidedCode);
```

#### vm Module (Node.js)

```javascript
// VULNERABLE: vm.runInNewContext with user input
const vm = require('vm');
app.post('/run', (req, res) => {
  const result = vm.runInNewContext(req.body.code, { data: sharedData });
  res.json({ result });
});

// NOTE: vm module is NOT a security mechanism. It does NOT provide a secure sandbox.
const script = new vm.Script(userCode);
script.runInNewContext(sandbox); // Can escape sandbox
```

#### child_process Command Injection

```javascript
// VULNERABLE: exec with string concatenation (use execFile instead)
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
  exec(`ping -c 1 ${req.query.host}`, (err, stdout) => {
    res.send(stdout);
  });
  // Exploit: ?host=google.com;cat /etc/passwd
});

// VULNERABLE: execSync with template literal
const { execSync } = require('child_process');
const output = execSync(`git log --author="${userName}"`);

// VULNERABLE: execFile with shell: true and user args
const { execFile } = require('child_process');
execFile('node', [userInput], { shell: true }, callback);
// shell: true + args = shell injection (Node.js DEP0190)

// VULNERABLE: spawn with shell: true
const { spawn } = require('child_process');
spawn('echo', [userInput], { shell: true });

// SAFE ALTERNATIVE: execFile without shell (no metacharacter injection)
// const { execFile } = require('child_process');
// execFile('ping', ['-c', '1', host], callback);
```

---

## 3. Prototype Pollution

### CWE References

| CWE | Name |
|-----|------|
| CWE-1321 | Improperly Controlled Modification of Object Prototype Attributes (Prototype Pollution) |
| CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| CWE-400 | Uncontrolled Resource Consumption (DoS via prototype pollution) |

### Dangerous Functions / Patterns for Regex Matching

```
Object.assign(
Object.defineProperty(
_.merge(                  # lodash/underscore
_.defaultsDeep(           # lodash
_.set(                    # lodash
_.setWith(                # lodash
merge(                    # deepmerge, webpack-merge, etc.
deepMerge(
defaultsDeep(
extend(                   # jQuery.extend, various libraries
deepExtend(
__proto__
constructor.prototype
Object.setPrototypeOf(
Reflect.setPrototypeOf(
```

### Regex Patterns

```regex
# Object.assign with potentially tainted input
Object\.assign\s*\(\s*\{\s*\}

# lodash merge/set operations
_\.(merge|defaultsDeep|set|setWith|assign|assignIn|extend|extendWith)\s*\(

# Generic deep merge patterns
(deep[Mm]erge|deepExtend|merge[Dd]eep|recursiveMerge)\s*\(

# __proto__ access in bracket notation
\[['"`]__proto__['"`]\]

# constructor.prototype access
\[['"`]constructor['"`]\]\s*\[['"`]prototype['"`]\]

# Object property assignment from user input (bracket notation with variable)
\[\s*(?:req\.|params\.|query\.|body\.|input\.|data\.|user)

# JSON.parse without prototype filtering
JSON\.parse\s*\(\s*(req\.|params\.|query\.|body\.|input)

# Recursive object iteration without __proto__ check
for\s*\(\s*(let|var|const)\s+\w+\s+in\s+
```

### Vulnerable Code Examples

#### Object.assign with User Input

```javascript
// VULNERABLE: Object.assign merges __proto__
function updateConfig(userInput) {
  const config = {};
  Object.assign(config, JSON.parse(userInput));
  // If userInput = '{"__proto__":{"isAdmin":true}}'
  // All objects now have isAdmin === true
}

// VULNERABLE: Spread operator doesn't protect against __proto__
const merged = { ...defaults, ...JSON.parse(userInput) };
```

#### Lodash merge/set

```javascript
// VULNERABLE: lodash _.merge with user input
const _ = require('lodash');
app.put('/settings', (req, res) => {
  _.merge(globalSettings, req.body);
  // Payload: {"__proto__":{"polluted":"yes"}}
});

// VULNERABLE: lodash _.set with user-controlled path
app.post('/update', (req, res) => {
  _.set(config, req.body.path, req.body.value);
  // Payload: { path: "__proto__.isAdmin", value: true }
});

// VULNERABLE: lodash _.defaultsDeep
_.defaultsDeep(target, JSON.parse(untrustedJSON));
```

#### Recursive Merge without Protection

```javascript
// VULNERABLE: Custom recursive merge
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]); // No __proto__ check!
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Called with user input
merge({}, JSON.parse(req.body));
```

#### Bracket Notation Property Assignment

```javascript
// VULNERABLE: Dynamic property assignment from user input
function setNestedProperty(obj, path, value) {
  const keys = path.split('.');
  let current = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    if (!current[keys[i]]) current[keys[i]] = {};
    current = current[keys[i]]; // keys[i] could be "__proto__"
  }
  current[keys[keys.length - 1]] = value;
}
```

---

## 4. JWT and Authentication Issues

### CWE References

| CWE | Name |
|-----|------|
| CWE-287 | Improper Authentication |
| CWE-288 | Authentication Bypass Using an Alternate Path or Channel |
| CWE-290 | Authentication Bypass by Spoofing |
| CWE-302 | Authentication Bypass by Assumed-Immutable Data |
| CWE-306 | Missing Authentication for Critical Function |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm |
| CWE-347 | Improper Verification of Cryptographic Signature |
| CWE-522 | Insufficiently Protected Credentials |
| CWE-613 | Insufficient Session Expiration |
| CWE-922 | Insecure Storage of Sensitive Information |

### Dangerous Functions / Patterns for Regex Matching

```
localStorage.setItem(.*token
localStorage.setItem(.*jwt
localStorage.setItem(.*session
localStorage.getItem(.*token
sessionStorage.setItem(.*token
jwt.sign(                    # without proper options
jwt.verify(                  # without algorithm specification
jwt.decode(                  # used instead of verify
jsonwebtoken.decode(
algorithms: ['none']         # JWT "none" algorithm
algorithms: \[.*HS.*RS       # algorithm confusion
expiresIn:                   # look for missing expiration
{ verify: false }            # disabled verification
ignoreExpiration: true
```

### Regex Patterns

```regex
# Storing tokens in localStorage/sessionStorage
localStorage\.(setItem|getItem)\s*\(\s*['"`].*(token|jwt|auth|session|credential|secret|key|password)

sessionStorage\.(setItem|getItem)\s*\(\s*['"`].*(token|jwt|auth|session)

# jwt.decode used for authentication (should use verify)
jwt\.decode\s*\(
jsonwebtoken.*\.decode\s*\(

# jwt.verify without algorithms option
jwt\.verify\s*\([^)]*\)\s*(?!.*algorithms)

# JWT "none" algorithm
algorithms\s*:\s*\[['"`]none['"`]\]

# Missing expiration in jwt.sign
jwt\.sign\s*\([^)]*\)\s*(?!.*expiresIn)

# Ignore expiration
ignoreExpiration\s*:\s*true

# Disabled verification
verify\s*:\s*false

# Hardcoded JWT secrets
jwt\.sign\s*\([^,]+,\s*['"`][^'"`]{5,}['"`]
```

### Vulnerable Code Examples

#### localStorage JWT Storage

```javascript
// VULNERABLE: JWT in localStorage (accessible via XSS)
function login(credentials) {
  const response = await fetch('/api/login', {
    method: 'POST',
    body: JSON.stringify(credentials),
  });
  const { token } = await response.json();
  localStorage.setItem('authToken', token); // XSS can steal this!
}

// VULNERABLE: Token in sessionStorage
sessionStorage.setItem('jwt', token);

// VULNERABLE: Token exposed in Authorization header from localStorage
fetch('/api/data', {
  headers: {
    Authorization: `Bearer ${localStorage.getItem('token')}`,
  },
});
```

#### JWT Verification Bypass

```javascript
// VULNERABLE: Using decode instead of verify (no signature check)
const jwt = require('jsonwebtoken');
app.get('/profile', (req, res) => {
  const token = req.headers.authorization.split(' ')[1];
  const user = jwt.decode(token); // Does NOT verify signature!
  res.json(user);
});

// VULNERABLE: verify without specifying algorithms
jwt.verify(token, publicKey); // susceptible to algorithm confusion
// Attacker can switch RS256 to HS256, using public key as HMAC secret

// VULNERABLE: "none" algorithm allowed
jwt.verify(token, secret, { algorithms: ['none', 'HS256'] });

// VULNERABLE: Hardcoded secret
const token = jwt.sign(payload, 'my-super-secret-key-123');

// VULNERABLE: Missing expiration
const token = jwt.sign({ userId: user.id }, SECRET);
// No expiresIn - token never expires

// VULNERABLE: ignoreExpiration
jwt.verify(token, secret, { ignoreExpiration: true });
```

#### Missing Auth on API Endpoints

```javascript
// VULNERABLE: No authentication check
app.get('/api/admin/users', (req, res) => {
  const users = db.getAllUsers();
  res.json(users); // Anyone can access admin data
});

// VULNERABLE: Auth check only on some methods
app.route('/api/settings')
  .get(authenticate, getSettings)
  .put(updateSettings); // PUT has no authentication!
```

---

## 5. Secret Exposure in Client Bundles

### CWE References

| CWE | Name |
|-----|------|
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor |
| CWE-312 | Cleartext Storage of Sensitive Information |
| CWE-319 | Cleartext Transmission of Sensitive Information |
| CWE-522 | Insufficiently Protected Credentials |
| CWE-540 | Inclusion of Sensitive Information in Source Code |
| CWE-615 | Inclusion of Sensitive Information in Source Code Comments |
| CWE-798 | Use of Hard-coded Credentials |

### Dangerous Functions / Patterns for Regex Matching

```
REACT_APP_                  # Create React App public env vars
NEXT_PUBLIC_                # Next.js public env vars
VITE_                       # Vite public env vars
EXPO_PUBLIC_                # Expo public env vars
process.env.                # In browser-bundled code
import.meta.env.            # Vite environment variables

# Hardcoded secret patterns
api[_-]?key\s*[:=]
api[_-]?secret\s*[:=]
secret[_-]?key\s*[:=]
private[_-]?key\s*[:=]
access[_-]?token\s*[:=]
auth[_-]?token\s*[:=]
password\s*[:=]
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
STRIPE_SECRET_KEY
DATABASE_URL
MONGODB_URI
OPENAI_API_KEY
GITHUB_TOKEN
firebase.*apiKey
```

### Regex Patterns

```regex
# Framework-specific public env var prefixes with sensitive names
REACT_APP_.*(SECRET|KEY|PASSWORD|TOKEN|PRIVATE|CREDENTIAL|API_KEY)
NEXT_PUBLIC_.*(SECRET|KEY|PASSWORD|TOKEN|PRIVATE|CREDENTIAL|API_KEY)
VITE_.*(SECRET|KEY|PASSWORD|TOKEN|PRIVATE|CREDENTIAL|API_KEY)
EXPO_PUBLIC_.*(SECRET|KEY|PASSWORD|TOKEN|PRIVATE|CREDENTIAL|API_KEY)

# process.env in client-side code
process\.env\.(REACT_APP_|NEXT_PUBLIC_|VITE_)

# Hardcoded API keys (common formats)
['"`](sk|pk|api|key|token|secret|password)[-_]?[a-zA-Z0-9]{20,}['"`]

# AWS access key pattern
['"`]AKIA[0-9A-Z]{16}['"`]

# Generic API key in assignment
(api[_-]?key|apiKey|api_secret|apiSecret|secret_key|secretKey|access_token|accessToken|auth_token|authToken|private_key|privateKey)\s*[:=]\s*['"`][^'"`]{8,}['"`]

# Stripe secret key
sk_(live|test)_[a-zA-Z0-9]{24,}

# Database connection strings
(mongodb(\+srv)?|postgres(ql)?|mysql|redis|amqp):\/\/[^\s'"`]+

# Firebase config object with API key
apiKey\s*:\s*['"`]AIza[a-zA-Z0-9_-]{35}['"`]

# GitHub/GitLab tokens
(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}
glpat-[A-Za-z0-9_-]{20,}

# OpenAI API key
sk-[a-zA-Z0-9]{20,}

# SendGrid API key
SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}

# Twilio
SK[a-f0-9]{32}

# Private key blocks
-----BEGIN (RSA |EC )?PRIVATE KEY-----
```

### Vulnerable Code Examples

#### React (Create React App) Environment Variables

```javascript
// VULNERABLE: Secret in REACT_APP_ env var (bundled into client JS)
// .env file:
// REACT_APP_API_SECRET=sk_live_EXAMPLE_REDACTED
// REACT_APP_DATABASE_URL=postgres://user:pass@host/db

const apiSecret = process.env.REACT_APP_API_SECRET; // In client bundle!
fetch('/api/data', {
  headers: { 'X-API-Key': process.env.REACT_APP_API_SECRET }
});
```

#### Next.js Public Environment Variables

```javascript
// VULNERABLE: Secret exposed via NEXT_PUBLIC_ prefix
// .env.local:
// NEXT_PUBLIC_STRIPE_SECRET=sk_live_EXAMPLE_REDACTED
// NEXT_PUBLIC_DB_PASSWORD=mypassword

// This is in the client bundle
const stripe = new Stripe(process.env.NEXT_PUBLIC_STRIPE_SECRET);
```

#### Vite Environment Variables

```javascript
// VULNERABLE: Secret exposed via VITE_ prefix
// .env:
// VITE_API_SECRET=secret123
// VITE_DATABASE_URL=postgres://...

const apiSecret = import.meta.env.VITE_API_SECRET; // In client bundle!
```

#### Hardcoded Secrets in Source Code

```javascript
// VULNERABLE: Hardcoded API keys
const config = {
  stripeKey: 'sk_live_EXAMPLE_KEY_REDACTED',
  awsAccessKey: 'AKIAIOSFODNN7EXAMPLE',
  awsSecretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  dbPassword: 'supersecretpassword123',
  jwtSecret: 'my-jwt-secret-key-do-not-share',
};

// VULNERABLE: Firebase config with sensitive data
const firebaseConfig = {
  apiKey: "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q",
  authDomain: "myapp.firebaseapp.com",
  databaseURL: "https://myapp.firebaseio.com",
  projectId: "myapp-12345",
  storageBucket: "myapp.appspot.com",
  messagingSenderId: "123456789",
  appId: "1:123456789:web:abc123def456"
};

// VULNERABLE: GitHub token in code
const octokit = new Octokit({
  auth: 'ghp_ABCDEFghijklmnopqrstuvwxyz0123456789'
});
```

---

## 6. SSRF in Server-Side Rendering

### CWE References

| CWE | Name |
|-----|------|
| CWE-918 | Server-Side Request Forgery (SSRF) |
| CWE-441 | Unintended Proxy or Intermediary (Confused Deputy) |
| CWE-601 | URL Redirection to Untrusted Site (Open Redirect, related) |

### Dangerous Functions / Patterns for Regex Matching

```
fetch(                      # with user-controlled URL
axios(                      # with user-controlled URL
axios.get(
axios.post(
http.get(
http.request(
https.get(
https.request(
got(
superagent(
request(                    # deprecated 'request' package
needle(
node-fetch(
undici.fetch(
```

### Regex Patterns

```regex
# fetch/axios with request parameters in SSR context
fetch\s*\(\s*(req\.|params\.|query\.|body\.|url|`[^`]*\$\{)
axios\.(get|post|put|delete|patch|request)\s*\(\s*(req\.|params\.|query\.|body\.|`[^`]*\$\{)

# http/https module with user input
https?\.(?:get|request)\s*\(\s*(?:req\.|params\.|query\.|body\.|`[^`]*\$\{)

# URL constructor with user input in SSR
new\s+URL\s*\(\s*(req\.|params\.|query\.|body\.)

# getServerSideProps with fetch using user input
getServerSideProps.*fetch\s*\(

# Next.js API route with outbound request
export\s+(?:default\s+)?(?:async\s+)?function\s+(?:handler|GET|POST|PUT|DELETE).*fetch\s*\(
```

### Vulnerable Code Examples

#### Next.js getServerSideProps SSRF

```javascript
// VULNERABLE: User-controlled URL in getServerSideProps
export async function getServerSideProps(context) {
  const { url } = context.query;
  // Attacker can set url=http://169.254.169.254/latest/meta-data/
  // to access AWS metadata service
  const res = await fetch(url);
  const data = await res.json();
  return { props: { data } };
}

// VULNERABLE: URL construction from user params
export async function getServerSideProps({ params }) {
  const res = await fetch(`http://internal-api/${params.resource}`);
  const data = await res.json();
  return { props: { data } };
}
```

#### Next.js API Route SSRF

```javascript
// VULNERABLE: API route proxying user-specified URL
export default async function handler(req, res) {
  const { target } = req.query;
  const response = await fetch(target); // SSRF!
  const data = await response.json();
  res.json(data);
}

// VULNERABLE: Partial URL construction
export default async function handler(req, res) {
  const { host, path } = req.body;
  const response = await axios.get(`https://${host}/${path}`);
  // host could be: "evil.com#@internal-service"
  res.json(response.data);
}
```

#### Image/File Proxy SSRF

```javascript
// VULNERABLE: Image proxy without URL validation
export default async function handler(req, res) {
  const imageUrl = req.query.src;
  const imageResponse = await fetch(imageUrl);
  const buffer = await imageResponse.buffer();
  res.setHeader('Content-Type', 'image/png');
  res.send(buffer);
  // Attacker: /api/image?src=http://localhost:6379/INFO (Redis info)
}
```

---

## 7. Open Redirects

### CWE References

| CWE | Name |
|-----|------|
| CWE-601 | URL Redirection to Untrusted Site (Open Redirect) |

### Dangerous Functions / Patterns for Regex Matching

```
window.location =
window.location.href =
window.location.assign(
window.location.replace(
document.location =
document.location.href =
res.redirect(
res.writeHead(3
response.redirect(
router.push(                # React Router, Next.js router
router.replace(
navigate(                   # React Router v6
history.push(
history.replace(
location.href =
self.location =
top.location =
window.open(
meta http-equiv="refresh"
```

### Regex Patterns

```regex
# window.location with user input
window\.location\s*=\s*(?!['"`]https?:\/\/)
window\.location\.href\s*=\s*(?!['"`]https?:\/\/)
window\.location\.(assign|replace)\s*\(\s*(?!['"`]https?:\/\/)

# document.location with user input
document\.location\s*=
document\.location\.href\s*=

# Server-side redirect with user input
res\.redirect\s*\(\s*(?:req\.|params\.|query\.|body\.)
res\.redirect\s*\(\s*(?!['"`]\/[^\/]|['"`]https?:\/\/(www\.)?mydomain)

# React Router / Next.js router
router\.(push|replace)\s*\(\s*(?:req\.|params\.|query\.|searchParams)
navigate\s*\(\s*(?!['"`]\/[^\/])

# window.open with user input
window\.open\s*\(\s*(?:req\.|params\.|query\.|body\.|user)

# Return URL / redirect URL from params
(returnUrl|redirectUrl|redirect_uri|next|callback|return_to|goto|target|destination|continue|redir)\s*=
```

### Vulnerable Code Examples

#### Client-Side Open Redirect

```javascript
// VULNERABLE: Redirect from URL parameter
function RedirectComponent() {
  const params = new URLSearchParams(window.location.search);
  const redirectUrl = params.get('redirect');
  window.location.href = redirectUrl; // Open redirect!
  // Exploit: ?redirect=https://evil.com/phishing
}

// VULNERABLE: React Router redirect from query param
function LoginCallback() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  useEffect(() => {
    const returnTo = searchParams.get('returnTo');
    navigate(returnTo); // Open redirect!
  }, []);
}

// VULNERABLE: Next.js router push from query
function AuthCallback() {
  const router = useRouter();
  useEffect(() => {
    const { redirect } = router.query;
    router.push(redirect); // Open redirect!
  }, []);
}
```

#### Server-Side Open Redirect

```javascript
// VULNERABLE: Express redirect with user input
app.get('/redirect', (req, res) => {
  res.redirect(req.query.url); // Open redirect!
});

// VULNERABLE: Next.js API route redirect
export default function handler(req, res) {
  const { callback } = req.query;
  res.redirect(callback); // Open redirect!
}

// VULNERABLE: Next.js middleware redirect
export function middleware(request) {
  const url = request.nextUrl.searchParams.get('redirect');
  return NextResponse.redirect(url); // Open redirect!
}
```

---

## 8. CORS Misconfiguration

### CWE References

| CWE | Name |
|-----|------|
| CWE-942 | Permissive Cross-domain Policy with Untrusted Domains |
| CWE-346 | Origin Validation Error |
| CWE-284 | Improper Access Control |

### Dangerous Functions / Patterns for Regex Matching

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Origin
Access-Control-Allow-Credentials: true
cors()                      # without options = allow all
cors({                      # check for permissive configs
origin: '*'
origin: true               # reflects any origin
credentials: true
```

### Regex Patterns

```regex
# Wildcard CORS
Access-Control-Allow-Origin['":\s]*\*

# CORS with credentials and wildcard (invalid but often attempted)
(credentials\s*:\s*true|Access-Control-Allow-Credentials['":\s]*true)

# Origin reflection (echoing back the Origin header)
origin\s*:\s*(req\.headers\.origin|req\.header\(['"`]origin['"`]\)|true)

# cors() without configuration (allows all origins)
\bcors\s*\(\s*\)

# Permissive origin pattern
origin\s*:\s*['"`]\*['"`]
origin\s*:\s*true

# Origin regex that's too permissive
origin\s*:\s*\/.*\.\*.*\/
origin\s*:\s*\(.*\.includes\(|\.endsWith\(|\.indexOf\()

# Express CORS headers
res\.setHeader\s*\(\s*['"`]Access-Control-Allow-Origin['"`]\s*,\s*['"`]\*['"`]\s*\)
res\.header\s*\(\s*['"`]Access-Control-Allow-Origin['"`]\s*,\s*req\.headers\.origin
```

### Vulnerable Code Examples

#### Express CORS Misconfiguration

```javascript
// VULNERABLE: Wildcard origin with credentials
const cors = require('cors');
app.use(cors({
  origin: '*',
  credentials: true // This combination is actually invalid,
                     // but misunderstanding leads to other misconfigs
}));

// VULNERABLE: Reflecting origin header (allows any domain)
app.use(cors({
  origin: true, // Reflects any origin
  credentials: true
}));

// VULNERABLE: Origin reflection manually
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});

// VULNERABLE: Weak origin validation
app.use(cors({
  origin: (origin, callback) => {
    if (origin.includes('myapp.com')) {
      callback(null, true);
    }
    // Bypass: evil-myapp.com or myapp.com.evil.com
  },
  credentials: true
}));

// VULNERABLE: Regex with unescaped dot
app.use(cors({
  origin: /myapp.com$/, // Matches "myappXcom" too
  credentials: true
}));
```

#### Next.js API Route CORS

```javascript
// VULNERABLE: Permissive CORS in Next.js API route
export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', '*');
  // ... handler logic
}

// VULNERABLE: Reflecting origin in Next.js
export default function handler(req, res) {
  const origin = req.headers.origin;
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
}
```

---

## 9. Node.js Server-Side Vulnerabilities

### CWE References

| CWE | Name |
|-----|------|
| CWE-22 | Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) |
| CWE-89 | Improper Neutralization of Special Elements used in an SQL Command (SQL Injection) |
| CWE-78 | Improper Neutralization of Special Elements used in an OS Command (Command Injection) |
| CWE-98 | Improper Control of Filename for Include/Require Statement (adapted for dynamic require in Node) |
| CWE-434 | Unrestricted Upload of File with Dangerous Type |
| CWE-502 | Deserialization of Untrusted Data |
| CWE-611 | Improper Restriction of XML External Entity Reference |
| CWE-776 | Improper Restriction of Recursive Entity References in DTDs (XML Entity Expansion) |

### Dangerous Functions / Patterns for Regex Matching

```
# Path Traversal
fs.readFile(
fs.readFileSync(
fs.writeFile(
fs.writeFileSync(
fs.unlink(
fs.unlinkSync(
fs.readdir(
fs.readdirSync(
fs.createReadStream(
fs.createWriteStream(
fs.access(
fs.stat(
path.join(                  # with user input
path.resolve(               # with user input
res.sendFile(
res.download(
express.static(

# SQL Injection
.query(                     # with string concatenation
.raw(                       # Sequelize raw query
.execute(                   # with string concatenation
knex.raw(
sequelize.query(
pool.query(
client.query(
connection.query(
db.query(
$queryRawUnsafe(            # Prisma unsafe raw query

# Dynamic require
require(                    # with variable argument

# Deserialization
node-serialize
unserialize(
funcster
```

### Regex Patterns

```regex
# Path traversal in fs operations
fs\.(readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync|readdir|readdirSync|createReadStream|createWriteStream|access|stat|statSync|existsSync|appendFile|appendFileSync|copyFile|copyFileSync|rename|renameSync|mkdir|mkdirSync|rmdir|rmdirSync)\s*\(\s*(?:req\.|params\.|query\.|body\.|`[^`]*\$\{)

# path.join/resolve with user input
path\.(join|resolve)\s*\([^)]*(?:req\.|params\.|query\.|body\.)

# res.sendFile/download with user input
res\.(sendFile|download)\s*\(\s*(?:req\.|params\.|query\.|body\.|`[^`]*\$\{|path\.(join|resolve))

# SQL injection - string concatenation in queries
\.(query|execute)\s*\(\s*['"`].*\+\s*(?:req\.|params\.|query\.|body\.|user)
\.(query|execute)\s*\(\s*`[^`]*\$\{(?:req\.|params\.|query\.|body\.|user)

# Sequelize raw query
sequelize\.query\s*\(\s*['"`].*\+
sequelize\.query\s*\(\s*`[^`]*\$\{

# knex.raw with concatenation
knex\.raw\s*\(\s*['"`].*\+
knex\.raw\s*\(\s*`[^`]*\$\{

# Prisma unsafe raw queries
\$queryRawUnsafe\s*\(
\$executeRawUnsafe\s*\(

# Dynamic require
require\s*\(\s*(?!['"`])[a-zA-Z]

# node-serialize (known vulnerable)
(require|import).*node-serialize
\.unserialize\s*\(
serialize\.unserialize\s*\(

# XXE in XML parsing
(xml2js|libxmljs|xmldom|fast-xml-parser|sax)
DOMParser\(\)
```

### Vulnerable Code Examples

#### Path Traversal

```javascript
// VULNERABLE: File read with user-controlled path
app.get('/file', (req, res) => {
  const filePath = path.join('/uploads', req.query.name);
  // req.query.name = "../../etc/passwd"
  fs.readFile(filePath, (err, data) => {
    res.send(data);
  });
});

// VULNERABLE: sendFile with user input
app.get('/download/:filename', (req, res) => {
  res.sendFile(path.join(__dirname, 'files', req.params.filename));
  // ../../../etc/passwd
});

// VULNERABLE: Directory listing
app.get('/browse', (req, res) => {
  const dir = req.query.path;
  fs.readdir(dir, (err, files) => {
    res.json(files);
  });
});

// VULNERABLE: File write with user-controlled path
app.post('/save', (req, res) => {
  const { filename, content } = req.body;
  fs.writeFileSync(path.join('/uploads', filename), content);
  // filename = "../../app/server.js" -> overwrite server code
});
```

#### SQL Injection

```javascript
// VULNERABLE: String concatenation in SQL query
const mysql = require('mysql');
app.get('/user', (req, res) => {
  const query = `SELECT * FROM users WHERE id = ${req.query.id}`;
  connection.query(query, (err, results) => {
    res.json(results);
  });
});

// VULNERABLE: Template literal in SQL
app.get('/search', (req, res) => {
  const query = `SELECT * FROM products WHERE name LIKE '%${req.query.term}%'`;
  pool.query(query, (err, results) => {
    res.json(results);
  });
});

// VULNERABLE: Sequelize raw query with interpolation
const results = await sequelize.query(
  `SELECT * FROM users WHERE email = '${req.body.email}'`
);

// VULNERABLE: knex.raw with string concatenation
const results = await knex.raw(
  `SELECT * FROM orders WHERE user_id = ${userId}`
);

// VULNERABLE: pg (node-postgres) with concatenation
const { rows } = await client.query(
  'SELECT * FROM users WHERE username = \'' + username + '\''
);

// VULNERABLE: Prisma $queryRawUnsafe
const results = await prisma.$queryRawUnsafe(
  `SELECT * FROM users WHERE name = '${userInput}'`
);
```

#### Dynamic require()

```javascript
// VULNERABLE: Dynamic require with user input
app.get('/plugin/:name', (req, res) => {
  const plugin = require(`./plugins/${req.params.name}`);
  // Can traverse: ../../etc/passwd or load unexpected modules
  plugin.run();
});

// VULNERABLE: Dynamic import with user input
app.get('/module/:name', async (req, res) => {
  const mod = await import(req.params.name);
  res.json(mod.default());
});
```

#### Deserialization

```javascript
// VULNERABLE: node-serialize (CVE-2017-5941)
const serialize = require('node-serialize');
app.post('/data', (req, res) => {
  const obj = serialize.unserialize(req.body.data);
  // Attacker can run arbitrary code via IIFE in serialized data
});
```

---

## 10. Dependency Risks

### CWE References

| CWE | Name |
|-----|------|
| CWE-1104 | Use of Unmaintained Third Party Components |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere |
| CWE-937 | Using Components with Known Vulnerabilities (OWASP A06:2021) |
| CWE-1357 | Reliance on Insufficiently Trustworthy Component |

### Dangerous Patterns for Regex Matching

```
# package.json patterns
"*"                         # Any version
"latest"                    # Latest version tag
">=                         # Very permissive range
">                          # Permissive range
"~                          # Patch-level range (less risky but notable)
"^                          # Minor-level range (common but worth noting)
"dependencies"              # Check for known vulnerable packages
postinstall                 # Post-install scripts (supply chain risk)
preinstall                  # Pre-install scripts (supply chain risk)
install                     # Install scripts (supply chain risk)
```

### Regex Patterns

```regex
# Unpinned/wildcard versions in package.json
"[^"]+"\s*:\s*"(\*|latest|>=|>[^=])"

# Known vulnerable packages (historical examples -- should be updated from advisory databases)
"(event-stream|ua-parser-js|coa|rc|colors|faker|node-ipc|peacenotwar|es5-ext)"

# Install scripts in package.json (potential supply chain attack vector)
"(pre|post)?install"\s*:\s*"[^"]*"

# require/import of known risky patterns
require\s*\(\s*['"`](node-serialize|serialize-to-js|funcster)['"`]\s*\)

# CDN script inclusion without integrity
<script\s+src=["'][^"']*cdn[^"']*["'](?![^>]*integrity)

# Importing from URL without hash
import\s+.*from\s+['"`]https?:\/\/
```

### Vulnerable Code Examples

#### package.json Anti-Patterns

```json
{
  "dependencies": {
    "lodash": "*",
    "express": "latest",
    "react": ">=16.0.0",
    "axios": ">0.18.0"
  },
  "scripts": {
    "postinstall": "node setup.js"
  }
}
```

#### Known Vulnerable Package Usage

```javascript
// VULNERABLE: event-stream@3.3.6 contained malicious code targeting copay wallet
const es = require('event-stream'); // Check version!

// VULNERABLE: node-serialize allows RCE
const serialize = require('node-serialize');

// VULNERABLE: Old version of minimist (prototype pollution)
const argv = require('minimist')(process.argv.slice(2));
```

#### CDN Without Subresource Integrity

```html
<!-- VULNERABLE: No integrity attribute -->
<script src="https://cdn.example.com/lib.js"></script>

<!-- SAFE: With SRI -->
<script
  src="https://cdn.example.com/lib.js"
  integrity="sha384-abc123..."
  crossorigin="anonymous"
></script>
```

---

## 11. React-Specific Vulnerabilities

### CWE References

| CWE | Name |
|-----|------|
| CWE-79 | XSS via dangerouslySetInnerHTML (covered above) |
| CWE-200 | Information Exposure via state/props |
| CWE-362 | Race Condition (concurrent state updates, useEffect cleanup) |
| CWE-400 | Uncontrolled Resource Consumption (memory leaks from missing cleanup) |
| CWE-668 | Exposure of Resource to Wrong Sphere |
| CWE-471 | Modification of Assumed-Immutable Data |

### Dangerous Functions / Patterns for Regex Matching

```
dangerouslySetInnerHTML       # XSS (see section 1)
createRef()                   # Direct DOM manipulation
useRef()                      # Direct DOM manipulation
findDOMNode(                  # Deprecated, unsafe DOM access
ReactDOM.render(              # Older API, can cause issues
__NEXT_DATA__                 # Server data exposure
window.__INITIAL_STATE__      # SSR state exposure
__APOLLO_STATE__              # GraphQL state exposure
```

### Regex Patterns

```regex
# Ref-based DOM manipulation (bypassing React's protections)
(useRef|createRef)\s*\(\s*\)[\s\S]{0,200}\.current\.(innerHTML|outerHTML)

# findDOMNode usage (deprecated)
ReactDOM\.findDOMNode\s*\(
findDOMNode\s*\(

# useEffect without cleanup (potential memory leak / subscription leak)
useEffect\s*\(\s*\(\s*\)\s*=>\s*\{[^}]*(addEventListener|setInterval|setTimeout|subscribe|on\(|\.listen)[^}]*\}\s*,
# Check for absence of return function

# Mutable state modification
\.current\s*=\s*(?!null|undefined|false|true|0|''|"")

# SSR state exposure in HTML
__NEXT_DATA__|__INITIAL_STATE__|__APOLLO_STATE__|__PRELOADED_STATE__|window\.__

# React context with sensitive data
createContext\s*\(\s*\{[^}]*(token|secret|password|key|credential)

# Uncontrolled form inputs with sensitive data
<input[^>]*type\s*=\s*['"`]hidden['"`][^>]*value\s*=\s*\{

# Rendering user-controlled component names
React\.createElement\s*\(\s*(?:req\.|params\.|query\.|body\.|user)
```

### Vulnerable Code Examples

#### Ref Manipulation Bypassing React Security

```jsx
// VULNERABLE: Using ref to set innerHTML (bypasses React's escaping)
function UnsafeComponent({ htmlContent }) {
  const divRef = useRef(null);

  useEffect(() => {
    if (divRef.current) {
      divRef.current.innerHTML = htmlContent; // XSS!
    }
  }, [htmlContent]);

  return <div ref={divRef} />;
}

// VULNERABLE: findDOMNode to manipulate DOM
class LegacyComponent extends React.Component {
  componentDidMount() {
    const node = ReactDOM.findDOMNode(this);
    node.innerHTML = this.props.content; // XSS!
  }
}
```

#### useEffect Cleanup Issues

```jsx
// VULNERABLE: Missing cleanup - memory leak and potential state update on unmounted component
function DataFetcher({ url }) {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetch(url)
      .then(res => res.json())
      .then(data => setData(data)); // May update state after unmount
    // Missing cleanup / abort controller!
  }, [url]);
}

// VULNERABLE: Interval without cleanup
function Timer() {
  const [count, setCount] = useState(0);
  useEffect(() => {
    setInterval(() => {
      setCount(c => c + 1);
    }, 1000);
    // Missing: return () => clearInterval(id);
  }, []);
}

// VULNERABLE: Event listener without cleanup
function ScrollTracker() {
  useEffect(() => {
    window.addEventListener('scroll', handleScroll);
    // Missing: return () => window.removeEventListener('scroll', handleScroll);
  }, []);
}

// VULNERABLE: WebSocket without cleanup
function ChatComponent() {
  useEffect(() => {
    const ws = new WebSocket('ws://chat.example.com');
    ws.onmessage = (event) => {
      setMessages(prev => [...prev, event.data]);
    };
    // Missing: return () => ws.close();
  }, []);
}
```

#### State Management Leaks

```jsx
// VULNERABLE: Sensitive data in Redux store accessible via DevTools
const userSlice = createSlice({
  name: 'user',
  initialState: {
    token: null,        // Visible in Redux DevTools
    ssn: null,          // PII in client state
    creditCard: null,   // Sensitive financial data
  },
  reducers: {
    setUser: (state, action) => {
      state.token = action.payload.token;
      state.ssn = action.payload.ssn;
    },
  },
});

// VULNERABLE: Server state leaked to client via SSR serialization
// In Next.js pages:
export async function getServerSideProps() {
  const user = await db.getUser(userId);
  return {
    props: {
      user, // Serialized into __NEXT_DATA__ -- includes ALL fields
      // May include: passwordHash, internalNotes, etc.
    },
  };
}
```

#### Dynamic Component Rendering

```jsx
// VULNERABLE: User-controlled component name
function DynamicRenderer({ componentName, props }) {
  const Component = components[componentName]; // Could access prototype chain
  return <Component {...props} />;
}

// VULNERABLE: React.createElement with user input
function render(userInput) {
  return React.createElement(userInput.type, userInput.props);
  // type could be "script" or other dangerous elements
}
```

---

## 12. Next.js-Specific Vulnerabilities

### CWE References

| CWE | Name |
|-----|------|
| CWE-200 | Exposure of Sensitive Information (data over-fetching in SSR) |
| CWE-284 | Improper Access Control (missing auth on API routes) |
| CWE-306 | Missing Authentication for Critical Function |
| CWE-346 | Origin Validation Error (middleware bypass) |
| CWE-441 | Unintended Proxy or Intermediary |
| CWE-502 | Deserialization of Untrusted Data |
| CWE-540 | Source Code Exposure (Server Components) |
| CWE-601 | Open Redirect |
| CWE-918 | SSRF (covered in section 6) |

### Dangerous Functions / Patterns for Regex Matching

```
# API routes without auth
export default function handler
export async function GET
export async function POST
export async function PUT
export async function DELETE
export async function PATCH

# Data fetching with exposure risk
getServerSideProps
getStaticProps
getInitialProps

# Server Actions / Server Components
'use server'
"use server"

# Middleware
middleware.ts
middleware.js
NextResponse.next()
NextResponse.redirect(
NextResponse.rewrite(

# __NEXT_DATA__
__NEXT_DATA__

# next.config.js dangerous options
rewrites
redirects
headers
images.domains
images.remotePatterns
experimental
serverActions

# Server Component data leaks
import 'server-only'       # When MISSING, indicates risk
```

### Regex Patterns

```regex
# API route handler without visible auth check
export\s+(default\s+)?(async\s+)?function\s+(handler|GET|POST|PUT|DELETE|PATCH)\s*\([^)]*\)\s*\{(?![\s\S]{0,500}(auth|session|verify|token|getUser|getSession|isAuthenticated|middleware|checkAuth|requireAuth|protect))

# getServerSideProps returning sensitive data
getServerSideProps[\s\S]*?return\s*\{[\s\S]*?props\s*:\s*\{[\s\S]*?(password|secret|token|ssn|creditCard|hash|salt|privateKey|internalId)

# getServerSideProps/getStaticProps with unsanitized DB query
(getServerSideProps|getStaticProps)[\s\S]*?(\.findOne|\.findMany|\.query|\.find\()[\s\S]*?return\s*\{[\s\S]*?props\s*:

# Missing 'server-only' import in server utilities
# (Look for files that use DB/secrets but don't import server-only)

# __NEXT_DATA__ script tag (inspect what's exposed)
__NEXT_DATA__

# next.config.js with permissive rewrites
rewrites\s*\(\s*\)\s*\{[\s\S]*?destination\s*:\s*['"`]https?:\/\/

# Middleware that doesn't check all routes
export\s+const\s+config\s*=\s*\{[\s\S]*?matcher\s*:\s*\[(?!.*\/)

# Server Action without validation
['"]use server['"][\s\S]*?export\s+async\s+function\s+\w+\s*\([^)]*\)\s*\{(?![\s\S]{0,300}(zod|validate|schema|parse|safeParse|check|sanitize))

# Unprotected revalidation
revalidatePath\s*\(|revalidateTag\s*\(

# Next.js redirect from user input
redirect\s*\(\s*(req\.|params\.|query\.|searchParams|formData)
```

### Vulnerable Code Examples

#### API Routes Without Authentication

```typescript
// VULNERABLE: No auth check on sensitive endpoint
// app/api/users/route.ts
export async function GET() {
  const users = await prisma.user.findMany();
  return Response.json(users); // Anyone can list all users!
}

// VULNERABLE: Admin action without role check
// app/api/admin/delete-user/route.ts
export async function DELETE(request: Request) {
  const { userId } = await request.json();
  await prisma.user.delete({ where: { id: userId } });
  return Response.json({ success: true });
}

// VULNERABLE: Partial auth (only some methods)
// pages/api/settings.ts
export default async function handler(req, res) {
  if (req.method === 'GET') {
    // No auth check!
    const settings = await getSettings();
    return res.json(settings);
  }
  if (req.method === 'PUT') {
    const session = await getSession(req);
    if (!session) return res.status(401).end();
    // ... update logic
  }
}
```

#### getServerSideProps Data Over-Exposure

```typescript
// VULNERABLE: Returning full database object to client
export async function getServerSideProps({ params }) {
  const user = await prisma.user.findUnique({
    where: { id: params.id },
  });

  return {
    props: {
      user, // Includes passwordHash, email, internalNotes, etc.
      // All serialized into HTML as __NEXT_DATA__
    },
  };
}

// VULNERABLE: Leaking internal API response
export async function getServerSideProps() {
  const res = await fetch('http://internal-service/data', {
    headers: { 'X-Internal-Key': process.env.INTERNAL_API_KEY }
  });
  const data = await res.json();

  return {
    props: { data }, // Internal fields exposed to client
  };
}
```

#### Server Actions Without Validation

```typescript
// VULNERABLE: Server Action with no input validation
'use server';

export async function updateProfile(formData: FormData) {
  const name = formData.get('name');
  const role = formData.get('role'); // User can submit role=admin!

  await prisma.user.update({
    where: { id: getCurrentUserId() },
    data: { name, role }, // Mass assignment vulnerability
  });
}

// VULNERABLE: Server Action without auth check
'use server';

export async function deletePost(postId: string) {
  // No session verification!
  await prisma.post.delete({ where: { id: postId } });
}

// VULNERABLE: Server Action with SQL injection
'use server';

export async function searchUsers(query: string) {
  const results = await prisma.$queryRawUnsafe(
    `SELECT * FROM users WHERE name LIKE '%${query}%'`
  );
  return results;
}
```

#### Middleware Bypass

```typescript
// VULNERABLE: Middleware only checks specific paths
// middleware.ts
export function middleware(request: NextRequest) {
  const token = request.cookies.get('token');
  if (!token) {
    return NextResponse.redirect(new URL('/login', request.url));
  }
}

// Only protects /dashboard routes, API routes are unprotected!
export const config = {
  matcher: ['/dashboard/:path*'],
  // Missing: '/api/:path*'
};

// VULNERABLE: Middleware auth check bypass via path manipulation
export function middleware(request: NextRequest) {
  // Attacker can bypass with encoded or normalized path variations
  if (request.nextUrl.pathname.startsWith('/api/admin')) {
    const session = await getToken({ req: request });
    if (!session?.isAdmin) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }
  }
}

// VULNERABLE: Not checking for middleware skip via _next prefix
// Next.js internal routes starting with _next bypass middleware by default
```

#### Server Component Source Code Exposure (CVE-2025-55183)

```typescript
// VULNERABLE: Server Function that can leak source code
// (Patched in React 19.1.0-canary and later)
'use server';

export async function processInput(name: string) {
  const conn = db.createConnection(process.env.SECRET_KEY);
  // If 'name' is an object with toString override,
  // error messages could expose the function's source code
  const user = await conn.createUser(name);
  return { message: `Hello, ${name}!` };
}
```

#### next.config.js Misconfigurations

```javascript
// VULNERABLE: Permissive rewrites acting as open proxy
// next.config.js
module.exports = {
  async rewrites() {
    return [
      {
        source: '/api/proxy/:path*',
        destination: 'https://external-api.com/:path*', // Fine
      },
      {
        source: '/proxy/:url*',
        destination: '/:url*', // Open proxy!
      },
    ];
  },

  // VULNERABLE: Overly permissive image domains
  images: {
    domains: ['*'], // Allows any domain for image optimization
    // Can be used for SSRF via image optimization endpoint
  },

  // VULNERABLE: Permissive headers
  async headers() {
    return [
      {
        source: '/api/:path*',
        headers: [
          { key: 'Access-Control-Allow-Origin', value: '*' },
          { key: 'Access-Control-Allow-Credentials', value: 'true' },
        ],
      },
    ];
  },
};
```

---

## Appendix A: Comprehensive Regex Pattern Summary

This section provides consolidated regex patterns organized for direct use in a scanner tool.

### Critical Severity Patterns

```regex
# XSS via dangerouslySetInnerHTML with variable
dangerouslySetInnerHTML\s*=\s*\{

# eval / Function constructor
\beval\s*\(
new\s+Function\s*\(

# Command injection via string concatenation
(exec|execSync)\s*\(\s*(`[^`]*\$\{|['"][^'"]*\+)
spawn\s*\(.*shell\s*:\s*true

# SQL injection
\.(query|execute)\s*\(\s*(`[^`]*\$\{|['"][^'"]*\+\s*(?:req|params|query|body|user))
(sequelize\.query|knex\.raw)\s*\(\s*(`[^`]*\$\{|['"][^'"]*\+)
\$queryRawUnsafe\s*\(

# Hardcoded secrets
(sk_live_|sk_test_)[a-zA-Z0-9]{24,}
AKIA[0-9A-Z]{16}
-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----
(ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{36,}

# Deserialization RCE
(require|import).*node-serialize
\.unserialize\s*\(

# Prototype pollution
__proto__
constructor\s*\[\s*['"`]prototype['"`]\s*\]
```

### High Severity Patterns

```regex
# innerHTML/outerHTML assignment
\.(innerHTML|outerHTML)\s*=\s*(?!['"`])

# document.write
document\.write(ln)?\s*\(

# insertAdjacentHTML
\.insertAdjacentHTML\s*\(

# SSRF
fetch\s*\(\s*(req\.|params\.|query\.|body\.)
axios\.(get|post|put|delete)\s*\(\s*(req\.|params\.|query\.|body\.)

# Path traversal
(readFile|readFileSync|writeFile|writeFileSync|createReadStream|sendFile)\s*\(\s*(?:req\.|params\.|query\.|body\.|path\.(join|resolve)\s*\([^)]*(?:req|params|query|body))

# Open redirect
(window\.location|document\.location)\s*(\.href\s*)?=\s*(?!['"`](\/[^\/]|https?:\/\/))
res\.redirect\s*\(\s*(?:req\.|params\.|query\.)

# JWT decode without verify
jwt\.decode\s*\(

# Missing auth on API routes
export\s+(default\s+)?(async\s+)?function\s+(handler|GET|POST|PUT|DELETE|PATCH)\s*\(

# Client-side secret exposure
(REACT_APP_|NEXT_PUBLIC_|VITE_).*(SECRET|KEY|PASSWORD|TOKEN|PRIVATE)

# CORS wildcard with credentials
origin\s*:\s*(['"`]\*['"`]|true)[\s\S]*?credentials\s*:\s*true

# lodash prototype pollution vectors
_\.(merge|defaultsDeep|set)\s*\(\s*[^,]+,\s*(?:req|params|query|body|user)

# Dynamic require
require\s*\(\s*(?!['"`])(?:req|params|query|body|user)
```

### Medium Severity Patterns

```regex
# jQuery HTML injection
\$\s*\([^)]*\)\s*\.\s*(html|append|prepend|after|before|replaceWith)\s*\(

# setTimeout/setInterval with string
(setTimeout|setInterval)\s*\(\s*['"`]

# localStorage with tokens
localStorage\.(setItem|getItem)\s*\(\s*['"`].*(token|jwt|auth|session)

# Missing useEffect cleanup
useEffect\s*\(\s*\(\s*\)\s*=>\s*\{[^}]*(addEventListener|setInterval|setTimeout|subscribe|WebSocket)

# vm module usage
vm\.(runInNewContext|runInThisContext|runInContext)\s*\(

# href javascript: protocol
href\s*=\s*\{[^}]*\}(?=.*javascript:)

# CORS permissive
cors\s*\(\s*\)
Access-Control-Allow-Origin['":\s]*\*

# Unvalidated redirects in Next.js
router\.(push|replace)\s*\(\s*(?!['"`]\/[^\/])
redirect\s*\(\s*(?:req|params|query|searchParams|formData)

# Server Actions without validation
['"]use server['"][\s\S]*?export\s+async\s+function

# __NEXT_DATA__ exposure
__NEXT_DATA__|__INITIAL_STATE__|__PRELOADED_STATE__

# findDOMNode (deprecated)
findDOMNode\s*\(
```

---

## Appendix B: CWE Quick Reference Table

| CWE | Name | Categories |
|-----|------|------------|
| CWE-22 | Path Traversal | Node.js Server |
| CWE-78 | OS Command Injection | Dynamic Code, Node.js Server |
| CWE-79 | XSS | XSS |
| CWE-80 | Basic XSS | XSS |
| CWE-83 | XSS in Attributes | XSS |
| CWE-87 | Alternate XSS Syntax | XSS |
| CWE-89 | SQL Injection | Node.js Server |
| CWE-94 | Code Injection | Dynamic Code |
| CWE-95 | Eval Injection | Dynamic Code |
| CWE-98 | Dynamic Include | Node.js Server |
| CWE-116 | Improper Output Encoding | XSS |
| CWE-200 | Information Exposure | Secrets, React, Next.js |
| CWE-284 | Improper Access Control | CORS, Next.js |
| CWE-287 | Improper Authentication | JWT/Auth |
| CWE-288 | Auth Bypass via Alternate Path | JWT/Auth |
| CWE-290 | Auth Bypass by Spoofing | JWT/Auth |
| CWE-302 | Auth Bypass via Immutable Data | JWT/Auth |
| CWE-306 | Missing Authentication | JWT/Auth, Next.js |
| CWE-312 | Cleartext Storage | Secrets |
| CWE-319 | Cleartext Transmission | Secrets |
| CWE-327 | Broken Crypto Algorithm | JWT/Auth |
| CWE-346 | Origin Validation Error | CORS, Next.js |
| CWE-347 | Improper Signature Verification | JWT/Auth |
| CWE-362 | Race Condition | React |
| CWE-400 | Uncontrolled Resource Consumption | Prototype Pollution, React |
| CWE-434 | Unrestricted File Upload | Node.js Server |
| CWE-441 | Unintended Proxy | SSRF, Next.js |
| CWE-471 | Modification of Immutable Data | React |
| CWE-502 | Unsafe Deserialization | Node.js Server, Next.js |
| CWE-522 | Insufficiently Protected Credentials | JWT/Auth, Secrets |
| CWE-540 | Source Code in Info | Secrets, Next.js |
| CWE-601 | Open Redirect | Open Redirects |
| CWE-611 | XXE | Node.js Server |
| CWE-613 | Insufficient Session Expiration | JWT/Auth |
| CWE-615 | Info in Source Code Comments | Secrets |
| CWE-668 | Resource Exposure to Wrong Sphere | React |
| CWE-776 | XML Entity Expansion | Node.js Server |
| CWE-798 | Hard-coded Credentials | Secrets |
| CWE-829 | Untrusted Functionality Inclusion | Dependencies |
| CWE-915 | Dynamic Object Attribute Modification | Prototype Pollution |
| CWE-918 | SSRF | SSRF |
| CWE-922 | Insecure Storage | JWT/Auth |
| CWE-937 | Known Vulnerable Components | Dependencies |
| CWE-942 | Permissive Cross-domain Policy | CORS |
| CWE-1104 | Unmaintained Components | Dependencies |
| CWE-1321 | Prototype Pollution | Prototype Pollution |
| CWE-1357 | Untrustworthy Component | Dependencies |

---

## Appendix C: Tool Implementation Notes

### Priority for Static Analysis Implementation

**Phase 1 -- Critical (implement first):**
- XSS: `dangerouslySetInnerHTML`, `innerHTML`, `eval()`, `new Function()`
- Command Injection: `child_process` exec-family with string concatenation
- SQL Injection: String concatenation in `.query()` calls
- Hardcoded secrets: API keys, private keys, tokens
- Prototype pollution: `__proto__` access

**Phase 2 -- High:**
- SSRF: `fetch`/`axios` with user-controlled URLs in SSR
- Path Traversal: `fs.*` with user input
- JWT: `jwt.decode` used as `jwt.verify`, `localStorage` token storage
- Open Redirects: `res.redirect` with user input
- CORS: Wildcard origin with credentials

**Phase 3 -- Medium:**
- React: Missing `useEffect` cleanup, ref-based DOM manipulation
- Next.js: API routes without auth, data over-fetching in SSR props
- Dependencies: Unpinned versions, known vulnerable packages
- Server Actions: Missing validation, mass assignment

### False Positive Reduction Strategies

1. **Context awareness**: Check if the flagged pattern is in a test file, comment, or documentation
2. **Sanitization detection**: Look for DOMPurify, xss, sanitize-html, escape-html near flagged code
3. **Parameterization detection**: For SQL, check for `?` placeholders or named parameters
4. **Validation detection**: Look for Zod, Joi, Yup, or manual validation before flagged operations
5. **Framework safeguards**: React's default JSX escaping, Next.js built-in CSRF protection
6. **File path context**: Distinguish between server-only files and client-bundled code
7. **Import context**: Check if the flagged pattern uses imports from security libraries

### Severity Classification Guide

- **Critical**: Direct RCE, authentication bypass, data exfiltration (eval with user input, command injection, SQL injection, hardcoded production secrets)
- **High**: XSS, SSRF, path traversal, prototype pollution, JWT misconfiguration, open redirects
- **Medium**: CORS misconfiguration, missing auth on non-sensitive routes, client-side token storage, missing cleanup, dependency risks
- **Low**: Informational findings, potential issues that require additional context, coding style concerns
