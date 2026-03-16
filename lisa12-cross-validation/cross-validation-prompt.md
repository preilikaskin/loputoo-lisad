# Cross-Validation Request: Security Finding Classification

## Context

This is part of a bachelor's thesis at TalTech comparing four security testing methods
(DAST, SAST, SCA, AI) on OWASP Juice Shop v19.1.1.

The findings below were classified as True Positive (TP), False Positive (FP), or Info
by a first AI model (Claude Opus 4) based on source code review only (no runtime testing).
Your task is to **independently verify each classification** by examining the actual
source code at the referenced locations.

## Source Code Location

The Juice Shop v19.1.1 source code is available locally:

- **Local path**: `/Users/kaisaliiv/Desktop/juice-shop-test-2026`
- **Primary code directories**: `routes/`, `lib/`, `models/`, `server.ts`, `config/`, `data/`, `frontend/src/`
- **Ignore**: `test/`, `spec/`, `e2e/`, `node_modules/` (out of scope)
- **Docker container**: running as `juice-shop` on `http://localhost:3000` (if you need to check runtime behavior)
- **GitHub mirror**: https://github.com/juice-shop/juice-shop (tag v19.1.1)

All file paths in the findings below are **relative to the repo root** (`/Users/kaisaliiv/Desktop/juice-shop-test-2026/`).
For example, `routes/login.ts:34` means `/Users/kaisaliiv/Desktop/juice-shop-test-2026/routes/login.ts`, line 34.

## Instructions

For each finding below:
1. **Read the actual source code** at the referenced file and line number
2. Determine if the described vulnerability **actually exists** at that location
3. Classify as: **TP** (real vulnerability), **FP** (not a real vulnerability), or **Info** (informational, not exploitable)
4. If you **DISAGREE** with the original classification, explain why

## Output Format

Write your results to: `/Users/kaisaliiv/Desktop/Lõputöö/ai-prompts/results/cross-validation-results.md`

Use this format:

### Summary table
| VID | Original | Your Verdict | Agree? | Reasoning (if disagree) |

### Statistics
- Agreement rate: X/75 (Y%)
- Disagreements: list of VIDs with brief explanation
- Uncertain: findings where you'd need runtime testing to be sure

## Target Application

- **Application**: OWASP Juice Shop v19.1.1
- **Note**: This is an intentionally vulnerable application. Vulnerabilities are "by design".
  The question is whether the specific code pattern described constitutes a **real security
  vulnerability** at the stated location — not whether it's intentional.

---

## Findings to Verify (75 total: 67 classified as TP, 8 classified as FP)

### 1. V003 — Original: **TP** | Medium | CWE-693
- **File**: `http://localhost:3000 (+6 more)`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: DAST-ZAP
- **Description**: Content Security Policy (CSP) Header Not Set [Scans: accounting, admin, api, customer, deluxe, passive]
- **Reviewer reasoning**: CSP header not set — confirmed no Content-Security-Policy in response headers

### 2. V005 — Original: **TP** | Medium | CWE-250
- **File**: `Dockerfile:5`
- **OWASP**: A08 – Integrity Failures
- **Found by**: AI-CodeRabbit
- **Description**: `--unsafe-perm` flag forces lifecycle script execution without privilege dropping; builder stage runs in `node:22` (root by default); npm default behavior drops to unprivileged user, but flag bypasses this protection.; A malicious preinstall/postinstall script in any transitive dependency executes with root privileges during build, enabling tampering of built artifacts copied into the final image via `COPY --from=installer`.
- **Reviewer reasoning**: Docker --unsafe-perm — runs npm lifecycle scripts as root

### 3. V006 — Original: **TP** | Medium | CWE-494
- **File**: `Dockerfile:1, 4, 18-19, 22`
- **OWASP**: A08 – Integrity Failures
- **Found by**: AI-CodeRabbit
- **Description**: Base images and tool dependencies use mutable tags/defaults without digest pinning: line 1 uses `node:22`; line 4 installs typescript/ts-node without versions; line 18 defaults CYCLONEDX_NPM_VERSION to `latest`; line 22 uses `gcr.io/distroless/nodejs22-debian12` without digest.; Upstream tag drift or a compromised newly-published package/image can alter build artifacts without any repository diff. Future builds could silently incorporate compromised dependencies.
- **Reviewer reasoning**: Docker images without digest pinning — supply chain risk

### 4. V011 — Original: **TP** | Medium | CWE-540
- **File**: `ctf.key:1`
- **OWASP**: A01 – Broken Access Control
- **Found by**: AI-Claude
- **Description**: CTF HMAC key stored in plaintext file in repository root — allows forging CTF flags
- **Reviewer reasoning**: CTF HMAC key in plaintext — allows forging challenge tokens

### 5. V012 — Original: **TP** | Medium | CWE-532
- **File**: `data/datacreator.ts:633-636`
- **OWASP**: A09 – Logging Failures
- **Found by**: AI-CodeRabbit
- **Description**: Error log string interpolates the full security answer value on insertion failure.; Any principal with log access can recover password-reset secrets and use them for account recovery abuse/account takeover.
- **Reviewer reasoning**: Security answer logged in datacreator.ts

### 6. V013 — Original: **TP** | Medium | CWE-256
- **File**: `data/static/users.yml:1–272`
- **OWASP**: A06 – Insecure Design
- **Found by**: AI-Claude
- **Description**: Plaintext passwords stored in static data file — all user passwords stored in cleartext in repository
- **Reviewer reasoning**: Plaintext passwords in users.yml — intentional challenge data

### 7. V014 — Original: **TP** | Medium | CWE-261
- **File**: `data/static/users.yml:88`
- **OWASP**: A04 – Cryptographic Failures
- **Found by**: AI-Claude
- **Description**: Base64-encoded password used as actual credential: `bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=` — trivially reversible encoding used as password value
- **Reviewer reasoning**: Base64 password in users.yml — trivially decodable

### 8. V015 — Original: **TP** | Medium | CWE-521
- **File**: `data/static/users.yml:213`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-Claude
- **Description**: Weak password: demo user has password `demo`
- **Reviewer reasoning**: Weak password 'demo' — intentional for challenges

### 9. V016 — Original: **TP** | High | CWE-798
- **File**: `data/static/users.yml:3`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-Claude
- **Description**: Hardcoded admin credential: admin account uses weak password `admin123`
- **Reviewer reasoning**: Hardcoded admin/user passwords in users.yml

### 10. V017 — Original: **TP** | Medium | CWE-502
- **File**: `data/staticData.ts:7-11`
- **OWASP**: A08 – Integrity Failures
- **Found by**: AI-CodeRabbit
- **Description**: (1) No integrity verification (no signatures, checksums, or hashes found in codebase); (2) No schema validation framework detected (rg for joi/zod/yup/ajv returned zero matches); (3) TypeScript type casting is compile-time only, provides zero runtime protection; (4) Silent error handling at catch block allows undefined returns.; Seed data files are part of application bootstrap path and drive core functionality (users, challenges, deliveries, security Q&A). Filesystem tampering or supply-chain compromise of these files would corrupt application state. Risk escalates if files are deployed with insufficient access controls or included in external distributions.
- **Reviewer reasoning**: No integrity check on deserialized data

### 11. V021 — Original: **FP** | Medium | CWE-116
- **File**: `frontend/src/app/Services/challenge.service.ts:42-52`
- **OWASP**: A05 – Injection
- **Found by**: AI-CodeRabbit
- **Description**: Line 43, Line 47, and Line 51 append raw `continueCode` into endpoint path without encoding.; Special characters (`/`, `?`, `#`, `%`) can alter request path/query semantics and hit unintended endpoints or bypass expected client-side request structure.
- **Reviewer reasoning**: continueCode is not sensitive — challenge progress only

### 12. V022 — Original: **TP** | Medium | CWE-922
- **File**: `frontend/src/app/Services/request.interceptor.ts:13-18`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-CodeRabbit
- **Description**: Token read from localStorage (Line 13, 16) which is accessible to any JavaScript executing on the page; If XSS exists anywhere in the application, attacker scripts can read localStorage and exfiltrate the Bearer token
- **Reviewer reasoning**: Auth token in localStorage — XSS-accessible

### 13. V023 — Original: **FP** | Medium | CWE-74
- **File**: `frontend/src/app/Services/security-question.service.ts:25`
- **OWASP**: A05 – Injection
- **Found by**: AI-CodeRabbit
- **Description**: Raw string concatenation of `email` into query string at Line 25 without encoding/parameterization.; An attacker-controlled value (e.g., including `&`/`#`) can alter request semantics (HTTP parameter pollution), potentially changing backend behavior and enabling account-enumeration or logic abuse paths.
- **Reviewer reasoning**: Email in query string — not injection-sensitive

### 14. V024 — Original: **TP** | Medium | CWE-922
- **File**: `frontend/src/app/Services/two-factor-auth-service.ts:38`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-CodeRabbit
- **Description**: `verify()` reads a login-step token from `localStorage`, which is accessible to any script in origin context.; If an attacker achieves script execution (e.g., XSS), they can exfiltrate `totp_tmp_token` and attempt takeover of the in-progress authentication step.
- **Reviewer reasoning**: 2FA token in localStorage

### 15. V026 — Original: **TP** | High | CWE-79
- **File**: `frontend/src/app/about/about.component.ts:116-126`
- **OWASP**: A05 – Injection
- **Found by**: AI-CodeRabbit
- **Description**: User comment interpolated into HTML template string (line 116-118), then explicitly passed through `bypassSecurityTrustHtml()` (line 119-120) which disables Angular's default HTML sanitization.; High. Any user-supplied feedback containing malicious HTML/JavaScript will execute in the browser. The `bypassSecurityTrustHtml()` call explicitly tells Angular not to sanitize, making this exploitable for stored XSS attacks against other users viewing the About page.
- **Reviewer reasoning**: About page uses bypassSecurityTrustHtml — DOM XSS vector confirmed in source

### 16. V028 — Original: **TP** | High | CWE-79
- **File**: `frontend/src/app/administration/administration.component.ts:60-61,78-79`
- **OWASP**: A05 – Injection
- **Found by**: AI-CodeRabbit
- **Description**: Line 60 and Line 78 explicitly bypass Angular sanitization for untrusted backend-controlled fields before UI rendering.; A malicious value stored in email/comment can execute script when this admin view (or feedback details dialog) renders it, enabling session/token theft or privileged action abuse in browser context.
- **Reviewer reasoning**: User registration accepted HTML in email — renders as XSS in admin panel

### 17. V031 — Original: **TP** | Medium | CWE-532, CWE-209
- **File**: `frontend/src/app/change-password/change-password.component.ts:119-120, template line 48`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: Production code unconditionally logs raw error object and stores it without sanitization. Template displays raw error via `{{ error }}` binding. No error transformation or redaction layer exists.; Backend errors typically contain sensitive details (stack traces, database errors, API structures). Error is visible in DevTools (accessible to any user with browser dev tools) and rendered in DOM (visible to user). An attacker or curious user can inspect detailed backend failures.
- **Reviewer reasoning**: Raw error displayed in change-password component

### 18. V032 — Original: **FP** | Medium | CWE-602
- **File**: `frontend/src/app/change-password/change-password.component.ts:88-98`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-CodeRabbit
- **Description**: Client-side check for privileged accounts (support@*) with stricter password policy only logs a warning but does not prevent form submission; Attacker controlling a support account can bypass the 12-character complexity requirement since enforcement is client-side only and merely logs a warning without blocking
- **Reviewer reasoning**: Client-side password policy — intentional UX

### 19. V033 — Original: **TP** | Medium | CWE-614
- **File**: `frontend/src/app/chatbot/chatbot.component.ts:98-100`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: Token cookie created client-side with only expiration configured; no `Secure`, `HttpOnly`, or `SameSite` attributes passed to cookieService.put(). Token also stored in localStorage (line 97), compounding exposure.; Client-side cookies cannot be marked `HttpOnly`. Lack of `Secure` flag enables interception over insecure transport; missing `SameSite` permits CSRF token exfiltration. This is intentional training content in OWASP Juice Shop.
- **Reviewer reasoning**: Token cookie without security attributes

### 20. V034 — Original: **TP** | High | CWE-922
- **File**: `frontend/src/app/chatbot/chatbot.component.ts:96-97`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-CodeRabbit
- **Description**: Auth token persisted in JS-accessible localStorage; pattern confirmed systemic across payment.component.ts:232 and oauth.component.ts:51; token actively retrieved via localStorage.getItem() in last-login-ip.component.ts:34 and complaint.component.ts:44.; Any XSS on origin can access localStorage and exfiltrate token for account hijacking.
- **Reviewer reasoning**: Auth token in localStorage — script-accessible

### 21. V037 — Original: **TP** | High | CWE-79
- **File**: `frontend/src/app/data-export/data-export.component.ts:57`
- **OWASP**: A05 – Injection
- **Found by**: AI-CodeRabbit
- **Description**: `getNewCaptcha()` explicitly bypasses Angular HTML sanitization for server-provided captcha markup.; A tampered/compromised captcha response can inject active HTML/JS and execute in the browser context.
- **Reviewer reasoning**: Unsanitized content in data-export

### 22. V042 — Original: **FP** | Low | CWE-79
- **File**: `frontend/src/app/faucet/faucet.module.ts:46`
- **OWASP**: A05 – Injection
- **Found by**: AI-CodeRabbit
- **Description**: `classList.add(conf.application.theme + '-theme')` concatenates config value into CSS class; Very low - requires backend configuration compromise; impact limited to CSS class injection (not script execution)
- **Reviewer reasoning**: Theme CSS class from config — not user-controlled

### 23. V044 — Original: **TP** | High | CWE-79
- **File**: `frontend/src/app/last-login-ip/last-login-ip.component.ts:39`
- **OWASP**: A05 – Injection
- **Found by**: AI-Claude, AI-CodeRabbit
- **Description**: DOM XSS: `bypassSecurityTrustHtml` on `lastLoginIp` — renders attacker-controlled IP header value as HTML
- **Reviewer reasoning**: Login stores True-Client-IP header — XSS when lastLoginIp rendered

### 24. V045 — Original: **TP** | High | CWE-922
- **File**: `frontend/src/app/login/login.component.ts:101-104,112-113,127-127`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-CodeRabbit
- **Description**: Access token and temporary 2FA token are persisted in localStorage; token cookie is created from JavaScript (cannot be HttpOnly).; Any successful XSS or compromised same-origin script can exfiltrate these values and hijack authenticated sessions / interfere with MFA flow.
- **Reviewer reasoning**: Access token in localStorage

### 25. V047 — Original: **TP** | Medium | CWE-522
- **File**: `frontend/src/app/nft-unlock/nft-unlock.component.html:50-57`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-CodeRabbit
- **Description**: Line 56 sets the private key field to `type="text"` in the authentication form.; Secret input is visibly exposed and easier to capture (shoulder-surfing/screen recording/browser tooling), weakening credential protection.
- **Reviewer reasoning**: Private key field as type=text — visible on screen

### 26. V049 — Original: **TP** | Medium | CWE-922
- **File**: `frontend/src/app/oauth/oauth.component.ts:50-52`
- **OWASP**: A04 – Cryptographic Failures
- **Found by**: AI-CodeRabbit
- **Description**: Access token is persisted in `localStorage`, which is readable by any script executing in the origin.; Any XSS or compromised third-party script can exfiltrate bearer tokens from `localStorage`, enabling session hijack.
- **Reviewer reasoning**: Token in localStorage

### 27. V053 — Original: **TP** | High | CWE-922
- **File**: `frontend/src/app/payment/payment.component.ts:232-233`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-CodeRabbit
- **Description**: Line 232-233 stores auth token in storage mechanisms accessible to any script running on the origin.; Any successful XSS or compromised third-party script can read/exfiltrate the token and hijack authenticated sessions.
- **Reviewer reasoning**: Token in localStorage

### 28. V055 — Original: **FP** | Low | CWE-754
- **File**: `frontend/src/app/product-review-edit/product-review-edit.component.ts:56`
- **OWASP**: A06 – Insecure Design
- **Found by**: AI-CodeRabbit
- **Description**: Line 56 executes outside subscribe callbacks, before API response is received; Could mislead users into believing changes were saved when they failed; no direct exploitation path
- **Reviewer reasoning**: Snackbar before API response — UX issue only

### 29. V059 — Original: **TP** | High | CWE-79
- **File**: `frontend/src/app/search-result/search-result.component.html:13`
- **OWASP**: A05 – Injection
- **Found by**: AI-CodeRabbit
- **Description**: Line 171 of search-result.component.ts explicitly marks user-controlled `queryParam` with `this.sanitizer.bypassSecurityTrustHtml(queryParam)`, which is then bound to `[innerHTML]` on line 13 of the template, disabling Angular's built-in content sanitization.; Any XSS payload in the `q` query parameter will execute in the DOM. User-controlled input flows directly to the HTML sink without sanitization, allowing script injection (e.g., `?q=<img src=x onerror='alert(1)'>`).
- **Reviewer reasoning**: Search API active — DOM XSS via bypassSecurityTrustHtml confirmed in source

### 30. V060 — Original: **TP** | High | CWE-79
- **File**: `frontend/src/app/search-result/search-result.component.ts:145`
- **OWASP**: A05 – Injection
- **Found by**: AI-Claude, AI-CodeRabbit
- **Description**: DOM XSS: `bypassSecurityTrustHtml()` on product description — disables Angular's built-in XSS protection, rendering unsanitized HTML from API
- **Reviewer reasoning**: Same search endpoint — frontend renders unsanitized search term

### 31. V063 — Original: **TP** | High | CWE-922
- **File**: `frontend/src/app/two-factor-auth-enter/two-factor-auth-enter.component.ts:53, 56`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-CodeRabbit
- **Description**: Production code stores authentication token in localStorage (line 53) and a JS-set cookie (line 56) after successful 2FA verification. The spec tests at lines 100-112 verify this behavior.; Any XSS vulnerability in the origin can directly steal the token from `localStorage` without HttpOnly protection, enabling session hijacking and account takeover. The token has an 8-hour validity window (lines 54–55), increasing the window of exposure.
- **Reviewer reasoning**: Token in localStorage

### 32. V064 — Original: **TP** | Medium | CWE-200
- **File**: `frontend/src/app/two-factor-auth/two-factor-auth.component.html:Line [74]`
- **OWASP**: A04 – Cryptographic Failures
- **Found by**: AI-CodeRabbit
- **Description**: Line [74] binds the raw TOTP secret into `data-test-totp-secret`, exposing it to DOM reads.; Any in-page script, browser extension, or leaked DOM snapshot can exfiltrate the secret and generate valid OTPs until secret rotation.
- **Reviewer reasoning**: TOTP secret exposed in DOM attribute

### 33. V067 — Original: **TP** | Medium | CWE-494
- **File**: `frontend/src/app/web3-sandbox/web3-sandbox.component.ts:100`
- **OWASP**: A08 – Integrity Failures
- **Found by**: AI-CodeRabbit
- **Description**: The compiler artifact URL is constructed at runtime (`https://binaries.soliditylang.org/bin/${selectedVersion}`) and passed directly to `solidityCompiler()`. The `solidity-browser-compiler` library uses `importScripts()` to load the URL in a Web Worker with no built-in integrity verification. Although `binaries.soliditylang.org` publishes SHA-256 and Keccak-256 hashes for binaries in `list.json`, the library and this application code do not validate them.; If the remote compiler supply chain is compromised (CDN/domain hijacking, MITM), users download and execute malicious or altered compiler, producing compromised bytecode for deployment to the blockchain.
- **Reviewer reasoning**: Solidity compiler from mutable URL — supply chain risk

### 34. V075 — Original: **TP** | Medium | CWE-494
- **File**: `.github/workflows/update-challenges-ebook.yml:24`
- **OWASP**: A08 – Integrity Failures
- **Found by**: AI-CodeRabbit
- **Description**: Workflow fetches from a mutable branch ref (`github.ref_name`) instead of immutable triggering commit SHA.; Content can change between event trigger and fetch time, allowing unintended data to be committed into the companion repository (TOCTOU integrity gap).
- **Reviewer reasoning**: GitHub workflow uses mutable branch ref

### 35. V076 — Original: **TP** | Medium | CWE-494
- **File**: `.github/workflows/update-challenges-www.yml:24-29`
- **OWASP**: A08 – Integrity Failures
- **Found by**: AI-CodeRabbit
- **Description**: Line 24 uses `wget https://raw.githubusercontent.com/juice-shop/juice-shop/master/...`; Lines 25-29 immediately commit to `master` without pinning or integrity verification.; A compromised or malicious upstream change can be propagated cross-repository automatically without human verification.
- **Reviewer reasoning**: Unpinned wget in workflow

### 36. V077 — Original: **TP** | Major | CWE-77
- **File**: `.github/workflows/update-news-www.yml:19`
- **OWASP**: A05 – Injection
- **Found by**: AI-CodeRabbit
- **Description**: Tag names can contain forward slashes (valid per Git ref rules), which break sed's `/` delimiter syntax. Additionally, special characters like `&` in tag names are interpreted as sed metacharacters (representing matched text), corrupting the file output. Testing confirms: tag `v1.0/beta` causes sed exit code 1; tag `v1.0&other` produces malformed output with the marker text incorrectly expanded.; Any release author can trigger this workflow. A tag containing `/` causes step failure; a tag containing `&` silently corrupts the news file. Requires repository maintainer involvement (not external attacker).
- **Reviewer reasoning**: Tag name injection in sed command

### 37. V078 — Original: **TP** | Medium | CWE-732
- **File**: `.github/workflows/webpack-analysis.yml:1-1,12-15,57-65`
- **OWASP**: A08 – Integrity Failures
- **Found by**: AI-CodeRabbit
- **Description**: Workflow performs direct push to `master` (Lines 61-65) and does not define explicit `permissions:` constraints in the workflow/job scope.; If token has write scope, any compromised prior step can persist changes to a protected branch path, weakening CI/CD change-control integrity.
- **Reviewer reasoning**: Workflow pushes to master without permissions

### 38. V079 — Original: **TP** | High | CWE-494
- **File**: `.github/workflows/webpack-analysis.yml Lines: 29, 38`
- **OWASP**: A08 – Integrity Failures
- **Found by**: AI-CodeRabbit
- **Description**: Line 29 executes `npm install webpack-bundle-analyzer` and line 38 executes `npm install playwright` without version pinning and without `--ignore-scripts` protection. These unpinned installs can execute arbitrary package lifecycle scripts during installation in the CI environment. Risk: A compromised or typosquatted package release can execute arbitrary code with access to GitHub Actions secrets, workflow tokens, and repository contents.
- **Reviewer reasoning**: Unpinned npm install in CI

### 39. V084 — Original: **FP** | Medium | CWE-79
- **File**: `lib/challengeUtils.ts:52`
- **OWASP**: A05 – Injection
- **Found by**: AI-CodeRabbit
- **Description**: `entities.decode(sanitizeHtml(challenge.description, { allowedTags: [], allowedAttributes: {} }))` — decode is applied AFTER sanitization; If `challenge.description` contains HTML-encoded tags like `&lt;script&gt;alert(1)&lt;/script&gt;`, `sanitizeHtml` passes them through (they're not actual tags), then `entities.decode` converts them to `<script>alert(1)</script>`. This string is broadcast to WebSocket clients and could execute if rendered unsafely.
- **Reviewer reasoning**: Double sanitization — entities.decode after sanitizeHtml is safe

### 40. V086 — Original: **TP** | Medium | CWE-1275
- **File**: `lib/insecurity.ts:195`
- **OWASP**: A01 – Broken Access Control
- **Found by**: AI-Claude
- **Description**: Token cookie set without `httpOnly`, `secure`, or `sameSite` attributes — `res.cookie('token', token)` uses no security options
- **Reviewer reasoning**: Token cookie without httpOnly/secure/sameSite

### 41. V090 — Original: **TP** | Medium | CWE-565
- **File**: `lib/insecurity.ts:195`
- **OWASP**: A08 – Integrity Failures
- **Found by**: AI-Claude
- **Description**: A01 repeat (#10): Token cookie set without signed/httpOnly/secure attributes — no integrity verification
- **Reviewer reasoning**: Token cookie integrity — same as V086

### 42. V092 — Original: **TP** | Medium | CWE-614
- **File**: `lib/insecurity.ts:189-196`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-CodeRabbit
- **Description**: Cookie is set without explicit `httpOnly`, `secure`, or `sameSite` controls.; Token can be exposed to client-side scripts and cross-site request contexts, increasing session theft/fixation risk.
- **Reviewer reasoning**: Cookie without security attributes

### 43. V095 — Original: **TP** | Medium | CWE-532
- **File**: `lib/utils.ts:126`
- **OWASP**: A09 – Logging Failures
- **Found by**: AI-CodeRabbit
- **Description**: Full URL is logged verbatim on error.; Secrets embedded in URL userinfo/query can be exposed to log readers and log aggregation systems.
- **Reviewer reasoning**: URL logged with potential secrets

### 44. V096 — Original: **FP** | Medium | CWE-693
- **File**: `lib/utils.ts:22-24`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: `isGitpod` is hardcoded to `false`, so `disabledEnv` checks for `Gitpod` never trigger.; In `safetyMode='auto'`, challenges intended to be disabled on Gitpod can remain enabled.
- **Reviewer reasoning**: isGitpod false — intentional environment check

### 45. V097 — Original: **TP** | Medium | CWE-20
- **File**: `models/basketitem.ts:40`
- **OWASP**: A06 – Insecure Design
- **Found by**: AI-CodeRabbit
- **Description**: `quantity` field defined as bare `DataTypes.INTEGER` with zero validators. Sequelize codebase elsewhere uses `validate: { min: X }` patterns (card.ts, address.ts, hint.ts) establishing local convention.; Attackers can submit negative or zero quantities in basket requests; if upstream controllers do not enforce bounds, ORM will persist invalid values, causing inventory miscalculation or negative order totals.
- **Reviewer reasoning**: No validation on basket item quantity

### 46. V098 — Original: **TP** | Medium | CWE-681
- **File**: `models/card.ts:39–45`
- **OWASP**: A08 – Integrity Failures
- **Found by**: AI-CodeRabbit
- **Description**: Validation bound `9999999999999998` exceeds `Number.MAX_SAFE_INTEGER` (`9007199254740991`). 16-digit card numbers stored as JS numbers will lose precision in calculations and comparisons.; Distinct PANs can silently collapse to the same rounded integer, breaking lookup, audit trails, and transaction matching logic.
- **Reviewer reasoning**: Card number as INTEGER exceeds MAX_SAFE_INTEGER

### 47. V099 — Original: **TP** | High | CWE-79
- **File**: `models/feedback.ts:44–46`
- **OWASP**: A05 – Injection
- **Found by**: AI-Claude
- **Description**: Stored XSS: `sanitizeHtml()` allows certain tags through — `<iframe src="javascript:alert('xss')">` passes the default allowlist
- **Reviewer reasoning**: Feedback API accepted XSS payload — sanitizeHtml bypass confirmed in source

### 48. V101 — Original: **TP** | High | CWE-79
- **File**: `models/user.ts:49–51`
- **OWASP**: A05 – Injection
- **Found by**: AI-Claude
- **Description**: Stored XSS: `sanitizeLegacy()` uses incomplete regex `/<(?:\w+)\W+?[\w]/gi` which can be bypassed with payloads like `<iframe src="javascript:alert('xss')">`
- **Reviewer reasoning**: Registration accepted HTML in securityAnswer — sanitizeLegacy bypass in source

### 49. V105 — Original: **TP** | Medium | CWE-829
- **File**: `package.json:250`
- **OWASP**: A08 – Integrity Failures
- **Found by**: AI-CodeRabbit
- **Description**: Line 250 specifies mutable GitHub source without commit SHA; repository contains no lockfiles to provide immutable resolution.; Upstream repo compromise or ref mutation can inject unreviewed code into CI/test runs at install time.
- **Reviewer reasoning**: Mutable GitHub source in package.json

### 50. V117 — Original: **TP** | Medium | CWE-79
- **File**: `routes/chatbot.ts:197`
- **OWASP**: A05 – Injection
- **Found by**: SAST-Semgrep
- **Description**: raw-html-format: User data flows into the host portion of this manually-constructed HTML. This can introduce a Cross-Site-Scripting (XSS) vulnerability if this comes f
- **Reviewer reasoning**: User data in HTML format string in chatbot.ts

### 51. V118 — Original: **TP** | Medium | CWE-918
- **File**: `routes/chatbot.ts:28-31`
- **OWASP**: A10 – Exceptional Conditions
- **Found by**: AI-CodeRabbit
- **Description**: If trainingData config contains a URL, it is fetched via download() and written to disk. Config-based URL reduces direct exploitation but allows SSRF if config is attacker-influenced; Limited - requires ability to modify application config; could probe internal services or exfiltrate data if config is injectable
- **Reviewer reasoning**: Config-controlled URL fetch in chatbot — SSRF if config attacker-controlled

### 52. V125 — Original: **TP** | High | CWE-22
- **File**: `routes/fileServer.ts:28`
- **OWASP**: A01 – Broken Access Control
- **Found by**: AI-Claude
- **Description**: Null byte injection in file server: `cutOffPoisonNullByte()` truncates the filename at `%00`, allowing download of files that don't match the `.md`/`.pdf` allowlist
- **Reviewer reasoning**: FTP directory accessible — null byte bypass for path traversal confirmed in code

### 53. V126 — Original: **TP** | Medium | CWE-73
- **File**: `routes/fileServer.ts:33`
- **OWASP**: A01 – Broken Access Control
- **Found by**: SAST-Semgrep
- **Description**: express-res-sendfile: The application processes user-input, this is passed to res.sendFile which can allow an attacker to arbitrarily read files on the system through path 
- **Reviewer reasoning**: File server serves files from ftp directory — path traversal in code

### 54. V127 — Original: **TP** | Medium | CWE-209
- **File**: `routes/fileUpload.ts:87`
- **OWASP**: A05 – Injection
- **Found by**: AI-Claude
- **Description**: XML parsing errors reflected to user: `'B2B customer complaints via file upload have been deprecated: ' + xmlString` — leaks file contents from XXE
- **Reviewer reasoning**: XML parsing errors reflected to user

### 55. V128 — Original: **TP** | High | CWE-22
- **File**: `routes/fileUpload.ts:42–45`
- **OWASP**: A05 – Injection
- **Found by**: AI-Claude, AI-CodeRabbit
- **Description**: Zip slip: extracted file path constructed as `'uploads/complaints/' + fileName` where `fileName` comes from ZIP entry — can write files outside target directory
- **Reviewer reasoning**: ZIP extraction without path validation confirmed in fileUpload source code

### 56. V129 — Original: **TP** | Medium | CWE-434
- **File**: `routes/fileUpload.ts:67–73`
- **OWASP**: A06 – Insecure Design
- **Found by**: AI-Claude
- **Description**: File upload type check is non-blocking: `checkFileType` only logs challenge solutions but does not reject invalid file types — `next()` is always called
- **Reviewer reasoning**: File type check non-blocking

### 57. V130 — Original: **TP** | High | CWE-502
- **File**: `routes/fileUpload.ts:116`
- **OWASP**: A08 – Integrity Failures
- **Found by**: AI-Claude
- **Description**: A03 repeat (#23): Unsafe YAML deserialization with `yaml.load()` (default schema allows code execution)
- **Reviewer reasoning**: Unsafe js-yaml.load() without safe schema confirmed in source code

### 58. V132 — Original: **TP** | High | CWE-829
- **File**: `routes/fileUpload.ts:116`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: AI-Claude
- **Description**: `yaml.load()` used without safe schema — `js-yaml` default loader can execute arbitrary JavaScript constructors from untrusted YAML input
- **Reviewer reasoning**: Same YAML deserialization — confirmed in source code

### 59. V136 — Original: **TP** | Medium | CWE-22
- **File**: `routes/logfileServer.ts:13-14`
- **OWASP**: A01 – Broken Access Control
- **Found by**: AI-CodeRabbit
- **Description**: Validation only checks for forward slash '/'; backslash '\' bypasses on Windows; On Windows systems, attacker can traverse directories using backslash
- **Reviewer reasoning**: Backslash bypass in logfileServer path validation

### 60. V139 — Original: **TP** | Medium | CWE-778
- **File**: `routes/login.ts:34–55`
- **OWASP**: A09 – Logging Failures
- **Found by**: AI-Claude
- **Description**: Authentication endpoint lacks security event logging — successful and failed login attempts are not logged to a security audit log
- **Reviewer reasoning**: Login missing security event logging

### 61. V142 — Original: **TP** | Medium | CWE-400
- **File**: `routes/nftMint.ts:10-11,14-18,24-25`
- **OWASP**: A06 – Insecure Design
- **Found by**: AI-CodeRabbit
- **Description**: A new provider is created per request at Line 16 even after `isEventListenerCreated` is true; no close/dispose path exists, and `addressesMinted` has no cap/TTL.; Attackers can spam the endpoint to exhaust connection/memory resources and degrade availability.
- **Reviewer reasoning**: Provider leak per request — resource exhaustion

### 62. V143 — Original: **TP** | High | CWE-798
- **File**: `routes/nftMint.ts:16`
- **OWASP**: A04 – Cryptographic Failures
- **Found by**: AI-CodeRabbit
- **Description**: `wss://eth-sepolia.g.alchemy.com/v2/FZDapFZSs1l6yhHW4VnQqsi18qSd-3GJ` is committed in code.; Anyone with code access can reuse/abuse the key (quota drain, billing impact, service disruption).
- **Reviewer reasoning**: Alchemy API key hardcoded in nftMint.ts

### 63. V147 — Original: **TP** | High | CWE-639
- **File**: `routes/payment.ts:21,41,70`
- **OWASP**: A01 – Broken Access Control
- **Found by**: AI-CodeRabbit
- **Description**: All payment-card retrieval/deletion logic trusts `req.body.UserId` instead of a server-authenticated principal.; Attackers can set `UserId` to another user and read or delete that user’s saved payment methods (IDOR/BOLA).
- **Reviewer reasoning**: Cards API trusts UserId from request body — IDOR confirmed in source

### 64. V148 — Original: **TP** | High | CWE-918
- **File**: `routes/profileImageUrlUpload.ts:24`
- **OWASP**: A01 – Broken Access Control
- **Found by**: AI-Claude, AI-CodeRabbit
- **Description**: SSRF: user-controlled `imageUrl` is passed directly to `fetch(url)` for server-side request, enabling access to internal services and local files
- **Reviewer reasoning**: profileImageUrl accepts arbitrary URLs without validation — SSRF vector confirmed in source

### 65. V153 — Original: **TP** | Medium | CWE-778
- **File**: `routes/resetPassword.ts:47`
- **OWASP**: A09 – Logging Failures
- **Found by**: AI-Claude
- **Description**: Failed password reset attempts not logged — wrong security answers produce no audit trail
- **Reviewer reasoning**: Password reset attempts not logged

### 66. V155 — Original: **TP** | Medium | CWE-79
- **File**: `routes/saveLoginIp.ts:18–23`
- **OWASP**: A05 – Injection
- **Found by**: AI-Claude
- **Description**: XSS via HTTP header: `True-Client-IP` header value stored as `lastLoginIp` without sanitization (when challenge is enabled)
- **Reviewer reasoning**: Login accepts True-Client-IP header — stored XSS via saveLoginIp confirmed in source

### 67. V164 — Original: **TP** | Medium | CWE-1004
- **File**: `routes/updateUserProfile.ts:40`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-CodeRabbit
- **Description**: Cookie is set without explicit `httpOnly`, `secure`, or `sameSite` options in this call site. No global middleware or configuration sets these flags.; Session cookie exposure risk under XSS/CSRF-prone conditions. This is intentional training code in OWASP Juice Shop (marked with `challengeUtils.solveIf(challenges.csrfChallenge)`).
- **Reviewer reasoning**: Cookie without security attributes in updateUserProfile

### 68. V173 — Original: **TP** | High | CWE-798
- **File**: `routes/web3Wallet.ts:18`
- **OWASP**: A04 – Cryptographic Failures
- **Found by**: AI-CodeRabbit
- **Description**: Alchemy API key `FZDapFZSs1l6yhHW4VnQqsi18qSd-3GJ` hardcoded in source; API key exposed in repository enables unauthorized use of the Alchemy service, potential billing abuse or rate limit exhaustion
- **Reviewer reasoning**: Same API key in web3Wallet.ts

### 69. V174 — Original: **FP** | Medium | CWE-697
- **File**: `rsn/rsnUtil.ts:131-132`
- **OWASP**: A08 – Integrity Failures
- **Found by**: AI-CodeRabbit
- **Description**: `fileDataValueRemoved` and `dataValueAddedRemoved` are both derived from `.added`, so `.removed` arrays are never actually compared.; A removed-only mutation can evade detection, causing false “no diff” decisions and weakening the lock/check control for security-relevant codefix drift.
- **Reviewer reasoning**: rsnUtil field naming — not a security vuln

### 70. V177 — Original: **TP** | Medium | CWE-209
- **File**: `server.ts:671`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-Claude
- **Description**: `errorhandler()` middleware used without environment check — this development-only error handler exposes full stack traces in production
- **Reviewer reasoning**: errorhandler() in production — verbose errors

### 71. V178 — Original: **TP** | Medium | CWE-248
- **File**: `server.ts:753–754`
- **OWASP**: A10 – Exceptional Conditions
- **Found by**: AI-Claude
- **Description**: Missing `uncaughtException` and `unhandledRejection` handlers — only SIGINT/SIGTERM are handled; unhandled errors will crash the process
- **Reviewer reasoning**: Missing uncaughtException handler — DoS possible

### 72. V182 — Original: **TP** | Medium | CWE-547
- **File**: `server.ts:289`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-Claude
- **Description**: Cookie parser uses hardcoded weak secret `'kekse'` — `cookieParser('kekse')` uses a predictable signing key
- **Reviewer reasoning**: Weak cookie secret 'kekse'

### 73. V185 — Original: **TP** | Medium | CWE-799
- **File**: `server.ts:589`
- **OWASP**: A06 – Insecure Design
- **Found by**: AI-Claude
- **Description**: Missing rate limiting on `/rest/user/login` — no `rateLimit` middleware applied, enabling brute-force attacks
- **Reviewer reasoning**: Rate limit bypass via X-Forwarded-For

### 74. V190 — Original: **TP** | Medium | CWE-494
- **File**: `vagrant/bootstrap.sh:25`
- **OWASP**: A08 – Integrity Failures
- **Found by**: AI-CodeRabbit
- **Description**: Line 25 uses an unpinned image reference (no immutable digest), allowing mutable tag drift.; Future pulls can resolve to different image contents, enabling unintended or malicious code deployment through supply-chain compromise.
- **Reviewer reasoning**: Unpinned Docker image in Vagrant

### 75. V192 — Original: **TP** | Medium | CWE-79
- **File**: `views/dataErasureForm.hbs:21`
- **OWASP**: A05 – Injection
- **Found by**: AI-CodeRabbit
- **Description**: `placeholder={{userEmail}}` lacks quotes around attribute value; If `userEmail` contains spaces or special characters (e.g., `test@x.com onfocus=alert(1) autofocus`), unquoted attribute allows injection of additional HTML attributes; Handlebars escapes HTML entities but not spaces/attribute boundaries
- **Reviewer reasoning**: Unquoted template attribute placeholder

---

## Summary Request

After reviewing all findings, also provide:
1. **Agreement rate**: How many findings do you agree with out of the total?
2. **Disagreements summary**: List of VIDs where you disagree, with brief explanation
3. **Confidence notes**: Any findings where you are uncertain and would need runtime testing to decide
