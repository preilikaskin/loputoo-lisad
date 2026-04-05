# Code Review Verification — All 101 Manual Findings

## Context

This is part of a TalTech bachelor's thesis comparing security testing methods on OWASP Juice Shop v19.1.1.

An exploit verification script (`exploit_tests.py`) contains 101 pre-written code-review verdicts that need **independent verification against actual source code**. Your task is to read the real source code and confirm or correct each verdict.

## Source Code Location

- **Juice Shop repo**: `/Users/kaisaliiv/Desktop/juice-shop-test-2026`
- **Primary code**: `routes/`, `lib/`, `models/`, `server.ts`, `config/`, `data/`, `frontend/src/`
- **Do NOT read**: `test/`, `spec/`, `e2e/`, `node_modules/`
- **Docker container**: running as `juice-shop` on `http://localhost:3000`

## Rules

1. For EACH finding below, **read the actual source file** and verify the claim
2. For SCA findings (marked `[SCA]`), check `package.json` or `package-lock.json` for the actual version
3. Classify: **TP** (vulnerability exists in source), **FP** (claim is wrong or not exploitable), **Info** (exists but informational only)
4. Provide the **exact file path and line number(s)** where you verified
5. Write a 1-sentence evidence statement — what you actually saw in the code
6. If you DISAGREE with the original verdict, explain why

## Output

Write results to: `/Users/kaisaliiv/Desktop/Lõputöö/loputoo-lisad/lisa12-cross-validation/code-review-verification.md`

### Format

```
| # | VID  | Original | Your Verdict | Agree? | File:Line | Evidence |
|---|------|----------|--------------|--------|-----------|----------|
| 1 | V003 | TP       | TP           | Yes    | server.ts:42 | No CSP header set in helmet config |
```

### Summary statistics

- Agreement rate: X/101 (Y%)
- Disagreements: list of VIDs
- Uncertain: findings needing runtime testing

---

## Findings to Verify (101 total: 93 TP, 8 FP)

### Code-Review Findings (91)

| #  | VID  | Verdict | Description |
|----|------|---------|-------------|
| 1  | V003 | TP  | CSP header not set — confirmed no Content-Security-Policy in responses |
| 2  | V005 | TP  | Docker --unsafe-perm — npm lifecycle scripts can run as root |
| 3  | V006 | TP  | Docker images not pinned by digest — supply-chain risk |
| 4  | V011 | TP  | CTF HMAC key stored in plaintext |
| 5  | V012 | TP  | Security answer logged in datacreator.ts |
| 6  | V013 | TP  | Plaintext passwords in users.yml |
| 7  | V014 | TP  | Base64-encoded password in users.yml is trivially recoverable |
| 8  | V015 | TP  | Weak password 'demo' present in challenge data |
| 9  | V016 | TP  | Hardcoded admin/user passwords in users.yml |
| 10 | V017 | TP  | No integrity check on deserialized data |
| 11 | V021 | FP  | continueCode is challenge progress only, not sensitive security data |
| 12 | V022 | TP  | Auth token stored in localStorage |
| 13 | V023 | FP  | Email in query string is not by itself an injection vulnerability |
| 14 | V024 | TP  | 2FA token in localStorage |
| 15 | V026 | TP  | About page uses bypassSecurityTrustHtml — manual DOM-XSS sink |
| 16 | V028 | TP  | Administration component renders user-controlled data unsafely |
| 17 | V031 | TP  | Raw error displayed in change-password component |
| 18 | V032 | FP  | Client-side password policy alone is not a vulnerability |
| 19 | V033 | TP  | Token cookie lacks strong security attributes |
| 20 | V034 | TP  | Auth token in localStorage is script-accessible |
| 21 | V037 | TP  | Unsanitized content in data-export rendering path |
| 22 | V042 | FP  | Theme CSS class is config-controlled, not user-controlled |
| 23 | V045 | TP  | Access token in localStorage |
| 24 | V047 | TP  | Private key field rendered as type=text |
| 25 | V049 | TP  | Token persisted in localStorage |
| 26 | V053 | TP  | Token persisted in localStorage |
| 27 | V059 | TP  | Search component uses bypassSecurityTrustHtml — manual DOM-XSS sink |
| 28 | V060 | TP  | Search term rendered through unsafe Angular trust bypass |
| 29 | V063 | TP  | Token persisted in localStorage |
| 30 | V064 | TP  | TOTP secret exposed in DOM attribute |
| 31 | V067 | TP  | Solidity compiler loaded from mutable URL |
| 32 | V075 | TP  | GitHub workflow uses mutable branch ref |
| 33 | V076 | TP  | Workflow downloads unpinned wget |
| 34 | V077 | TP  | Tag name injection risk in sed command |
| 35 | V078 | TP  | Workflow pushes to master without strict permissions |
| 36 | V079 | TP  | Unpinned npm install in CI |
| 37 | V084 | FP  | Double sanitization path does not create an exploitable issue here |
| 38 | V086 | TP  | Cookie lacks httpOnly/secure/sameSite hardening |
| 39 | V087 | TP  | Hardcoded JWT/RSA material in source |
| 40 | V088 | TP  | MD5 used for password hashing |
| 41 | V089 | TP  | RSA private key committed in source |
| 42 | V090 | TP  | Cookie integrity weakness same class as missing secure attributes |
| 43 | V092 | TP  | Cookie without recommended security attributes |
| 44 | V093 | TP  | Hardcoded JWT secret in source |
| 45 | V095 | TP  | URL logging may leak sensitive values |
| 46 | V096 | FP  | isGitpod false is environment logic, not a security defect |
| 47 | V097 | TP  | No validation on basket item quantity |
| 48 | V098 | TP  | Card number stored as INTEGER exceeds JS safe integer semantics |
| 49 | V100 | TP  | MD5 hashing without salt |
| 50 | V105 | TP  | Mutable GitHub source in package.json |
| 51 | V109 | TP  | B2B order code path contains vm.runInContext sink |
| 52 | V114 | FP  | CAPTCHA eval path has no attacker-controlled input to the sink |
| 53 | V117 | TP  | User data embedded into HTML in chatbot.ts |
| 54 | V118 | TP  | Config-controlled URL fetch in chatbot could enable SSRF if config is attacker-controlled |
| 55 | V121 | TP  | Data export/order flow has userId trust discrepancy |
| 56 | V127 | TP  | XML parsing errors reflected to users |
| 57 | V128 | TP  | ZIP extraction logic lacks strong path validation |
| 58 | V129 | TP  | File type check is non-blocking |
| 59 | V130 | TP  | Unsafe js-yaml.load usage in source |
| 60 | V131 | TP  | File upload XML parser/source path permits XXE-relevant handling |
| 61 | V132 | TP  | Unsafe js-yaml.load usage in source |
| 62 | V136 | TP  | Backslash bypass exists in logfileServer validation logic |
| 63 | V139 | TP  | Login lacks security-event logging |
| 64 | V142 | TP  | Per-request provider creation can leak resources |
| 65 | V143 | TP  | Alchemy API key hardcoded in nftMint.ts |
| 66 | V148 | TP  | profileImageUrlUpload accepts arbitrary external URLs in source |
| 67 | V149 | TP  | Quarantine sendFile path handling is weak in source |
| 68 | V153 | TP  | Password reset attempts not logged |
| 69 | V154 | TP  | Hardcoded salts present |
| 70 | V155 | TP  | saveLoginIp stores unsanitized header-derived IP value |
| 71 | V158 | TP  | Review update path uses unsafe Mongo-style operator handling |
| 72 | V159 | TP  | Review update path allows operator injection patterns |
| 73 | V160 | TP  | trackOrder frontend sink renders attacker-influenced content unsafely |
| 74 | V163 | TP  | Review update path accepts unsafe _id/operator structure |
| 75 | V164 | TP  | Cookie without strong security attributes in profile update flow |
| 76 | V165 | TP  | userProfile.ts contains eval-like template execution sink |
| 77 | V166 | TP  | userProfile.ts contains eval-like template execution sink |
| 78 | V168 | TP  | Unhandled async throw path can crash flow |
| 79 | V170 | TP  | Wallet balance logic trusts client-controlled update flow |
| 80 | V171 | TP  | Wallet credit manipulation risk present in source |
| 81 | V172 | TP  | Wallet logic trusts client-supplied amount semantics |
| 82 | V173 | TP  | Web3 wallet code contains same hardcoded API key |
| 83 | V174 | FP  | Field naming issue is not a security vulnerability |
| 84 | V177 | TP  | errorhandler() used in production path |
| 85 | V178 | TP  | Missing uncaughtException handling may enable DoS |
| 86 | V180 | TP  | Permissive CORS configured in source |
| 87 | V182 | TP  | Weak cookie secret 'kekse' |
| 88 | V185 | TP  | Rate limit can be bypassed with spoofable forwarding header logic |
| 89 | V188 | TP  | Permissive CORS confirmed in configuration/source |
| 90 | V190 | TP  | Unpinned Docker image in Vagrant |
| 91 | V192 | TP  | Unquoted template attribute placeholder |

### SCA Findings (10)

| #  | VID  | Verdict | Description |
|----|------|---------|-------------|
| 92 | V018 | TP  | [SCA] express-jwt 0.1.3 present — vulnerable version |
| 93 | V020 | TP  | [SCA] socket.io-client 3.1.0 transitively exposes vulnerable parser version |
| 94 | V071 | TP  | [SCA] jQuery 2.2.4 present — vulnerable version |
| 95 | V080 | TP  | [SCA] jsonwebtoken 0.4.0 present — vulnerable version |
| 96 | V081 | TP  | [SCA] jsonwebtoken 0.4.0 vulnerable to historical algorithm confusion issues |
| 97 | V082 | TP  | [SCA] jsonwebtoken 0.4.0 legacy algorithm handling issue applies |
| 98 | V083 | TP  | [SCA] jsonwebtoken 0.4.0 missing algorithm enforcement issue applies |
| 99 | V103 | TP  | [SCA] notevil dependency present — vulnerable version family |
| 100| V104 | TP  | [SCA] sanitize-html 1.4.2 present — vulnerable version family |
| 101| V194 | TP  | [SCA] unzipper 0.9.15 present — outdated version family |
