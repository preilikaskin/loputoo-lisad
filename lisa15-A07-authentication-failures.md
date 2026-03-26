# A07:2025 Authentication Failures — Agent Instructions

## Category
OWASP Top 10:2025 A07 — Authentication Failures (formerly A07:2021 Identification and Authentication Failures)
Covers weak authentication, session management flaws, allowing credential stuffing.

## CWE List
- CWE-255: Credentials Management Errors
- CWE-259: Use of Hard-coded Password
- CWE-287: Improper Authentication
- CWE-288: Authentication Bypass Using an Alternate Path or Channel
- CWE-290: Authentication Bypass by Spoofing
- CWE-294: Authentication Bypass by Capture-replay
- CWE-295: Improper Certificate Validation
- CWE-297: Improper Validation of Certificate with Host Mismatch
- CWE-300: Channel Accessible by Non-Endpoint
- CWE-302: Authentication Bypass by Assumed-Immutable Data
- CWE-304: Missing Critical Step in Authentication
- CWE-306: Missing Authentication for Critical Function
- CWE-307: Improper Restriction of Excessive Authentication Attempts
- CWE-346: Origin Validation Error
- CWE-384: Session Fixation
- CWE-521: Weak Password Requirements
- CWE-613: Insufficient Session Expiration
- CWE-620: Unverified Password Change
- CWE-640: Weak Password Recovery Mechanism for Forgotten Password
- CWE-798: Use of Hard-coded Credentials

## Search Patterns (grep)
### Group 1: Login/authentication (CWE-287, 306, 307, 521)
- `login|Login|authenticate|signIn|sign-in`
- `password|passwd|credential`
- `bcrypt\.compare|compare.*password|verify.*password`
- `brute.*force|lockout|maxAttempts|failedAttempts`

### Group 2: Hardcoded credentials (CWE-259, 798)
- `password.*=.*['"]|admin.*password|default.*password`
- `username.*=.*['"].*password.*=.*['"]`

### Group 3: Session management (CWE-384, 613)
- `session|express-session|cookie-session`
- `regenerate|destroy|invalidate`
- `maxAge|expires|ttl.*session`
- `sessionId|connect\.sid`

### Group 4: Password recovery (CWE-620, 640)
- `reset.*password|forgot.*password|recover`
- `security.*question|answer`
- `token.*reset|reset.*token`

## Output Format
Return a table:
```
| # | File | Line | CWE | Vulnerability description | Severity | TP/FP/Info |
|---|------|------|-----|--------------------------|----------|------------|
| 1 | routes/login.ts | 45 | CWE-307 | Missing brute-force protection on authentication endpoint | High | TP |
```

At the end of the summary, include:
- Total findings: X
- TP: X, FP: X, Info: X  
- High: X, Medium: X, Low: X, Info: X
