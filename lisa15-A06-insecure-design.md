# A06:2025 Insecure Design — Agent Instructions

## Category
OWASP Top 10:2025 A06 — Insecure Design (formerly A04:2021)
Covers design-level deficiencies: missing business risk profiling, missing rate limiting mechanisms, unintended data flows.

## CWE List
- CWE-73: External Control of File Name or Path
- CWE-183: Permissive List of Allowed Inputs
- CWE-209: Generation of Error Message Containing Sensitive Information
- CWE-213: Exposure of Sensitive Information Due to Incompatible Policies
- CWE-235: Improper Handling of Extra Parameters
- CWE-256: Plaintext Storage of a Password
- CWE-257: Storing Passwords in a Recoverable Format
- CWE-266: Incorrect Privilege Assignment
- CWE-269: Improper Privilege Management
- CWE-280: Improper Handling of Insufficient Permissions
- CWE-311: Missing Encryption of Sensitive Data
- CWE-312: Cleartext Storage of Sensitive Information
- CWE-313: Cleartext Storage in a File or on Disk
- CWE-316: Cleartext Storage of Sensitive Information in Memory
- CWE-419: Unprotected Primary Channel
- CWE-430: Deployment of Wrong Handler
- CWE-434: Unrestricted Upload of File with Dangerous Type
- CWE-444: Inconsistent Interpretation of HTTP Requests (HTTP Request/Response Smuggling)
- CWE-451: User Interface (UI) Misrepresentation of Critical Information
- CWE-472: External Control of Assumed-Immutable Web Parameter
- CWE-501: Trust Boundary Violation
- CWE-522: Insufficiently Protected Credentials
- CWE-525: Use of Web Browser Cache Containing Sensitive Information
- CWE-539: Use of Persistent Cookies Containing Sensitive Information
- CWE-579: J2EE Bad Practices: Non-serializable Object Stored in Session
- CWE-598: Use of GET Request Method With Sensitive Query Strings
- CWE-602: Client-Side Enforcement of Server-Side Security
- CWE-642: External Control of Critical State Data
- CWE-646: Reliance on File Name or Extension of Externally-Supplied File
- CWE-650: Trusting HTTP Permission Methods on the Server Side
- CWE-653: Improper Isolation or Compartmentalization
- CWE-656: Reliance on Security Through Obscurity
- CWE-657: Violation of Secure Design Principles
- CWE-799: Improper Control of Interaction Frequency
- CWE-807: Reliance on Untrusted Inputs in a Security Decision
- CWE-840: Business Logic Errors
- CWE-841: Improper Enforcement of Behavioral Workflow
- CWE-927: Use of Implicit Intent for Sensitive Communication

## Search Patterns (grep)
### Group 1: File upload (CWE-434, 73, 646)
- `upload|multer|formidable|busboy`
- `mimetype|file\.type|extension|\.ext`
- `rename|move|mv\(`

### Group 2: Cleartext data (CWE-256, 312, 313, 311, 522)
- `password.*plain|cleartext|unencrypt`
- `writeFile.*password|writeFile.*secret|writeFile.*token`
- `console\.log.*password|console\.log.*token`

### Group 3: Rate limiting / workflow (CWE-799, 840, 841)
- `rate.*limit|rateLimit|express-rate-limit|throttle`
- `captcha|CAPTCHA|recaptcha`
- `retry|attempts|maxAttempts|lockout`

### Group 4: Client-side security (CWE-602, 472, 807)
- `disabled.*server|client.*valid|frontend.*check`
- `hidden.*input|type=.*hidden`
- `role.*client|admin.*frontend`

## Output Format
Return a table:
```
| # | File | Line | CWE | Vulnerability description | Severity | TP/FP/Info |
|---|------|------|-----|--------------------------|----------|------------|
| 1 | routes/login.ts | 67 | CWE-799 | Missing rate limiting on login endpoint | Medium | TP |
```

At the end of the summary, include:
- Total findings: X
- TP: X, FP: X, Info: X  
- High: X, Medium: X, Low: X, Info: X
