# A02:2025 Security Misconfiguration — Agent Instructions

## Category
OWASP Top 10:2025 A02 — Security Misconfiguration
Covers missing security hardening, misconfigured permissions, unnecessary enabled features, default accounts/passwords.

## CWE List
- CWE-2: Environment Configuration (7PK)
- CWE-11: ASP.NET Misconfiguration
- CWE-13: ASP.NET Misconfiguration: Password in Configuration File
- CWE-15: External Control of System or Configuration Setting
- CWE-16: Configuration
- CWE-209: Generation of Error Message Containing Sensitive Information
- CWE-260: Password in Configuration File
- CWE-315: Cleartext Storage of Sensitive Information in a Cookie
- CWE-520: .NET Misconfiguration: Use of Impersonation
- CWE-526: Exposure of Sensitive Information Through Environmental Variables
- CWE-537: Java Runtime Error Message Containing Sensitive Information
- CWE-541: Inclusion of Sensitive Information in an Include File
- CWE-547: Use of Hard-coded, Security-relevant Constants
- CWE-611: Improper Restriction of XML External Entity Reference
- CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
- CWE-756: Missing Custom Error Page
- CWE-776: Improper Restriction of Recursive Entity References in DTDs (XML Entity Expansion)
- CWE-942: Permissive Cross-domain Policy with Untrusted Domains
- CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
- CWE-1032: OWASP Top Ten 2017 Category A6
- CWE-1174: ASP.NET Misconfiguration: Improper Model Validation

## Search Patterns (grep)
### Group 1: Error handling / info leak (CWE-209, 756)
- `stack|stackTrace|err\.message|error\.message`
- `console\.log|console\.error|console\.warn` (in production)
- `NODE_ENV|development|production`
- `app\.use.*errorHandler|express\.errorHandler`

### Group 2: Headers and security configuration (CWE-16, 942, 614, 1004)
- `helmet|X-Frame|X-Content-Type|Content-Security-Policy|CSP`
- `httpOnly|secure|sameSite` (cookie settings)
- `cors\(|Access-Control-Allow-Origin`
- `X-Powered-By|server.*header`

### Group 3: Hardcoded secrets / config (CWE-260, 315, 526, 541, 547)
- `password.*=.*['"]|secret.*=.*['"]|key.*=.*['"]`
- `process\.env\.|dotenv|\.env`
- `default.*password|admin.*password`

### Group 4: XML/DTD (CWE-611, 776)
- `xml|XML|parseXml|libxmljs|xml2js|DOMParser`
- `DOCTYPE|ENTITY|SYSTEM`
- `xxe|XXE`

## Output Format
Return a table:
```
| # | File | Line | CWE | Vulnerability description | Severity | TP/FP/Info |
|---|------|------|-----|--------------------------|----------|------------|
| 1 | server.ts | 12 | CWE-209 | Stack trace leaks to client in errorHandler | Medium | TP |
```

At the end of the summary, include:
- Total findings: X
- TP: X, FP: X, Info: X  
- High: X, Medium: X, Low: X, Info: X
