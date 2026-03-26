# A08:2025 Software or Data Integrity Failures — Agent Instructions

## Category  
OWASP Top 10:2025 A08 — Software or Data Integrity Failures (formerly A08:2021)
Covers insecure deserialization, missing integrity checks, CI/CD pipeline compromise.

## CWE List
- CWE-345: Insufficient Verification of Data Authenticity
- CWE-353: Missing Support for Integrity Check
- CWE-426: Untrusted Search Path
- CWE-494: Download of Code Without Integrity Check
- CWE-502: Deserialization of Untrusted Data
- CWE-565: Reliance on Cookies without Validation and Integrity Checking
- CWE-784: Reliance on Cookies without Validation and Integrity Checking in a Security Decision
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere
- CWE-830: Inclusion of Web Functionality from an Untrusted Source
- CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes (Mass Assignment)

## Search Patterns (grep)
### Group 1: Deserialization (CWE-502)
- `deserialize|unserialize|JSON\.parse|yaml\.load`
- `pickle|marshal|ObjectInputStream`
- `node-serialize|serialize-javascript`

### Group 2: Integrity checks (CWE-345, 353, 494)
- `integrity|checksum|hash.*verify|signature`
- `<script.*src=` (manually check if `integrity` attribute is present — grep cannot detect attribute absence reliably)
- `download|fetch.*exec|curl|wget`

### Group 3: Mass assignment (CWE-915)
- `Object\.assign|spread.*req\.body|\.\.\..*req\.body`
- `Model\.(create|save|update|build).*req\.body|\.(create|update)\(.*req\.body` (req.body passed directly into ORM method)
- `allowlist|whitelist|pick\(|omit\(` (protective patterns — if present, mark as Info/FP; their absence in routes handling req.body is the actual vulnerability)

### Group 4: Cookie integrity (CWE-565, 784)
- `cookie|Cookie|signed.*cookie|cookie.*sign`
- `jwt.*verify|token.*valid`

## Output Format
Return a table:
```
| # | File | Line | CWE | Vulnerability description | Severity | TP/FP/Info |
|---|------|------|-----|--------------------------|----------|------------|
| 1 | routes/order.ts | 30 | CWE-915 | req.body passed directly to model via Object.assign | Medium | TP |
```

At the end of the summary, include:
- Total findings: X
- TP: X, FP: X, Info: X  
- High: X, Medium: X, Low: X, Info: X
