# A03:2025 Software Supply Chain Failures — Agent Instructions

## Category
OWASP Top 10:2025 A03 — Software Supply Chain Failures (formerly A06:2021 Vulnerable and Outdated Components)
Covers vulnerable dependencies, missing version management, components from untrusted sources.

## CWE List
- CWE-426: Untrusted Search Path
- CWE-427: Uncontrolled Search Path Element
- CWE-506: Embedded Malicious Code
- CWE-511: Logic/Time Bomb
- CWE-512: Spyware
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere
- CWE-830: Inclusion of Web Functionality from an Untrusted Source
- CWE-1035: OWASP Top Ten 2017 Category A9
- CWE-1104: Use of Unmaintained Third-Party Components
- CWE-1357: Reliance on Insufficiently Trustworthy Component

## Search Patterns (grep)
### Group 1: Dependency analysis (CWE-829, 1104, 1357)
- `package.json` — dependencies and versions
- `package-lock.json` — locked versions
- `require\(|import .* from` — third-party libraries
- `npm|yarn|pnpm` — package management config

### Group 2: Untrusted sources (CWE-830, 426, 427)
- `cdn\.|unpkg|jsdelivr|cloudflare` — loading from external CDNs
- `<script.*src=.*http` — scripts loaded over HTTP
- `integrity=|crossorigin` — subresource integrity check (missing?)

### Group 3: Malicious/hidden code (CWE-506, 511, 512)
- `eval\(|Function\(|setTimeout.*string|setInterval.*string`
- `postinstall|preinstall` — package.json scripts
- `obfusc|encode|decode|atob|btoa` evaluate in context

## Output Format
Return a table:
```
| # | File | Line | CWE | Vulnerability description | Severity | TP/FP/Info |
|---|------|------|-----|--------------------------|----------|------------|
| 1 | package.json | 5 | CWE-1104 | Unmaintained dependency xyz version < x.y | Medium | TP |
```

At the end of the summary, include:
- Total findings: X
- TP: X, FP: X, Info: X  
- High: X, Medium: X, Low: X, Info: X
