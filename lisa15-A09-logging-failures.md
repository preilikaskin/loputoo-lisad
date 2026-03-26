# A09:2025 Security Logging and Alerting Failures — Agent Instructions

## Category
OWASP Top 10:2025 A09 — Security Logging and Alerting Failures (formerly A09:2021)
Covers missing logging, insufficient monitoring, log manipulation.

## CWE List
- CWE-117: Improper Output Neutralization for Logs
- CWE-223: Omission of Security-relevant Information
- CWE-532: Insertion of Sensitive Information into Log File
- CWE-778: Insufficient Logging
- CWE-779: Logging of Excessive Data

## Search Patterns (grep)
### Group 1: Logging presence (CWE-778, 223)
- `logger|winston|morgan|pino|bunyan|log4js`
- `console\.log|console\.error` (used instead of proper logging?)
- `app\.use.*morgan|app\.use.*logger`
- Routes WITHOUT logging (especially auth/admin endpoints)

### Group 2: Sensitive data in logs (CWE-532, 779)
- `log.*password|log.*token|log.*secret|log.*key`
- `console\.log.*req\.body|console\.log.*req\.headers`
- `JSON\.stringify.*req\.body` into logs

### Group 3: Log manipulation (CWE-117)
- `\n.*log|\\n.*log|req\..*log` (CRLF injection into logs)
- `sanitize.*log|escape.*log` (are logs sanitized?)

## Output Format
Return a table:
```
| # | File | Line | CWE | Vulnerability description | Severity | TP/FP/Info |
|---|------|------|-----|--------------------------|----------|------------|
| 1 | routes/admin.ts | 55 | CWE-778 | Admin endpoint without security logging | Low | TP |
```

At the end of the summary, include:
- Total findings: X
- TP: X, FP: X, Info: X  
- High: X, Medium: X, Low: X, Info: X
