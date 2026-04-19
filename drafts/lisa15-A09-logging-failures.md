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
- `ILogger|_logger|LogInformation|LogWarning|LogError|LogCritical`
- `AddLogging|UseSerilog|UseNLog|AddSerilog` — logging framework configuration
- `builder\.Logging|ILoggerFactory` — logging setup in Program.cs
- Controllers/endpoints WITHOUT `_logger.Log` — especially auth/admin endpoints (scan ApiControllers/ and Areas/)

### Group 2: Sensitive data in logs (CWE-532, 779)
- `Log.*password|Log.*token|Log.*secret|Log.*key|Log.*credit`
- `Log.*req\.Body|Log.*Request\.Body|Log.*Request\.Headers`
- `JsonSerializer\.Serialize.*password` — serializing sensitive objects into logs
- `LogInformation.*\{Email\}|LogInformation.*\{Password\}` — structured logging with sensitive fields

### Group 3: Log manipulation (CWE-117)
- Verify that structured logging (`{placeholder}` syntax) is used instead of string concatenation
- `\$".*_logger|string\.Format.*_logger` — string interpolation/concatenation in log messages (allows log injection)
- `\n|\r` in user-controlled input flowing into logs

## Output Format
Return a table:
```
| # | File | Line | CWE | Vulnerability description | Severity | TP/FP/Info |
|---|------|------|-----|--------------------------|----------|------------|
| 1 | WebApp/ApiControllers/Identity/AccountController.cs | 55 | CWE-778 | Admin endpoint without security logging | Low | TP |
```

At the end of the summary, include:
- Total findings: X
- TP: X, FP: X, Info: X  
- High: X, Medium: X, Low: X, Info: X
