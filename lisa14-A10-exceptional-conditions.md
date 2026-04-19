# A10:2025 Mishandling of Exceptional Conditions — Agent Instructions

## Category
OWASP Top 10:2025 A10 — Mishandling of Exceptional Conditions (formerly A10:2021 SSRF + new category)
Covers improper exception handling, uncaught errors, information leaks through exceptions.

## CWE List
- CWE-248: Uncaught Exception
- CWE-252: Unchecked Return Value
- CWE-390: Detection of Error Condition Without Action
- CWE-391: Unchecked Error Condition
- CWE-392: Missing Report of Error Condition
- CWE-395: Use of NullPointerException Catch to Detect NULL Pointer Dereference
- CWE-396: Declaration of Catch for Generic Exception
- CWE-397: Declaration of Throws for Generic Exception
- CWE-544: Missing Standardized Error Handling Mechanism
- CWE-703: Improper Check or Handling of Exceptional Conditions
- CWE-754: Improper Check for Unusual or Exceptional Conditions
- CWE-755: Improper Handling of Exceptional Conditions

## Otsimustrid (grep)
### Grupp 1: Try/catch käsitlus (CWE-248, 396, 544)
- `catch\s*\(` — üldised catch blokid
- `catch\s*\(Exception|catch\s*\(System\.Exception` — liiga lai catch (CWE-396)
- `catch.*\{\s*\}|catch.*\{\s*\/\/` — tühjad catch'id
- `catch.*_logger\.Log` — kas catch logib ja käsitleb korralikult?
- `throw;|throw ex;` — kas throw säilitab stack trace'i? (`throw;` on korrektne, `throw ex;` kaotab stack trace'i)

### Grupp 2: Kontrollimata tagastusväärtused (CWE-252, 391)
- `\.Result|.GetAwaiter\(\)\.GetResult\(\)` — sünkroonne async-blokeering (potentsiaalne deadlock)
- `await ` ilma try/catch'ita kriitilistes tehtedes
- `Task\.Run|Task\.Factory\.StartNew` — kas tulemus on kontrollitud?
- `TryParse|TryGetValue` — kas tagastusväärtus on kontrollitud? (hea muster: `if (!Guid.TryParse(..., out var id)) return BadRequest()`)

### Grupp 3: Error info leak (CWE-209 koostöös, CWE-703)
- `StatusCode\(500|InternalServerError|Problem\(` — kas 500 vastusesse satub stack trace?
- `ex\.Message|ex\.ToString\(\)|ex\.StackTrace` vastusesse (Ok(), Json(), Content())
- `BadRequest\(.*ex|NotFound\(.*ex` — exception message kliendile

### Grupp 4: Globaalne error handling (CWE-544, 755)
- `UseExceptionHandler|app\.UseStatusCodePages` — globaalne error middleware
- `UseDeveloperExceptionPage` — ei tohi olla production'is
- `IExceptionHandler|ExceptionHandlerMiddleware` — custom error handler
- `AppDomain\.CurrentDomain\.UnhandledException|TaskScheduler\.UnobservedTaskException` — globaalne exception püüdmine

## Output Format
Return a table:
```
| # | File | Line | CWE | Vulnerability description | Severity | TP/FP/Info |
|---|------|------|-----|--------------------------|----------|------------|
| 1 | WebApp/ApiControllers/ServiceApiController.cs | 42 | CWE-248 | Empty catch block in service processing | Medium | TP |
```

At the end of the summary, include:
- Total findings: X
- TP: X, FP: X, Info: X  
- High: X, Medium: X, Low: X, Info: X
