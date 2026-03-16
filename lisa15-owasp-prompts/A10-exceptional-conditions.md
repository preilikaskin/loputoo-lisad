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
- `catch.*\{[\s]*\}|catch.*\{\s*\/\/` — tühjad catch'id
- `catch.*console\.log` — catch mis ainult logib
- `catch.*next\(` — kas edastatakse error middleware'le?

### Grupp 2: Kontrollimata tagastusväärtused (CWE-252, 391)
- `\.then\(` ilma `.catch\(` blokita
- `await ` ilma try/catch'ita
- `callback.*err.*null|callback\(null`

### Grupp 3: Error info leak (CWE-209 koostöös, CWE-703)
- `res\.status\(500\)|res\.send.*err|res\.json.*err`
- `next\(err\)|next\(error\)`
- `stack|stackTrace|err\.message` vastusesse

### Grupp 4: Globaalne error handling (CWE-544, 755)
- `process\.on.*uncaughtException|process\.on.*unhandledRejection`
- `app\.use.*err.*req.*res.*next` — Express error middleware
- `errorHandler|error-handler`

## Output Format
Return a table:
```
| # | File | Line | CWE | Vulnerability description | Severity | TP/FP/Info |
|---|------|------|-----|--------------------------|----------|------------|
| 1 | routes/payment.ts | 42 | CWE-248 | Empty catch block in payment processing | Medium | TP |
```

At the end of the summary, include:
- Total findings: X
- TP: X, FP: X, Info: X  
- High: X, Medium: X, Low: X, Info: X
