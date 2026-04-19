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
- `JsonSerializer\.Deserialize|JsonConvert\.DeserializeObject|Newtonsoft` — JSON deserialization
- `BinaryFormatter|ObjectStateFormatter|SoapFormatter|LosFormatter` — dangerous binary deserialization
- `TypeNameHandling|TypeNameAssemblyFormat` — Newtonsoft type handling (Auto/All = dangerous)
- `\[FromBody\]|\[FromForm\]|\[FromQuery\]` — model binding from user input (check what types)
- `XmlSerializer|DataContractSerializer` — XML deserialization

### Group 2: Integrity checks (CWE-345, 353, 494)
- `integrity=|crossorigin` — SRI attributes on external scripts (check presence in HTML templates)
- `<script.*src=|<link.*href=` — manually check if external resources have `integrity` attribute
- `HttpClient\.GetAsync|DownloadFileAsync` — downloading code/data without verification
- `NuGet\.Config|<packageSources>` — trusted package sources

### Group 3: Mass assignment (CWE-915)
- `\[Bind\(|\[BindProperty\(` — whitelisted model binding (presence = protective)
- `\[FromBody\].*model|\[FromBody\].*entity` — check if whole entity is bound from request body
- API controllers accepting domain entities directly vs DTOs — DTO pattern reduces mass assignment risk
- `TryUpdateModelAsync|UpdateModel` — manual model update (check which properties)

### Group 4: Cookie integrity (CWE-565, 784)
- `CookieOptions|CookieBuilder|Append.*cookie`
- `HttpOnly|Secure|SameSite|SameSiteMode` — cookie security flags
- `JwtBearerEvents|OnMessageReceived` — JWT from cookie extraction
- `DataProtection|IDataProtector|Protect\(|Unprotect\(` — cookie data protection

## Output Format
Return a table:
```
| # | File | Line | CWE | Vulnerability description | Severity | TP/FP/Info |
|---|------|------|-----|--------------------------|----------|------------|
| 1 | WebApp/ApiControllers/ServiceApiController.cs | 30 | CWE-915 | Domain entity directly bound from [FromBody] without DTO | Medium | TP |
```

At the end of the summary, include:
- Total findings: X
- TP: X, FP: X, Info: X  
- High: X, Medium: X, Low: X, Info: X
