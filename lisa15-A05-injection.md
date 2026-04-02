# A05:2025 Injection — Agent Instructions

## Category
OWASP Top 10:2025 A05 — Injection (formerly A03:2021)
Covers SQL injection, XSS, NoSQL injection, command injection, LDAP injection, etc.

## CWE List
- CWE-20: Improper Input Validation
- CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component (Injection)
- CWE-75: Failure to Sanitize Special Elements into a Different Plane
- CWE-77: Improper Neutralization of Special Elements Used in a Command (Command Injection)
- CWE-78: OS Command Injection
- CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)
- CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
- CWE-83: Improper Neutralization of Script in Attributes in a Web Page
- CWE-87: Improper Neutralization of Alternate XSS Syntax
- CWE-88: Improper Neutralization of Argument Delimiters in a Command
- CWE-89: SQL Injection
- CWE-90: LDAP Injection
- CWE-91: XML Injection
- CWE-93: Improper Neutralization of CRLF Sequences (HTTP Response Splitting)
- CWE-94: Improper Control of Code Generation (Code Injection)
- CWE-95: Eval Injection
- CWE-96: Improper Neutralization of Directives in Statically Saved Code
- CWE-97: Improper Neutralization of Server-Side Includes (SSI)
- CWE-98: PHP Remote File Inclusion
- CWE-113: HTTP Response Splitting
- CWE-116: Improper Encoding or Escaping of Output
- CWE-138: Improper Neutralization of Special Elements
- CWE-184: Incomplete List of Disallowed Inputs
- CWE-470: Use of Externally-Controlled Input to Select Classes or Code
- CWE-471: Modification of Assumed-Immutable Data
- CWE-564: SQL Injection: Hibernate
- CWE-610: Externally Controlled Reference to a Resource in Another Sphere
- CWE-643: Improper Neutralization of Data within XPath Expressions
- CWE-644: Improper Neutralization of HTTP Headers for Scripting Syntax
- CWE-652: Improper Neutralization of Data within XQuery Expressions
- CWE-917: Improper Neutralization of Special Elements Used in an Expression Language Statement

## Search Patterns (grep)
### Group 1: SQL Injection (CWE-89, 564)
- `FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync|SqlCommand|SqlDataReader`
- `string\.Format.*SELECT|string\.Format.*INSERT|string\.Format.*UPDATE|string\.Format.*DELETE`
- `\$".*SELECT|\$".*INSERT|\$".*WHERE` — string interpolation in SQL (check if `FromSqlInterpolated` is used safely)
- `FromSqlInterpolated|ExecuteSqlInterpolated` — these are safe (EF Core parameterizes automatically), mark as Info
- `.Where\(|.FirstOrDefaultAsync\(|.ToListAsync\(` — LINQ queries (EF Core parameterizes, verify no raw string concat)

### Group 2: XSS (CWE-79, 80, 83, 87, 116)
- `Html\.Raw|@Html\.Raw` — unescaped HTML output in Razor views
- `v-html` — Vue directive for rendering raw HTML (bypasses auto-escaping)
- `innerHTML|outerHTML|document\.write` — DOM XSS in frontend
- `HtmlEncoder|JavaScriptEncoder|UrlEncoder` — encoding functions (presence = Info)
- `Content\(.*text/html|return Content\(` — returning raw content

### Group 3: Command/Code Injection (CWE-77, 78, 94, 95)
- `Process\.Start|ProcessStartInfo|cmd\.exe|/bin/bash`
- `Assembly\.Load|Activator\.CreateInstance|Type\.GetType` — dynamic type loading
- `Reflection|MethodInfo\.Invoke` — reflective code execution
- `CSharpScript|Roslyn|DynamicExpresso` — runtime code compilation

### Group 4: Other injections (CWE-90, 91, 93, 113)
- `XmlDocument|XPath|XPathNavigator|SelectNodes` — XML/XPath injection
- `DirectorySearcher|DirectoryEntry|LDAP` — LDAP injection
- `\r\n|Response\.Headers\.Add.*req|AppendHeader` — HTTP header injection
- `Razor|RazorPage|@model` — template injection in Razor views

## Output Format
Return a table:
```
| # | File | Line | CWE | Vulnerability description | Severity | TP/FP/Info |
|---|------|------|-----|--------------------------|----------|------------|
| 1 | WebApp/ApiControllers/ServiceApiController.cs | 34 | CWE-89 | SQL query with user input via FromSqlRaw without parameterization | High | TP |
```

At the end of the summary, include:
- Total findings: X
- TP: X, FP: X, Info: X  
- High: X, Medium: X, Low: X, Info: X
