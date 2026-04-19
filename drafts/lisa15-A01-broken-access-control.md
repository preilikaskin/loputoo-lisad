# A01:2025 Broken Access Control — Agent Instructions

## Category
OWASP Top 10:2025 A01 — Broken Access Control
40 mapped CWEs, highest incidence rate in the dataset.

## CWE List
- CWE-22: Path Traversal
- CWE-23: Relative Path Traversal
- CWE-36: Absolute Path Traversal
- CWE-59: Improper Link Resolution (Symlink Following)
- CWE-61: UNIX Symbolic Link Following
- CWE-65: Windows Hard Link
- CWE-200: Exposure of Sensitive Information to Unauthorized Actor
- CWE-201: Exposure of Sensitive Information Through Sent Data
- CWE-219: Storage of File with Sensitive Data Under Web Root
- CWE-276: Incorrect Default Permissions
- CWE-281: Improper Preservation of Permissions
- CWE-282: Improper Ownership Management
- CWE-283: Unverified Ownership
- CWE-284: Improper Access Control
- CWE-285: Improper Authorization
- CWE-352: Cross-Site Request Forgery (CSRF)
- CWE-359: Exposure of Private Personal Information
- CWE-377: Insecure Temporary File
- CWE-379: Creation of Temporary File in Directory with Insecure Permissions
- CWE-402: Transmission of Private Resources into New Sphere
- CWE-424: Improper Protection of Alternate Path
- CWE-425: Direct Request (Forced Browsing)
- CWE-441: Unintended Proxy or Intermediary (Confused Deputy)
- CWE-497: Exposure of Sensitive System Information
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File
- CWE-540: Inclusion of Sensitive Information in Source Code
- CWE-548: Exposure of Information Through Directory Listing
- CWE-552: Files or Directories Accessible to External Parties
- CWE-566: Authorization Bypass Through User-Controlled SQL Primary Key
- CWE-601: URL Redirection to Untrusted Site (Open Redirect)
- CWE-615: Inclusion of Sensitive Information in Source Code Comments
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-668: Exposure of Resource to Wrong Sphere
- CWE-732: Incorrect Permission Assignment for Critical Resource
- CWE-749: Exposed Dangerous Method or Function
- CWE-862: Missing Authorization
- CWE-863: Incorrect Authorization
- CWE-918: Server-Side Request Forgery (SSRF)
- CWE-922: Insecure Storage of Sensitive Information
- CWE-1275: Sensitive Cookie with Improper SameSite Attribute

## Search Patterns (grep)
### Group 1: Authorization (CWE-284, 285, 862, 863, 639, 566, 425)
- `\[Authorize|\[AllowAnonymous|Authorize\(` — check all controllers/actions for auth attributes
- `Roles\s*=|Policy\s*=|RoleConstants` — role-based access rules
- `User\.FindFirst|User\.IsInRole|User\.Claims` — user identity lookups (check IDOR: is the user's own ID enforced?)
- Controllers WITHOUT `[Authorize]` — scan ApiControllers/ and Areas/ for missing auth
- `FindAsync\(id\)|FirstOrDefaultAsync` — check if user ownership is validated before returning data

### Group 2: Information leak (CWE-200, 201, 359, 497, 540, 615, 922)
- `password|secret|key|token|apiKey` (hardcoded values in appsettings, Program.cs)
- `Ok\(|return Json\(|return View\(` — check what data is returned to the client
- Comments containing TODO, FIXME, hack, password, secret
- `appsettings\.json|appsettings\.Development\.json` — secrets in config files

### Group 3: Path traversal (CWE-22, 23, 36, 219, 538, 548, 552)
- `Path\.Combine|Path\.GetFullPath|Path\.Join`
- `FileStream|StreamReader|StreamWriter|System\.IO\.File`
- `IFormFile|upload|download|file` in controllers
- `UseStaticFiles|UseDirectoryBrowser|PhysicalFileProvider`

### Group 4: CSRF/CORS/SSRF (CWE-352, 918, 441, 1275)
- `AddCors|WithOrigins|AllowAnyOrigin|AllowCredentials`
- `ValidateAntiForgeryToken|AntiForgery|IgnoreAntiforgeryToken`
- `HttpClient|IHttpClientFactory|GetAsync|PostAsync` (server-side requests)
- `CookieOptions|SameSite|HttpOnly|Secure|sameSiteMode`

### Group 5: JWT/session (CWE-284 subset)
- `JwtBearer|JwtSecurityToken|TokenValidationParameters`
- `IssuerSigningKey|SymmetricSecurityKey|SigningCredentials`
- `RefreshToken|ClockSkew|ValidateLifetime`
- `Request\.Cookies\["jwt"|OnMessageReceived` — cookie-based JWT extraction

### Group 6: Redirect/files (CWE-601, 668, 732, 749)
- `Redirect\(|RedirectToAction|RedirectPermanent|LocalRedirect`
- `returnUrl|ReturnUrl|redirect` — open redirect via user-controlled URL
- `Process\.Start|ProcessStartInfo` — dangerous OS process invocation
- `Assembly\.Load|Activator\.CreateInstance|Type\.GetType` — dynamic type loading

## Output Format
Return a table:
```
| # | File | Line | CWE | Vulnerability description | Severity | TP/FP/Info |
|---|------|------|-----|--------------------------|----------|------------|
| 1 | WebApp/ApiControllers/PersonApiController.cs | 45 | CWE-285 | Missing authorization check on admin endpoint | High | TP |
```

At the end of the summary, include:
- Total findings: X
- TP: X, FP: X, Info: X  
- High: X, Medium: X, Low: X, Info: X
