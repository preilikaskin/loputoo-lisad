# Code Review Verification — All 124 Manual Findings (Haldur / Puksiir)

## Context

This is part of a TalTech bachelor's thesis comparing security testing methods. The target is **Puksiir**, a custom ASP.NET Core towing-company management application.

An exploit verification script (`exploit_tests.py`) contains 124 pre-written code-review and SCA verdicts (Phase 2) that need **independent verification against actual source code**. Your task is to read the real source code and confirm or correct each verdict.

**IMPORTANT**: These verdicts were originally written with LLM assistance during the same session that produced the initial findings. This verification must be **independent** — base your verdict solely on what you find in the source code, not on the descriptions below.

## Source Code Location

- **Puksiir repo**: `/Users/kaisaliiv/Projects/puksiir2026-security-tests`
- **Backend**: `backend/WebApp/`, `backend/App.BLL/`, `backend/App.DAL.EF/`, `backend/App.Domain/`, `backend/App.DTO/`
- **Frontend**: `frontend/src/`
- **Config**: `backend/WebApp/appsettings.*.json`, `backend/.env`
- **Do NOT read**: `node_modules/`, `bin/`, `obj/`, `.git/`

## Rules

1. For EACH finding below, **read the actual source file** and verify the claim
2. For SCA findings (marked `[SCA]`), check `frontend/package.json` or `frontend/package-lock.json` for the actual installed version
3. Classify: **TP** (vulnerability/weakness exists in source), **FP** (claim is wrong, not exploitable, or not a security issue), **Info** (exists but informational only)
4. Provide the **exact file path and line number(s)** where you verified
5. Write a 1-sentence evidence statement — what you actually saw in the code
6. If you DISAGREE with the original verdict, explain why in detail

## Output

Write results to: `/Users/kaisaliiv/Desktop/Lõputöö/ai-prompts/results/code-review-verification-haldur.md`

### Format

```
| # | VID  | Original | Your Verdict | Agree? | File:Line | Evidence |
|---|------|----------|--------------|--------|-----------|----------|
| 1 | V006 | TP       | TP           | Yes    | backend/App.BLL/Services/ServiceService.cs:84 | IsOwnedByUserAsync defined but not called in UpdateServiceWithLinesAsync |
```

### Summary statistics at the end

- Total findings verified: 124
- Agreement rate: X/124 (Y%)
- Disagreements: list of VIDs with reasoning
- Uncertain: findings needing runtime testing

---

## Code-Review Findings to Verify (104 total)

### A01 — Broken Access Control

| #  | VID  | Verdict | Description |
|----|------|---------|-------------|
| 1  | V006 | TP  | IServiceService defines IsOwnedByUserAsync but ownership not enforced in update path |
| 2  | V007 | TP  | ServiceBLLMapper drops UserId on BLL→DAL direction — audit field lost on write-back |
| 3  | V011 | TP  | BaseRepository.Update has explicit TODO comment: 'add user id check to update' |
| 4  | V012 | TP  | Route 'organisationcreate' guarded with allStaff but comment says 'only managers' |
| 5  | V013 | TP  | Frontend role predicates derived from localStorage values — client-side only security |
| 6  | V014 | TP  | AdminUserEdit availableRoles populated from backend but no client-side filtering |
| 7  | V044 | TP  | RecentServiceApiMapper maps five fully nested client-supplied objects — mass assignment risk |
| 8  | V049 | TP  | HasOverlapAsync accepts excludeId=null which bypasses overlap check |
| 9  | V052 | TP  | AddToRoleAsync failure logged to Console.WriteLine but does not throw — silent failure |
| 10 | V063 | TP  | appsettings.Development.json contains hardcoded DB password and JWT key |
| 11 | V122 | FP  | Authority.IsActive commented out is a design decision, not a security vulnerability |
| 12 | V125 | TP  | IAppUser interface surfaces isLockedOut/lockoutEnd to frontend — information disclosure |
| 13 | V126 | FP  | Interpolating organisationId into URL path is normal API call pattern, not injection |
| 14 | V127 | TP  | localStorage role data can be tampered — same issue family as V013 |
| 15 | V128 | TP  | Organisation edit button visible to non-managers — client-side rendering only check |
| 16 | V129 | TP  | DeleteDatabase is public static with no environment check — callable from any context |

### A02 — Security Misconfiguration

| #  | VID  | Verdict | Description |
|----|------|---------|-------------|
| 17 | V068 | TP  | ParseHms splits on ':' with int.Parse — no try/catch, no length check, throws on bad input |
| 18 | V069 | TP  | ScheduleEntryRepository loads all entries to memory for overlap check — unbounded query |
| 19 | V070 | TP  | ServiceRepository uses in-memory GroupBy after ToListAsync — full table loaded |
| 20 | V071 | TP  | VehicleUseStart resource maps to 'Kasutamise lõpp' (end) — wrong label |
| 21 | V072 | TP  | Organisation resource key holds garbage placeholder 'sdsd' |
| 22 | V073 | TP  | ServiceType.Designer.cs exposes properties not present in .resx — build artifact mismatch |
| 23 | V074 | TP  | Guid.Parse throws FormatException for non-GUID — no try-parse validation before call |
| 24 | V081 | TP  | axiosInterceptor passes server-controlled string directly to toast notification |
| 25 | V082 | TP  | JSON.parse on localStorage 'roles' without try/catch — throws on corrupt data |
| 26 | V130 | FP  | csproj resource file path mismatch is a build issue, not a security vulnerability |
| 27 | V131 | FP  | Unused resource keys in Designer.cs are build artifacts, not security issues |
| 28 | V132 | FP  | Static JwtSecurityTokenHandler is thread-safety concern, not a security vulnerability |
| 29 | V134 | FP  | UnauthorizedAccessException in GetMy is proper authorization check, not a vulnerability |
| 30 | V136 | TP  | Bare catch(Exception) in ServicesController — swallows all errors including security-relevant ones |
| 31 | V137 | TP  | Admin create/edit views expose FK dropdown IDs — information disclosure of internal GUIDs |
| 32 | V138 | FP  | Null-forgiving operator (!) is NRE risk, not a security vulnerability |
| 33 | V139 | TP  | Services Index/Details renders Person.Code (isikukood) — PII exposed in admin UI |
| 34 | V140 | TP  | Notification pending array has no max length — memory exhaustion vector |
| 35 | V141 | TP  | NotFound page renders FloatingConfigurator without requiresAuth — config exposed |

### A03 — Supply Chain Failures

| #  | VID  | Verdict | Description |
|----|------|---------|-------------|
| 36 | V019 | TP  | Project targets net10.0 with mismatched Microsoft.AspNetCore.Identity.EF version — supply chain risk |
| 37 | V143 | FP  | AppBLL circular dependency is code smell, not a security vulnerability |
| 38 | V144 | TP  | CSP whitelists https://fonts.cdnfonts.com without SRI — external dependency risk |
| 39 | V146 | TP  | External font stylesheet from cdnfonts.com loaded without integrity attribute |

### A04 — Cryptographic Failures

| #  | VID  | Verdict | Description |
|----|------|---------|-------------|
| 40 | V015 | TP  | AppDbContextFactory fallback: 'Username=postgres;Password=postgres' hardcoded in source |
| 41 | V029 | TP  | Person.Code (isikukood) stored and transmitted without encryption or masking |
| 42 | V030 | TP  | Plaintext passwords 'Foo.Bar.1', 'Foo.Bar.2' hardcoded for seed users including Admin |
| 43 | V031 | TP  | No minimum key length validation before SymmetricSecurityKey construction |
| 44 | V033 | TP  | Person.Code has no [PersonalData] attribute — no special handling for Estonian ID code |
| 45 | V090 | TP  | JWT signing key stored in cleartext .env file — if leaked, all tokens forgeable |
| 46 | V091 | FP  | Guid.NewGuid() provides 122 bits entropy — sufficient for refresh token uniqueness |
| 47 | V092 | TP  | Hardcoded dev passwords (CeoDev123!, PuksDev123!, PesulaDev123!) in Program.cs source |
| 48 | V094 | TP  | Hardcoded JWT key in appsettings.Development.json — key in source control |
| 49 | V095 | TP  | Full request URL embedded in error detail string — may leak sensitive URL params |
| 50 | V148 | FP  | HTTP between Docker containers is internal network — acceptable in compose |
| 51 | V149 | FP  | RegisterDto carrying password as string is standard DTO pattern, HTTPS assumed |

### A05 — Injection

| #  | VID  | Verdict | Description |
|----|------|---------|-------------|
| 52 | V096 | TP  | Model.ImageUrl accepts arbitrary string with only MaxLength — no URL scheme validation |
| 53 | V097 | TP  | UserNameResolver silently returns 'System' when HttpContext null — audit trail gap |
| 54 | V098 | TP  | servedVehicleRegNumber sent raw without sanitization or validation |
| 55 | V150 | TP  | ServiceApiService interpolates date strings directly into query params |

### A06 — Insecure Design

| #  | VID  | Verdict | Description |
|----|------|---------|-------------|
| 56 | V099 | TP  | Service.PriceNoVat uses IEEE 754 double — rounding errors for monetary values |
| 57 | V100 | FP  | AppRefreshToken.SessionStartedAt set at login is informational, not exploitable |
| 58 | V101 | TP  | AppUser FirstName/LastName lack [PersonalData] attribute — PII not marked for GDPR |
| 59 | V151 | TP  | Authority ValidFrom/ValidUntil have no model-level constraint ensuring from < until |
| 60 | V152 | TP  | Service.CreatedByName [NotMapped] has no MaxLength — unbounded string |
| 61 | V153 | TP  | ScheduleColor MaxLength(7) but no regex for #RRGGBB — accepts arbitrary 7-char strings |

### A07 — Authentication Failures

| #  | VID  | Verdict | Description |
|----|------|---------|-------------|
| 62 | V037 | TP  | All identity and session fields stored in localStorage — script-accessible |
| 63 | V038 | TP  | Password reset token and email passed via URL query parameters (CWE-598) |
| 64 | V104 | FP  | JWTResponse comment about cookie delivery is informational documentation |
| 65 | V106 | TP  | Admin password reset sends new plaintext password in HTML email body |
| 66 | V107 | TP  | Session timeout check uses localStorage timestamps — client-side only enforcement |
| 67 | V108 | TP  | Registration form has zero client-side password validation before submit |
| 68 | V158 | TP  | Default ASP.NET Identity password policy (min 6 chars) — below NIST 800-63B minimum of 8 |
| 69 | V159 | FP  | SessionExpiryWarning 30s delay is UX issue, not a security vulnerability |
| 70 | V160 | TP  | i18n locale read from localStorage with no allowlist — arbitrary culture injection |
| 71 | V161 | TP  | AdminUserCreate performs no client-side password validation before API call |
| 72 | V162 | FP  | ForgotPassword always returns Ok — finding about error display is incorrect |

### A08 — Integrity Failures

| #  | VID  | Verdict | Description |
|----|------|---------|-------------|
| 73 | V113 | TP  | Service DAL DTO uses double for PriceNoVat — same issue as V099 |
| 74 | V115 | TP  | ScheduleEntryMapper casts int to enum without validation — undefined values accepted |
| 75 | V163 | FP  | ServiceMapper null propagation with ! operator is NRE risk, not security vuln |
| 76 | V164 | TP  | Model.ImageUrl has no [Url] attribute — accepts arbitrary string as URL |

### A09 — Logging Failures

| #  | VID  | Verdict | Description |
|----|------|---------|-------------|
| 77 | V119 | TP  | AdminUsersController has no security logging for role changes, password resets, user unlocks |
| 78 | V120 | TP  | notificationStore logs internal API URLs and HTTP status codes to browser console |
| 79 | V121 | TP  | .env file contains cleartext DB password, JWT key, admin password |
| 80 | V165 | TP  | MarkBLLMapper logs full entity objects at Debug level — may contain PII |
| 81 | V166 | TP  | AuthorityApiController has no security logging — no audit trail |
| 82 | V167 | TP  | ModelsApiController has no security logging; MarksApiController has ILogger commented out |
| 83 | V168 | TP  | OrganisationApiController has no security logging |
| 84 | V169 | TP  | OrganisationVehicleApiController has no security logging |
| 85 | V170 | TP  | PersonApiController has no ILogger injected — no audit trail for PII access |
| 86 | V171 | TP  | ScheduleApiController has no security logging |
| 87 | V172 | TP  | ScheduleEntryApiController has no security logging |
| 88 | V173 | TP  | ServiceApiController has no security logging |
| 89 | V174 | TP  | ServiceTypeApiController has no security logging |
| 90 | V175 | TP  | VatApiController has no security logging |
| 91 | V176 | TP  | VehicleController has no security logging |
| 92 | V177 | TP  | All 9 MVC admin area controllers lack ILogger — no audit trail for admin CRUD |
| 93 | V178 | TP  | MarksController uses Console.WriteLine with entity data — PII in stdout |
| 94 | V179 | TP  | VehiclesController logs registration numbers at Information level |
| 95 | V180 | FP  | PersonApiService no try/catch is error propagation pattern, not security vuln |

### A10 — Exceptional Conditions

| #  | VID  | Verdict | Description |
|----|------|---------|-------------|
| 96 | V157 | TP  | DataSeeding uses .Result on async — deadlock risk in synchronous context |
| 97 | V181 | TP  | Global error handler present for non-dev, but no custom handler for API routes |

---

## SCA Findings to Verify (20 total)

For each SCA finding, check `frontend/package-lock.json` (or `frontend/package.json`) for the actual installed version. If the version matches the claimed vulnerable version, verify the CVE/GHSA applies.

| #   | VID  | Verdict | Package | Claimed Version | Description |
|-----|------|---------|---------|-----------------|-------------|
| 98  | V002 | TP  | form-data | 4.0.2 | uses Math.random() for boundary — GHSA-fjxv-7rqg-78g4 (CWE-330) |
| 99  | V017 | TP  | axios | 1.9.0 | CVE-2025-58754 (CWE-770) — request body not properly limited |
| 100 | V018 | TP  | axios | 1.9.0 | CVE-2026-25639 (CWE-754) — incomplete error handling |
| 101 | V020 | TP  | flatted | 3.3.3 | CVE-2026-32141 (CWE-674) — recursive revive() stack overflow |
| 102 | V021 | TP  | flatted | 3.3.3 | GHSA-rf6f-7fwh-wjgh (CWE-1321) — prototype pollution in parse() |
| 103 | V022 | TP  | glob | 10.4.5 | CLI command injection — GHSA-5j98-mcp5-4vw2 (CWE-78) |
| 104 | V023 | TP  | immutable | 5.1.1 | GHSA-wf6x-7x77-mvgw (CWE-1321) — prototype pollution |
| 105 | V024 | TP  | minimatch | 3.1.2 | CVE-2026-26996 (CWE-1333) — ReDoS |
| 106 | V025 | TP  | minimatch | 3.1.2 | CVE-2026-27903 (CWE-407) — algorithmic complexity DoS |
| 107 | V026 | TP  | minimatch | 9.0.5 | CVE-2026-26996 (CWE-1333) — ReDoS |
| 108 | V027 | TP  | minimatch | 9.0.5 | CVE-2026-27903 (CWE-407) — algorithmic complexity DoS |
| 109 | V028 | TP  | rollup | 4.40.1 | CVE-2026-27606 (CWE-22) — path traversal in module bundler |
| 110 | V084 | TP  | @intlify/core-base | 11.1.3 | XSS bypass in escapeParameterHtml — GHSA-x8qp-wqqm-57ph |
| 111 | V085 | TP  | ajv | 6.12.6 | GHSA-2g4f-4pwh-qvx6 (CWE-400) — ReDoS |
| 112 | V086 | TP  | js-yaml | 4.1.0 | GHSA-mh29-5h37-fv8m (CWE-1321) — prototype pollution |
| 113 | V087 | TP  | lodash | 4.17.21 | CVE-2025-13465 (CWE-1321) — prototype pollution via _.unset |
| 114 | V088 | TP  | vite | 6.3.4 | GHSA-93m4-6634-74q7 (CWE-22) — server.fs.deny bypass |
| 115 | V089 | TP  | vue-i18n | 11.1.3 | XSS bypass in escapeParameterHtml — GHSA-x8qp-wqqm-57ph |
| 116 | V145 | TP  | brace-expansion | 1.1.11 | GHSA-v6h2-p8h4-qcjw (CWE-400) — ReDoS |
| 117 | V147 | TP  | vite | 6.3.4 | CVE-2025-58752 (CWE-23) — relative path traversal |
