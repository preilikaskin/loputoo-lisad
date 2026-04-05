# Cross-Validation Request: Security Finding Classification — Haldur (Puksiir)

## Context

This is part of a bachelor's thesis at TalTech comparing four security testing methods
(DAST, SAST, SCA, AI) on a real-world towing company web application (Puksiir).

The findings below were classified as True Positive (TP) or False Positive (FP)
by a first AI model (Claude, via GitHub Copilot) based on source code review only
(no runtime testing). Your task is to **independently verify each classification**
by examining the actual source code at the referenced locations.

## Source Code Location

The Puksiir application source code is available locally:

- **Local path**: `/Users/kaisaliiv/Projects/puksiir2026-security-tests`
- **Backend**: `backend/WebApp/` (ApiControllers/, Areas/, Controllers/, Program.cs)
  - Also: `backend/App.BLL/`, `backend/App.DAL.EF/`, `backend/App.Domain/`,
    `backend/App.DTO/`, `backend/App.BLL.DTO/`, `backend/App.DAL.DTO/`
- **Frontend**: `frontend/src/` (views/, components/, service/, stores/, plugins/)
- **Config**: `backend/WebApp/appsettings.Development.json`, `backend/.env`
- **Dependencies**: `frontend/package.json`, `frontend/package-lock.json`
- **Do NOT read**: `bin/`, `obj/`, `Migrations/`, `App.Tests/`, `TestResults/`,
  `node_modules/`, `dist/`
- **Stack**: C# / .NET 10 (ASP.NET Core) + Vue 3 / TypeScript + PostgreSQL 16

All file paths in the findings below are **relative to the repo root**
(`/Users/kaisaliiv/Projects/puksiir2026-security-tests/`).
For example, `backend/WebApp/ApiControllers/PersonApiController.cs:46` means
`/Users/kaisaliiv/Projects/puksiir2026-security-tests/backend/WebApp/ApiControllers/PersonApiController.cs`, line 46.

## Instructions

For each finding below:
1. **Read the actual source code** at the referenced file and line number
2. Determine if the described vulnerability **actually exists** at that location
3. Classify as: **TP** (real vulnerability), **FP** (not a real vulnerability),
   or **Info** (informational, not directly exploitable)
4. If you **DISAGREE** with the original classification, explain why

Note on SCA findings: these are verified against `frontend/package-lock.json`.
If the specified package version is present, the finding is TP; if patched or
absent, it is FP.

## Output Format

Write your results to:
`/Users/kaisaliiv/Desktop/Lõputöö/ai-prompts/results/cross-validation-results-haldur.md`

Use this format:

### Summary table
| VID | Original | Your Verdict | Agree? | Reasoning (if disagree) |

### Statistics
- Agreement rate: X/124 (Y%)
- Disagreements: list of VIDs with brief explanation
- Uncertain: findings where you'd need runtime testing to be sure

## Target Application

- **Application**: Puksiir towing company (real-world internal business app)
- **Note**: This is NOT an intentionally vulnerable app. Vulnerabilities are unintentional.
  Benign design decisions that resemble vulnerabilities should be classified as FP.

---

## Findings to Verify (124 total)


### 1. V002 — Original: **TP** | Critical | CWE-330
- **File**: `form-data:4.0.2`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: SCA-DepCheck
- **Description**: GHSA-fjxv-7rqg-78g4: ### Summary

form-data uses `Math.random()` to select a boundary value for multipart form-encoded data. This can lead to a security issue if an attacker:
1. can observe other values produced by Math.random in the target application, and
2. can control one field of a request made using form-data

Bec
- **Reviewer reasoning**: form-data:4.0.2 — uses Math.random() for boundary — GHSA-fjxv-7rqg-78g4 (CWE-330)


### 2. V006 — Original: **TP** | High | CWE-285
- **File**: `backend/App.BLL.Contracts/IServiceService.cs:43-48`
- **OWASP**: A01 – Broken Access Control
- **Found by**: AI-CodeRabbit
- **Description**: IsOwnedByUserAsync(Guid serviceId, Guid userId) is defined on the same interface (line 31) as an explicit ownership check, yet UpdateWithValidationAsync and UpdateServiceWithLinesAsync accept no userId parameter. The ownership verification is therefore not enforceable at the contract level; callers can invoke the update methods without ever calling IsOwnedByUserAsync. | If a controller or higher-…
- **Reviewer reasoning**: IServiceService defines IsOwnedByUserAsync but ownership not enforced in update path


### 3. V007 — Original: **TP** | High | CWE-284
- **File**: `backend/App.BLL/Mappers/ServiceBLLMapper.cs:68-99`
- **OWASP**: A01 – Broken Access Control
- **Found by**: AI-CodeRabbit
- **Description**: The DAL→BLL Map (lines ~16-59) copies UserId (line ~56) and CreatedByName (line ~57) into the BLL DTO. The inverse BLL→DAL Map (lines ~68-99) constructs the outgoing App.DAL.DTO.Service without assigning UserId or CreatedByName. These fields are silently dropped on every write-back path. | Any call path that reads a Service, modifies it, and writes it back through ServiceBLLMapper will persist a…
- **Reviewer reasoning**: ServiceBLLMapper drops UserId on BLL→DAL direction — audit field lost on write-back


### 4. V011 — Original: **TP** | High | CWE-639
- **File**: `backend/Base.DAL.EF/BaseRepository.cs:88-103`
- **OWASP**: A01 – Broken Access Control
- **Found by**: AI-CodeRabbit
- **Description**: An explicit TODO comment at line 88 confirms the missing ownership check: "// TODO: add user id check to update". All other mutation methods (Add, Remove, RemoveAsync) filter by userId via GetQuery. Update does not. | An authenticated user who knows or guesses a valid entity Id belonging to another user can call the Update path (via BLL → repository) and overwrite that entity's data. The userId…
- **Reviewer reasoning**: BaseRepository.Update has explicit TODO comment: 'add user id check to update'


### 5. V012 — Original: **TP** | High | CWE-285
- **File**: `frontend/src/router/index.js:97`
- **OWASP**: A01 – Broken Access Control
- **Found by**: AI-CodeRabbit
- **Description**: Route `organisationcreate` is guarded with `requiresRoles: allStaff`, but the inline comment directly above this block reads `"Organisations — read: allStaff, CRU: managers, delete: admin"`. `allStaff` includes operator-level roles (e.g. `Puksiirijuht`, `Worker`) that should not be able to create organisations per the stated access model. | Any authenticated staff member (non-manager) can…
- **Reviewer reasoning**: Route 'organisationcreate' guarded with allStaff but comment says 'only managers'


### 6. V013 — Original: **TP** | High | CWE-284
- **File**: `frontend/src/stores/userDataStore.ts:108-120`
- **OWASP**: A01 – Broken Access Control
- **Found by**: AI-CodeRabbit
- **Description**: Role predicates derive entirely from `effectiveRole`, which derives from `activeRole`/`roles` values that are read from `localStorage` at store initialization. Any JS running in the same origin (including XSS) can call `localStorage.setItem('roles', '["Admin"]')` and reload to assume any role. | High if these computed flags gate sensitive API calls or UI workflows without server-side re-…
- **Reviewer reasoning**: Frontend role predicates derived from localStorage values — client-side only security


### 7. V014 — Original: **TP** | High | CWE-269
- **File**: `frontend/src/views/pages/AdminUserEdit.vue:96`
- **OWASP**: A01 – Broken Access Control
- **Found by**: AI-CodeRabbit
- **Description**: `availableRoles` defaults to `['User', 'Admin', 'Worker']` and is populated from the backend with no client-side filtering. A manager-level user (role `CEO` or `Haldusjuht`) can check the `Admin` checkbox for any user, including themselves, and click "Update Roles". There is no `v-if` or programmatic filter preventing non-Admin managers from selecting the `Admin` role. | Exploitability is…
- **Reviewer reasoning**: AdminUserEdit availableRoles populated from backend but no client-side filtering


### 8. V015 — Original: **TP** | High | CWE-259
- **File**: `backend/App.DAL.EF/AppDbContextFactory.cs:13`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: `?? "Host=localhost;Port=5432;Database=puksiir;Username=postgres;Password=postgres"` — credentials committed in source | Any developer or CI pipeline that omits the env var silently connects using the hardcoded `postgres/postgres` credential; if the image is built without the env var set and the container exposes port 5432, the DB is reachable with the embedded password.
- **Reviewer reasoning**: AppDbContextFactory fallback: 'Username=postgres;Password=postgres' hardcoded in source


### 9. V016 — Original: **TP** | High | CWE-693
- **File**: `frontend/index.html:6`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: `script-src 'self' 'unsafe-inline'` in the CSP meta tag allows any inline `<script>` block to execute, completely negating XSS protection that CSP is meant to provide. | Any reflected or stored XSS that injects an inline `<script>` tag bypasses CSP entirely. Combined with the Vue SPA architecture, a successful XSS can steal Pinia store state (including auth tokens/roles), hijack the session, or…
- **Reviewer reasoning**: Frontend index.html contains CSP meta tag with 'unsafe-inline' — confirmed in source code


### 10. V017 — Original: **TP** | High | CWE-770
- **File**: `axios:1.9.0`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: SCA-DepCheck
- **Description**: CVE-2025-58754: Axios is a promise based HTTP client for the browser and Node.js. When Axios starting in version 0.28.0 and prior to versions 0.30.2 and 1.12.0 runs on Node.js and is given a URL with the `data:` scheme, it does not perform HTTP. Instead, its Node http adapter decodes the entire payload into memory
- **Reviewer reasoning**: axios:1.9.0 — CVE-2025-58754 (CWE-770) — request body not properly limited


### 11. V018 — Original: **TP** | High | CWE-754
- **File**: `axios:1.9.0`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: SCA-DepCheck
- **Description**: CVE-2026-25639: Axios is a promise based HTTP client for the browser and Node.js. Prior to versions 0.30.3 and 1.13.5, the mergeConfig function in axios crashes with a TypeError when processing configuration objects containing __proto__ as an own property. An attacker can trigger this by providing a malicious confi
- **Reviewer reasoning**: axios:1.9.0 — CVE-2026-25639 (CWE-754) — incomplete error handling


### 12. V019 — Original: **TP** | High | CWE-1035
- **File**: `backend/App.Domain/App.Domain.csproj:16`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: AI-CodeRabbit
- **Description**: Project targets net10.0 and references Microsoft.AspNetCore.Identity.EntityFrameworkCore 10.0.3, yet pins Microsoft.AspNetCore.Identity to 2.3.9 (released ~2018, ASP.NET Core 2.x era). This is a ~8 major-version gap. Multiple CVEs exist against the 2.x Identity stack. | The older Identity package may shadow or conflict with the 10.x EF Identity package's security fixes. Version resolution…
- **Reviewer reasoning**: Project targets net10.0 with mismatched Microsoft.AspNetCore.Identity.EF version — supply chain risk


### 13. V020 — Original: **TP** | High | CWE-674
- **File**: `flatted:3.3.3`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: SCA-DepCheck
- **Description**: CVE-2026-32141: flatted is a circular JSON parser. Prior to 3.4.0, flatted's parse() function uses a recursive revive() phase to resolve circular references in deserialized JSON. When given a crafted payload with deeply nested or self-referential $ indices, the recursion depth is unbounded, causing a stack overflow
- **Reviewer reasoning**: flatted:3.3.3 — CVE-2026-32141 (CWE-674) — recursive revive() stack overflow


### 14. V021 — Original: **TP** | High | CWE-1321
- **File**: `flatted:3.3.3`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: SCA-DepCheck
- **Description**: GHSA-rf6f-7fwh-wjgh: ---
  **Summary**

  The parse() function in flatted can use attacker-controlled string values from the parsed JSON as direct array index
  keys, without validating that they are numeric. Since the internal input buffer is a JavaScript Array, accessing it
  with the key "\_\_proto\_\_" returns Array
- **Reviewer reasoning**: flatted:3.3.3 — GHSA-rf6f-7fwh-wjgh (CWE-1321) — prototype pollution in parse()


### 15. V022 — Original: **FP** | High | CWE-78
- **File**: `glob:10.4.5`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: SCA-DepCheck
- **Description**: GHSA-5j98-mcp5-4vw2: ### Summary

The glob CLI contains a command injection vulnerability in its `-c/--cmd` option that allows arbitrary command execution when processing files with malicious names. When `glob -c <command> <patterns>` is used, matched filenames are passed to a shell with `shell: true`, enabling shell me
- **Reviewer reasoning**: glob version changed from 10.4.5 to 7.2.3 — vulnerability may be patched


### 16. V023 — Original: **TP** | High | CWE-1321
- **File**: `immutable:5.1.1`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: SCA-DepCheck
- **Description**: GHSA-wf6x-7x77-mvgw: ## Impact
_What kind of vulnerability is it? Who is impacted?_

A Prototype Pollution is possible in immutable via the mergeDeep(), mergeDeepWith(), merge(), Map.toJS(), and Map.toObject() APIs.

## Affected APIs

| API                                     | Notes
- **Reviewer reasoning**: immutable:5.1.1 — GHSA-wf6x-7x77-mvgw (CWE-1321) — prototype pollution


### 17. V024 — Original: **FP** | High | CWE-1333
- **File**: `minimatch:3.1.2`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: SCA-DepCheck
- **Description**: CVE-2026-26996: minimatch is a minimal matching utility for converting glob expressions into JavaScript RegExp objects. Versions 10.2.0 and below are vulnerable to Regular Expression Denial of Service (ReDoS) when a glob pattern contains many consecutive * wildcards followed by a literal character that doesn't appe
- **Reviewer reasoning**: minimatch version changed from 3.1.2 to 9.0.5 — vulnerability may be patched


### 18. V025 — Original: **FP** | High | CWE-407
- **File**: `minimatch:3.1.2`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: SCA-DepCheck
- **Description**: CVE-2026-27903: minimatch is a minimal matching utility for converting glob expressions into JavaScript RegExp objects. Prior to version 10.2.3, 9.0.7, 8.0.6, 7.4.8, 6.2.2, 5.1.8, 4.2.5, and 3.1.3, `matchOne()` performs unbounded recursive backtracking when a glob pattern contains multiple non-adjacent `**` (GLOBST
- **Reviewer reasoning**: minimatch version changed from 3.1.2 to 9.0.5 — vulnerability may be patched


### 19. V026 — Original: **TP** | High | CWE-1333
- **File**: `minimatch:9.0.5`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: SCA-DepCheck
- **Description**: CVE-2026-26996: minimatch is a minimal matching utility for converting glob expressions into JavaScript RegExp objects. Versions 10.2.0 and below are vulnerable to Regular Expression Denial of Service (ReDoS) when a glob pattern contains many consecutive * wildcards followed by a literal character that doesn't appe
- **Reviewer reasoning**: minimatch:9.0.5 — CVE-2026-26996 (CWE-1333) — ReDoS


### 20. V027 — Original: **TP** | High | CWE-407
- **File**: `minimatch:9.0.5`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: SCA-DepCheck
- **Description**: CVE-2026-27903: minimatch is a minimal matching utility for converting glob expressions into JavaScript RegExp objects. Prior to version 10.2.3, 9.0.7, 8.0.6, 7.4.8, 6.2.2, 5.1.8, 4.2.5, and 3.1.3, `matchOne()` performs unbounded recursive backtracking when a glob pattern contains multiple non-adjacent `**` (GLOBST
- **Reviewer reasoning**: minimatch:9.0.5 — CVE-2026-27903 (CWE-407) — algorithmic complexity DoS


### 21. V028 — Original: **TP** | High | CWE-22
- **File**: `rollup:4.40.1`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: SCA-DepCheck
- **Description**: CVE-2026-27606: Rollup is a module bundler for JavaScript. Versions prior to 2.80.0, 3.30.0, and 4.59.0 of the Rollup module bundler (specifically v4.x and present in current source) is vulnerable to an Arbitrary File Write via Path Traversal. Insecure file name sanitization in the core engine allows an attacker to
- **Reviewer reasoning**: rollup:4.40.1 — CVE-2026-27606 (CWE-22) — path traversal in module bundler


### 22. V029 — Original: **TP** | High | CWE-312
- **File**: `backend/App.DAL.DTO/Person.cs:17`
- **OWASP**: A04 – Cryptographic Failures
- **Found by**: AI-CodeRabbit
- **Description**: `Code` on a `Person` entity in this business context (vehicle/service management in what appears to be an Estonian codebase) is a national personal identification code (isikukood or equivalent). It is mapped in both directions (DTO↔Domain) as a bare string with only `[MaxLength(80)]`. No hashing, tokenisation, or `[JsonIgnore]` is applied. | Any API endpoint that returns a `Person` or embeds it…
- **Reviewer reasoning**: Person.Code (isikukood) stored and transmitted without encryption or masking


### 23. V030 — Original: **TP** | High | CWE-259
- **File**: `backend/App.DAL.EF/DataSeeding/InitialData.cs:21-27`
- **OWASP**: A04 – Cryptographic Failures
- **Found by**: AI-CodeRabbit
- **Description**: Plaintext passwords `"Foo.Bar.1"`, `"Foo.Bar.2"` hardcoded for six seed users including the `Admin` account; committed to version control. | Any repository reader (including future contributors, CI logs, or a leaked git history) obtains valid credentials for admin and named role accounts. The `Admin` account uses the same password (`Foo.Bar.1`) as four other accounts, broadening the blast radius…
- **Reviewer reasoning**: Plaintext passwords 'Foo.Bar.1', 'Foo.Bar.2' hardcoded for seed users including Admin


### 24. V031 — Original: **TP** | High | CWE-326
- **File**: `backend/Helpers/IdentityHelpers.cs:27-28`
- **OWASP**: A04 – Cryptographic Failures
- **Found by**: AI-CodeRabbit
- **Description**: No minimum key length validation before SymmetricSecurityKey is constructed. HMAC-SHA-512 requires at least 512 bits (64 bytes). A short UTF-8 key is padded internally by HMAC, but a weak secret still allows practical brute-force forgery. | If appsettings supplies a short or guessable JWT secret (e.g., "secret", "changeme"), an attacker can brute-force or guess the HMAC key and forge arbitrary…
- **Reviewer reasoning**: No minimum key length validation before SymmetricSecurityKey construction


### 25. V033 — Original: **TP** | High | CWE-312
- **File**: `backend/App.Domain/Models/Customer/Person.cs:18`
- **OWASP**: A06 – Insecure Design
- **Found by**: AI-CodeRabbit
- **Description**: `public string Code { get; set; } = default!;` — no [PersonalData], no column-level encryption hint, no masking annotation. In the Estonian context "Code" is the isikukood (national personal ID), a government-issued unique identifier classified as special-category data. | Any SQL injection, DB dump, EF query that inadvertently over-fetches, or misconfigured DTO serialization exposes the raw…
- **Reviewer reasoning**: Person.Code has no [PersonalData] attribute — no special handling for Estonian ID code


### 26. V034 — Original: **TP** | High | CWE-613
- **File**: `backend/Helpers/IdentityHelpers.cs:54`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-CodeRabbit
- **Description**: ValidateJwt sets ValidateLifetime = false while method name implies full validation. Unlike ValidateJwtIgnoreLifetime, this method has no documented intent to skip expiry. | Any expired token with a valid signature passes ValidateJwt. If the call-site relies on this method as the primary guard, replayed or stolen expired tokens remain valid indefinitely.
- **Reviewer reasoning**: IdentityHelpers.ValidateJwt sets ValidateLifetime=false — confirmed in source code


### 27. V037 — Original: **TP** | High | CWE-312
- **File**: `frontend/src/stores/userDataStore.ts:10-14, 17, 20, 23`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-CodeRabbit
- **Description**: All identity and session fields are read from and written to `localStorage`, which is accessible to any same-origin JavaScript including injected XSS payloads. | If any page in the application renders unsanitized user-controlled content (XSS), an attacker can exfiltrate the entire session identity including role assignments via `localStorage.getItem`. There is no integrity protection on the…
- **Reviewer reasoning**: All identity and session fields stored in localStorage — script-accessible


### 28. V038 — Original: **TP** | High | CWE-598
- **File**: `frontend/src/views/pages/auth/ResetPassword.vue:11-12`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-CodeRabbit
- **Description**: Password-reset token and user email address are read directly from URL query parameters and passed to the reset API call. URL query parameters appear in browser history, server access logs, proxy/CDN logs, and the HTTP `Referer` header when any resource on the success page is loaded. | An attacker with access to server logs, shared browser history, or an injected third-party resource that…
- **Reviewer reasoning**: Password reset token and email passed via URL query parameters (CWE-598)


### 29. V044 — Original: **TP** | Medium | CWE-915
- **File**: `backend/App.API/Mappers/RecentServiceApiMapper.cs:22-34`
- **OWASP**: A01 – Broken Access Control
- **Found by**: AI-CodeRabbit
- **Description**: The inbound `Map(App.DTO.v1.RecentService? dto)` direction maps five fully nested client-supplied objects into the BLL DTO alongside their FK IDs. Unlike all other mappers in this PR, `RecentServiceApiMapper` does not implement `IMapper<>` (no `Base.BLL.Contracts` reference), making it invisible to any type-checked registration or validation framework applied to typed mappers. | Same EF Core…
- **Reviewer reasoning**: RecentServiceApiMapper maps five fully nested client-supplied objects — mass assignment risk


### 30. V049 — Original: **TP** | Medium | CWE-284
- **File**: `backend/App.BLL.Contracts/IScheduleEntryService.cs:10-11`
- **OWASP**: A01 – Broken Access Control
- **Found by**: AI-CodeRabbit
- **Description**: HasOverlapAsync and GetOverlapDescriptionAsync both accept Guid? excludeId = null which bypasses a specific schedule entry in the conflict detection logic. A caller who knows any target scheduleEntryId can pass it as excludeId to suppress the conflict check for that entry. | If the excludeId is not validated against the calling user's ownership of that entry, an attacker can pass the ID of a…
- **Reviewer reasoning**: HasOverlapAsync accepts excludeId=null which bypasses overlap check


### 31. V052 — Original: **TP** | Medium | CWE-285
- **File**: `backend/App.DAL.EF/DataSeeding/AppDataInit.cs:72-80`
- **OWASP**: A01 – Broken Access Control
- **Found by**: AI-CodeRabbit
- **Description**: When `AddToRoleAsync` fails, the code iterates `roleResult.Errors` and writes each to `Console.WriteLine` but does **not** throw; execution continues silently. The user account is fully created (`CreateAsync` succeeded) but lacks its intended role(s). | On a first-deploy or re-seed, if role creation or assignment fails (e.g., role not yet committed, transient DB error), the user exists with zero…
- **Reviewer reasoning**: AddToRoleAsync failure logged to Console.WriteLine but does not throw — silent failure


### 32. V063 — Original: **TP** | Medium | CWE-540
- **File**: `backend/WebApp/appsettings.Development.json:9`
- **OWASP**: A01 – Broken Access Control
- **Found by**: AI-Claude
- **Description**: Hardcoded development database password (DevPassword123!) and JWT key in appsettings.Development.json
- **Reviewer reasoning**: appsettings.Development.json contains hardcoded DB password and JWT key


### 33. V068 — Original: **TP** | Medium | CWE-20
- **File**: `backend/App.API/Mappers/ScheduleEntryApiMapper.cs:30-32`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: `ParseHms` splits on `:` and calls `int.Parse` on each segment with no try/catch, no length check on `parts`, and no numeric range validation. An input such as `"99:xx"`, `":"`, or `""` produces an unhandled `FormatException` or `IndexOutOfRangeException` that propagates to the caller. | An unauthenticated or low-privilege caller submitting a malformed `StartTime`/`EndTime` string can crash…
- **Reviewer reasoning**: ParseHms splits on ':' with int.Parse — no try/catch, no length check, throws on bad input


### 34. V069 — Original: **TP** | Medium | CWE-400
- **File**: `backend/App.DAL.EF/Repositories/ScheduleEntryRepository.cs:44-57 (HasOverlapAsync), 64-76 (GetOverlapDescriptionAsync)`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: Both methods apply a user+date filter in SQL but then call `ToListAsync()` and perform `TimeSpan` overlap logic in-memory. A user account covering a long date range (e.g., spanning years) will load every matching `ScheduleEntry` row into memory. No `Take()` or pagination limit is applied. | An authenticated user who submits a request with `startDate` in the far past and `endDate` in the far…
- **Reviewer reasoning**: ScheduleEntryRepository loads all entries to memory for overlap check — unbounded query


### 35. V070 — Original: **TP** | Medium | CWE-400
- **File**: `backend/App.DAL.EF/Repositories/ServiceRepository.cs:138-152 (GetTopOrganisationRevenueThisMonthAsync)`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: The query fetches all services for the month with `Organisation` included via `ToListAsync()`, then calls `.GroupBy(s => s.Organisation!.Name)` in-memory. In a production system with high service volume, a single month's data could be thousands of rows loaded fully into server memory per request. | Any caller of the dashboard endpoint backed by this method triggers unbounded memory allocation.…
- **Reviewer reasoning**: ServiceRepository uses in-memory GroupBy after ToListAsync — full table loaded


### 36. V071 — Original: **TP** | Medium | CWE-1068
- **File**: `backend/App.Resources/Domain/Car/Vehicle.et.resx:41-43`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: `VehicleUseStart` (Line 41) = `"Kasutamise lõpp"` — the Estonian phrase for "End of use" — which is the exact same string as `VehicleUseEnd` (Line 38). The default-locale Vehicle.resx correctly distinguishes `"Start of use"` vs `"End of use"`. | In the Estonian locale, both date fields render the label "End of use", breaking the semantic contract between field name and displayed label. A user…
- **Reviewer reasoning**: VehicleUseStart resource maps to 'Kasutamise lõpp' (end) — wrong label


### 37. V072 — Original: **TP** | Medium | CWE-489
- **File**: `backend/App.Resources/Domain/Event/Service.resx:66-68`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: `Organisation` resource key holds the garbage placeholder value `"sdsd"` in the default locale; the corresponding Estonian locale file (`Service.et.resx`, Line 59) holds `"sdsdds"` — both are clearly unfinished debug/placeholder values committed to the resource layer | Any UI surface rendering this label will display junk text, confirming to an observer that the resource layer is in an…
- **Reviewer reasoning**: Organisation resource key holds garbage placeholder 'sdsd'


### 38. V073 — Original: **TP** | Medium | CWE-476
- **File**: `backend/App.Resources/Domain/Event/ServiceType.resx:21-27`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: - `ServiceType.Designer.cs` exposes properties `Comment`, `IsWashRelated`, `IsTowingRelated`, `ServicePrice` — none of these keys exist in `ServiceType.resx` (which only defines `Name` and `Description`). `ResourceManager.GetString` will return `null` for all four at runtime. - `OrganisationVehicle.Designer.cs` exposes `VehicleInOrganisation` and `VehicleOwner` — neither key exists in…
- **Reviewer reasoning**: ServiceType.Designer.cs exposes properties not present in .resx — build artifact mismatch


### 39. V074 — Original: **TP** | Medium | CWE-20
- **File**: `backend/Helpers/IdentityHelpers.cs:16`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: Guid.Parse throws FormatException for any non-GUID string. No try-parse or validation before the call. | If a token somehow carries a non-GUID sub claim (malformed token, mismatched identity provider, misconfigured issuer), the unhandled FormatException propagates up the call stack. Depending on the exception handling middleware this can cause a 500 response that leaks stack trace detail or…
- **Reviewer reasoning**: Guid.Parse throws FormatException for non-GUID — no try-parse validation before call


### 40. V079 — Original: **TP** | Medium | CWE-20
- **File**: `backend/WebApp/appsettings.json:11`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: `"AllowedHosts": "*"` disables ASP.NET Core's host-header filtering middleware entirely. Combined with `options.Issuer` being derived from `JWTSecurity:Issuer` (a static string), the primary risk is HTTP Host header injection in password-reset and email-confirmation link generation, which uses `Request.Scheme` + host. | An attacker can send a request with a spoofed `Host:` header; if the…
- **Reviewer reasoning**: Server accepted request with Host: evil.attacker.com (HTTP 200) but spoofed value was not reflected in response body or Location header; permissive host acceptance is a misconfiguration risk (cache/reset-link poisoning behind reverse proxy) but no exploitable sink demonstrated in this test run


### 41. V080 — Original: **TP** | Medium | CWE-1021
- **File**: `frontend/index.html:6`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: `frame-ancestors 'none'` is declared inside a `<meta http-equiv="Content-Security-Policy">` tag. Per the CSP Level 3 specification, the `frame-ancestors` directive is **not** processed when CSP is delivered via a meta tag — it is silently ignored by all compliant browsers. | The application can be embedded in an attacker-controlled `<iframe>` or `<frame>`. An attacker can overlay transparent UI…
- **Reviewer reasoning**: frame-ancestors declared via <meta> tag in index.html source — ineffective per CSP Level 3 spec


### 42. V081 — Original: **TP** | Medium | CWE-79
- **File**: `frontend/src/plugins/axiosInterceptor.ts:74-76`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: `if (!detail && typeof data === 'string' && data.length < 200) { detail = data; }` passes server-controlled string content directly to the toast detail without HTML-escaping. PrimeVue Toast v4 renders `detail` via `v-html` on some configurations or custom slot overrides. | If the backend ever returns HTML/script fragments in a 4xx/5xx body (e.g., from a proxy, WAF, or misconfigured ASP.NET error…
- **Reviewer reasoning**: axiosInterceptor passes server-controlled string directly to toast notification


### 43. V082 — Original: **TP** | Medium | CWE-20
- **File**: `frontend/src/stores/userDataStore.ts:14`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: `const roles = ref<string[]>(JSON.parse(localStorage.getItem('roles') || '[]'));` — if localStorage is manually edited or corrupted to a non-JSON string, this throws an unhandled `SyntaxError` at store initialization, crashing the application before any auth check runs. | Attacker with physical access or any XSS that writes a malformed value can cause a persistent denial-of-service (application…
- **Reviewer reasoning**: JSON.parse on localStorage 'roles' without try/catch — throws on corrupt data


### 44. V084 — Original: **TP** | Medium | CWE-79
- **File**: `@intlify/core-base:11.1.3`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: SCA-DepCheck
- **Description**: GHSA-x8qp-wqqm-57ph: ### Summary
The escapeParameterHtml: true option in Vue I18n is designed to protect against HTML/script injection by escaping interpolated parameters. However, this setting fails to prevent execution of certain tag-based payloads, such as `<img src=x onerror=...>`, if the interpolated value is inser
- **Reviewer reasoning**: @intlify/core-base:11.1.3 — XSS bypass in escapeParameterHtml — GHSA-x8qp-wqqm-57ph


### 45. V085 — Original: **TP** | Medium | CWE-400
- **File**: `ajv:6.12.6`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: SCA-DepCheck
- **Description**: GHSA-2g4f-4pwh-qvx6: ajv (Another JSON Schema Validator) through version 8.17.1 is vulnerable to Regular Expression Denial of Service (ReDoS) when the `$data` option is enabled. The pattern keyword accepts runtime data via JSON Pointer syntax (`$data` reference), which is passed directly to the JavaScript `RegExp()` con
- **Reviewer reasoning**: ajv:6.12.6 — GHSA-2g4f-4pwh-qvx6 (CWE-400) — ReDoS


### 46. V086 — Original: **TP** | Medium | CWE-1321
- **File**: `js-yaml:4.1.0`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: SCA-DepCheck
- **Description**: GHSA-mh29-5h37-fv8m: ### Impact

In js-yaml 4.1.0, 4.0.0, and 3.14.1 and below, it's possible for an attacker to modify the prototype of the result of a parsed yaml document via prototype pollution (`__proto__`). All users who parse untrusted yaml documents may be impacted.

### Patches

Problem is patched in js-yaml 4.
- **Reviewer reasoning**: js-yaml:4.1.0 — GHSA-mh29-5h37-fv8m (CWE-1321) — prototype pollution


### 47. V087 — Original: **TP** | Medium | CWE-1321
- **File**: `lodash:4.17.21`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: SCA-DepCheck
- **Description**: CVE-2025-13465: Lodash versions 4.0.0 through 4.17.22 are vulnerable to prototype pollution in the _.unset and _.omit functions. An attacker can pass crafted paths which cause Lodash to delete methods from global prototypes.

The issue permits deletion of properties but does not allow overwriting their original beh
- **Reviewer reasoning**: lodash:4.17.21 — CVE-2025-13465 (CWE-1321) — prototype pollution via _.unset


### 48. V088 — Original: **TP** | Medium | CWE-22
- **File**: `vite:6.3.4`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: SCA-DepCheck
- **Description**: GHSA-93m4-6634-74q7: ### Summary
Files denied by [`server.fs.deny`](https://vitejs.dev/config/server-options.html#server-fs-deny) were sent if the URL ended with `\` when the dev server is running on Windows.

### Impact
Only apps that match the following conditions are affected:

- explicitly exposes the Vite dev serve
- **Reviewer reasoning**: vite:6.3.4 — GHSA-93m4-6634-74q7 (CWE-22) — server.fs.deny bypass


### 49. V089 — Original: **TP** | Medium | CWE-79
- **File**: `vue-i18n:11.1.3`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: SCA-DepCheck
- **Description**: GHSA-x8qp-wqqm-57ph: ### Summary
The escapeParameterHtml: true option in Vue I18n is designed to protect against HTML/script injection by escaping interpolated parameters. However, this setting fails to prevent execution of certain tag-based payloads, such as `<img src=x onerror=...>`, if the interpolated value is inser
- **Reviewer reasoning**: vue-i18n:11.1.3 — XSS bypass in escapeParameterHtml — GHSA-x8qp-wqqm-57ph


### 50. V090 — Original: **TP** | Medium | CWE-321
- **File**: `backend/.env:5`
- **OWASP**: A04 – Cryptographic Failures
- **Found by**: AI-Claude
- **Description**: JWT signing key stored in .env cleartext file. If .env leaks, all JWT tokens can be forged.
- **Reviewer reasoning**: JWT signing key stored in cleartext .env file — if leaked, all tokens forgeable


### 51. V091 — Original: **FP** | Medium | CWE-338
- **File**: `backend/Base.Domain/BaseRefreshToken.cs:13`
- **OWASP**: A04 – Cryptographic Failures
- **Found by**: AI-CodeRabbit
- **Description**: Guid.NewGuid().ToString() produces a 36-character string with approximately 122 bits of entropy. While .NET's Guid.NewGuid() uses a CSPRNG on modern platforms, the format leaks version/variant bits and is not the recommended approach for security tokens. The [MaxLength(64)] constraint permits stronger tokens but the default never uses the available space. | Low on current .NET runtime (CSPRNG-…
- **Reviewer reasoning**: Guid.NewGuid() provides 122 bits entropy — sufficient for refresh token uniqueness


### 52. V092 — Original: **TP** | Medium | CWE-798
- **File**: `backend/WebApp/Program.cs:306-308`
- **OWASP**: A04 – Cryptographic Failures
- **Found by**: AI-Claude, AI-CodeRabbit
- **Description**: Hardcoded development user passwords (CeoDev123!, PuksDev123!, PesulaDev123!) in source code, guarded by IsDevelopment().
- **Reviewer reasoning**: Hardcoded dev passwords (CeoDev123!, PuksDev123!, PesulaDev123!) in Program.cs source


### 53. V094 — Original: **TP** | Medium | CWE-321
- **File**: `backend/WebApp/appsettings.Development.json:8`
- **OWASP**: A04 – Cryptographic Failures
- **Found by**: AI-Claude
- **Description**: Hardcoded JWT signing key DevOnlyKey_CHANGE_IN_PRODUCTION... in development config. Key should never be in source-controlled config files.
- **Reviewer reasoning**: Hardcoded JWT key in appsettings.Development.json — key in source control


### 54. V095 — Original: **TP** | Medium | CWE-598
- **File**: `frontend/src/plugins/axiosInterceptor.ts:80`
- **OWASP**: A04 – Cryptographic Failures
- **Found by**: AI-CodeRabbit
- **Description**: `detail = \`${method} ${url}\` + (status ? \` → HTTP ${status}\` : '');` embeds the full request URL verbatim into the user-visible toast detail string when no richer error body is available. Endpoints such as `confirmEmail?userId=...&token=...` or any route that carries auth tokens or PII in the query string will surface those values in the UI toast. | Any failed request to a URL carrying…
- **Reviewer reasoning**: Full request URL embedded in error detail string — may leak sensitive URL params


### 55. V096 — Original: **TP** | Medium | CWE-918
- **File**: `backend/App.DAL.DTO/Model.cs:19`
- **OWASP**: A05 – Injection
- **Found by**: AI-CodeRabbit
- **Description**: `ImageUrl` accepts an arbitrary string constrained only by `[MaxLength(160)]`. No URL scheme validation (`http`/`https` only), no hostname whitelist, and no validation attribute (e.g. `[Url]`) is applied. This is a known SSRF entry-point pattern in DAL DTOs when the stored URL is later fetched server-side. | Confidence is Low because reachability depends on whether upper layers consume `ImageUrl`…
- **Reviewer reasoning**: Model.ImageUrl accepts arbitrary string with only MaxLength — no URL scheme validation


### 56. V097 — Original: **TP** | Medium | CWE-288
- **File**: `backend/Helpers/UserNameResolver.cs:14-15`
- **OWASP**: A05 – Injection
- **Found by**: AI-CodeRabbit
- **Description**: When HttpContext is null (background jobs, test harness, scheduled tasks) or user is unauthenticated, the property silently returns the hardcoded string "system" instead of throwing or returning a sentinel that callers can explicitly handle. | If any downstream layer grants elevated trust to records where CreatedBy == "system" (admin dashboards, audit reports, bypass logic), an unauthenticated…
- **Reviewer reasoning**: UserNameResolver silently returns 'System' when HttpContext null — audit trail gap


### 57. V098 — Original: **TP** | Medium | CWE-20
- **File**: `frontend/src/composables/useServiceForm.ts:218-222`
- **OWASP**: A05 – Injection
- **Found by**: AI-CodeRabbit
- **Description**: `servedVehicleRegNumber: !isKnownVehicle && servedVehicleInput.value ? servedVehicleInput.value : null` sends the raw, unvalidated text-input value as a vehicle registration number field. No length limit, format check (e.g., regex for license plate format), or character allowlist is applied before the value is serialized into the request payload. | If the backend stores and later renders this…
- **Reviewer reasoning**: servedVehicleRegNumber sent raw without sanitization or validation


### 58. V099 — Original: **TP** | Medium | CWE-682
- **File**: `backend/App.Domain/Models/Event/Service.cs:24`
- **OWASP**: A06 – Insecure Design
- **Found by**: AI-CodeRabbit
- **Description**: `public double PriceNoVat { get; set; }` — IEEE 754 double-precision floating point cannot represent most decimal fractions exactly. Same issue in ServiceLine.PriceNoVat (ServiceLine.cs, line 13). ServiceType.ServicePrice correctly uses `decimal` (ServiceType.cs, line 15), creating an inconsistency that will cause rounding errors at the boundary. | Arithmetic errors accumulate across service…
- **Reviewer reasoning**: Service.PriceNoVat uses IEEE 754 double — rounding errors for monetary values


### 59. V100 — Original: **FP** | Medium | CWE-284
- **File**: `backend/App.Domain/Models/Identity/AppRefreshToken.cs:11`
- **OWASP**: A06 – Insecure Design
- **Found by**: AI-CodeRabbit
- **Description**: `public DateTime SessionStartedAt { get; set; } = DateTime.UtcNow;` — the XML doc comment states "set once at login, never updated on refresh", but the property has a public setter, making it trivially overwritable by any code path including token refresh handlers, model binders, or bulk-update EF operations. | If a token refresh handler inadvertently writes to this field (e.g., via an EF Update…
- **Reviewer reasoning**: AppRefreshToken.SessionStartedAt set at login is informational, not exploitable


### 60. V101 — Original: **TP** | Medium | CWE-312
- **File**: `backend/App.Domain/Models/Identity/AppUser.cs:8-9`
- **OWASP**: A06 – Insecure Design
- **Found by**: AI-CodeRabbit
- **Description**: `[MaxLength(128)] public string FirstName { get; set; }` and `LastName` — neither carries `[PersonalData]` attribute. ASP.NET Core Identity's built-in GDPR support (IPersonalDataProtector, DownloadPersonalDataAsync, DeletePersonalDataAsync) only operates on properties decorated with [PersonalData]. Same gap exists on Person.FirstName (line 12), Person.LastName (line 15), Person.Email (line 22),…
- **Reviewer reasoning**: AppUser FirstName/LastName lack [PersonalData] attribute — PII not marked for GDPR


### 61. V104 — Original: **FP** | Medium | CWE-319
- **File**: `backend/App.DTO/v1/Identity/RefreshTokenModel.cs:5`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-CodeRabbit
- **Description**: `JWTResponse.cs` Line 5 contains the comment "JWT and refresh token are delivered via HttpOnly cookies, not in the response body." However, `RefreshTokenModel` accepts a raw `Jwt` string field from the request body. This is architecturally inconsistent: if JWTs are issued as HttpOnly cookies, the refresh endpoint should read the JWT from the cookie (automatically sent by the browser), not from a…
- **Reviewer reasoning**: JWTResponse comment about cookie delivery is informational documentation


### 62. V106 — Original: **TP** | Medium | CWE-640
- **File**: `backend/WebApp/ApiControllers/Identity/AdminUsersController.cs:178`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-Claude
- **Description**: Admin password reset sends new plaintext password via email. Password transmitted in cleartext HTML email body.
- **Reviewer reasoning**: Admin password reset sends new plaintext password in HTML email body


### 63. V107 — Original: **TP** | Medium | CWE-613
- **File**: `frontend/src/stores/userDataStore.ts:97-104`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-CodeRabbit
- **Description**: Both `sessionStart` and `lastActivity` are stored in and read from `localStorage`. The `isSessionValid()` function compares `Date.now()` against these values. An attacker or the user can set `localStorage.setItem('sessionStart', Date.now())` to reset the absolute session clock at will, defeating `MAX_SESSION_MS` enforcement. | Any XSS payload or privileged browser extension can extend or reset…
- **Reviewer reasoning**: Session timeout check uses localStorage timestamps — client-side only enforcement


### 64. V108 — Original: **TP** | Medium | CWE-521
- **File**: `frontend/src/views/pages/auth/Register.vue:10-25`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-CodeRabbit
- **Description**: The registration form performs zero client-side password validation before submitting. No minimum length, no complexity requirement, no strength feedback (`<Password>` component renders with `toggleMask` but no `strongRegex` or `promptLabel`). An empty string password is accepted and forwarded to the API. | Users can register with trivially weak passwords (e.g., a single character or empty string…
- **Reviewer reasoning**: Registration form has zero client-side password validation before submit


### 65. V113 — Original: **TP** | Medium | CWE-681
- **File**: `backend/App.DAL.DTO/Service.cs:16`
- **OWASP**: A08 – Integrity Failures
- **Found by**: AI-CodeRabbit
- **Description**: `public double PriceNoVat { get; set; }` uses a binary floating-point type for a monetary amount. The same defect is present in `backend/App.DAL.DTO/ServiceLine.cs` Line 11 (`public double PriceNoVat { get; set; }`). Floating-point arithmetic cannot represent all decimal fractions exactly, introducing rounding errors that accumulate across VAT calculations, discounts, and line-item summation. |…
- **Reviewer reasoning**: Service DAL DTO uses double for PriceNoVat — same issue as V099


### 66. V115 — Original: **TP** | Medium | CWE-20
- **File**: `backend/App.DAL.EF/Mappers/ScheduleEntryMapper.cs:19`
- **OWASP**: A08 – Integrity Failures
- **Found by**: AI-CodeRabbit
- **Description**: In .NET, casting an arbitrary `int` to an `enum` does not throw even when the value is outside the defined enum members — the result is an enum variable holding an undefined numeric value. `DTO.ScheduleEntry.EntryType` has no `[Range]` attribute. The same unchecked cast pattern exists in: - `ScheduleMapper.cs` Line 16: `(Domain.Models.EScheduleType)dalEntity.ScheduleType` -…
- **Reviewer reasoning**: ScheduleEntryMapper casts int to enum without validation — undefined values accepted


### 67. V118 — Original: **TP** | Medium | CWE-915
- **File**: `backend/WebApp/Areas/Admin/Controllers/AuthorityTypesController.cs:43`
- **OWASP**: A08 – Integrity Failures
- **Found by**: AI-CodeRabbit
- **Description**: `[Bind("AuthorityTypeName,CreatedBy,CreatedAt,UpdatedBy,UpdatedAt,Id")]` allows client-controlled audit fields `CreatedBy`, `CreatedAt`, `UpdatedBy`, `UpdatedAt` to be written directly to the database. | An Admin user (or anyone who can reach the endpoint — see Finding 1 for related controllers) can forge audit timestamps and attribution by crafting the POST body, breaking audit-trail integrity.
- **Reviewer reasoning**: [Bind] attribute includes CreatedBy/UpdatedBy audit fields — POST accepted but server overrides values; source-level mass assignment risk confirmed in code review


### 68. V119 — Original: **TP** | Medium | CWE-778
- **File**: `backend/WebApp/ApiControllers/Identity/AdminUsersController.cs`
- **OWASP**: A09 – Logging Failures
- **Found by**: AI-Claude
- **Description**: No security logging in AdminUsersController — admin operations (role changes, password resets, user unlocks) have no audit trail.
- **Reviewer reasoning**: AdminUsersController has no security logging for role changes, password resets, user unlocks


### 69. V120 — Original: **TP** | Medium | CWE-532
- **File**: `frontend/src/stores/notificationStore.ts:34`
- **OWASP**: A09 – Logging Failures
- **Found by**: AI-CodeRabbit
- **Description**: `logFn(..., notification.requestUrl ?? '')` unconditionally logs internal API request URLs and HTTP status codes to the browser console for every notification, including errors. API paths may reveal internal service topology, versioning, or resource identifiers. | Browser console output is readable by any JS in the same origin (e.g., third-party analytics scripts, browser extensions, XSS…
- **Reviewer reasoning**: notificationStore logs internal API URLs and HTTP status codes to browser console


### 70. V121 — Original: **TP** | Low | CWE-540
- **File**: `backend/.env:2`
- **OWASP**: A01 – Broken Access Control
- **Found by**: AI-Claude
- **Description**: .env file contains cleartext credentials (DB password, JWT key, admin password). .gitignore excludes .env, but file present in testing fork.
- **Reviewer reasoning**: .env file contains cleartext DB password, JWT key, admin password


### 71. V122 — Original: **FP** | Low | CWE-284
- **File**: `backend/App.BLL.DTO/Authority.cs:31`
- **OWASP**: A01 – Broken Access Control
- **Found by**: AI-CodeRabbit
- **Description**: `//public bool IsActive { get; set; }` is commented out (Line 31). The only validity signal remaining is `ValidFrom`/`ValidUntil`. If consumers of this DTO do not explicitly check `ValidUntil >= DateTime.UtcNow`, expired authority records remain operationally active. | Uncertain without seeing the API controller and authorization filter layers (out of scope for this diff). Flagged as Info-…
- **Reviewer reasoning**: Authority.IsActive commented out is a design decision, not a security vulnerability


### 72. V125 — Original: **TP** | Low | CWE-200
- **File**: `frontend/src/domain/puksiir/IAppUser.ts:6-7`
- **OWASP**: A01 – Broken Access Control
- **Found by**: AI-CodeRabbit
- **Description**: The `IAppUser` interface surfaces account lockout state (`isLockedOut`, `lockoutEnd`) to the frontend. If this model is used to render admin user-management views, the data exposure is intentional. If it is included in general user profile API responses accessible to non-admin roles, it constitutes information disclosure about other accounts. | Depends entirely on which API endpoint returns…
- **Reviewer reasoning**: IAppUser interface surfaces isLockedOut/lockoutEnd to frontend — information disclosure


### 73. V126 — Original: **FP** | Low | CWE-639
- **File**: `frontend/src/service/puksiir/OrganisationApiService.ts:20`
- **OWASP**: A01 – Broken Access Control
- **Found by**: AI-CodeRabbit
- **Description**: `async getServices(organisationId: string): Promise<unknown[]>` interpolates `organisationId` directly into the URL path with no UUID-format validation on the client side. A non-GUID string could modify the effective path (e.g., `../../adminEndpoint`). | Path traversal impact depends on backend routing strictness. If the backend route matches on the full segment and validates UUID format, this is…
- **Reviewer reasoning**: Interpolating organisationId into URL path is normal API call pattern, not injection


### 74. V127 — Original: **TP** | Low | CWE-922
- **File**: `frontend/src/stores/userDataStore.ts:10-17`
- **OWASP**: A01 – Broken Access Control
- **Found by**: AI-Claude
- **Description**: User identity data (userId, firstName, lastName, roles, activeRole) stored in localStorage. Role data can be tampered client-side. Server-side enforcement present.
- **Reviewer reasoning**: localStorage role data can be tampered — same issue family as V013


### 75. V128 — Original: **TP** | Low | CWE-284
- **File**: `frontend/src/views/pages/OrganisationDetail.vue:12`
- **OWASP**: A01 – Broken Access Control
- **Found by**: AI-CodeRabbit
- **Description**: The edit button `<Button :label="t('edit')" icon="pi pi-pencil" severity="secondary" `@click`="router.push({ name: 'organisationedit', params: { id } })" />` has no `v-if="userStore.isManager"` guard. All 19 other write-action buttons in the reviewed files use a `v-if` role check. The `beforeEach` guard on `organisationedit` will redirect non-managers to `unauthorized`, so there is no actual data…
- **Reviewer reasoning**: Organisation edit button visible to non-managers — client-side rendering only check


### 76. V129 — Original: **TP** | Low | CWE-284
- **File**: `backend/App.DAL.EF/DataSeeding/AppDataInit.cs:18-21`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: `public static void DeleteDatabase(AppDbContext context)` is a public, parameter-only method with no environment check, caller-identity check, or guard flag. Any code path that obtains an `AppDbContext` can invoke it unconditionally. | If this method is accidentally wired into a production startup path (e.g., a mis-configured environment flag in `Program.cs`), the entire database is permanently…
- **Reviewer reasoning**: DeleteDatabase is public static with no environment check — callable from any context


### 77. V130 — Original: **FP** | Low | CWE-1068
- **File**: `backend/App.Resources/App.Resources.csproj:14-17`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: The csproj references `Domain\Customer\Authority.Designer.cs` (dependent on `Authority.resx`), but the actual files in the repository are `AuthorityType.Designer.cs` and `AuthorityType.resx`. No `Authority.resx` or `Authority.Designer.cs` file exists. | The `DesignTime=True` / `AutoGen=True` metadata is applied to a non-existent file path, meaning the actual `AuthorityType.Designer.cs` is not…
- **Reviewer reasoning**: csproj resource file path mismatch is a build issue, not a security vulnerability


### 78. V131 — Original: **FP** | Low | CWE-561
- **File**: `backend/App.Resources/Domain/Event/ServiceType.resx:24-26 (Description key)`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: - `ServiceType.resx` / `ServiceType.et.resx` define key `Description` — not exposed by `ServiceType.Designer.cs` - `OrganisationVehicle.resx` / `OrganisationVehicle.et.resx` define keys `OrganisationId` and `VehicleId` — not exposed by `OrganisationVehicle.Designer.cs` - `Service.resx` / `Service.et.resx` define key `Organisation` (with garbage value `"sdsd"`) — not exposed by…
- **Reviewer reasoning**: Unused resource keys in Designer.cs are build artifacts, not security issues


### 79. V132 — Original: **FP** | Low | CWE-1188
- **File**: `backend/Helpers/IdentityHelpers.cs:8`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: JwtSecurityTokenHandler maintains a mutable InboundClaimTypeMap dictionary and an internal token cache. A static instance shares this state across concurrent requests and DI lifetimes. | Low direct security impact in read-only usage, but if any downstream code mutates JwtHandler.InboundClaimTypeMap (e.g., to disable the standard claim type remapping), the change applies globally and can silently…
- **Reviewer reasoning**: Static JwtSecurityTokenHandler is thread-safety concern, not a security vulnerability


### 80. V134 — Original: **FP** | Low | CWE-703
- **File**: `backend/WebApp/ApiControllers/ScheduleEntryApiController.cs:65-72`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: `GetMy` extracts the user ID with `?? throw new UnauthorizedAccessException()`. `[Authorize]` ensures a valid JWT is present but does not guarantee the `sub` claim exists (e.g., non-standard token issuers, misconfigured claim mappings). If the claim is absent, a raw `UnauthorizedAccessException` is thrown rather than a proper `401 Unauthorized` HTTP response, resulting in a 500 error and…
- **Reviewer reasoning**: UnauthorizedAccessException in GetMy is proper authorization check, not a vulnerability


### 81. V136 — Original: **TP** | Low | CWE-390
- **File**: `backend/WebApp/Areas/Admin/Controllers/ServicesController.cs:82-84`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: The `catch` clause is bare (catches `System.Exception` and all subclasses), not `catch (DbUpdateConcurrencyException)`. This means transient DB errors, connection failures, or infrastructure exceptions are all routed through the exists-check path before rethrowing. During the `ExistsAsync` call inside an already-failed exception context, a second DB failure could produce an unhandled nested…
- **Reviewer reasoning**: Bare catch(Exception) in ServicesController — swallows all errors including security-relevant ones


### 82. V137 — Original: **TP** | Low | CWE-1021
- **File**: `backend/WebApp/Areas/Admin/Views/Services/Create.cshtml:14 (primary; same pattern in OrganisationVehicles/Create.cshtml:15, Vehicles/Create.cshtml:15)`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: Foreign-key dropdown fields (`VatId`, `PersonId`, `ServiceTypeId`, `ServerPersonId`, `ServedVehicleId`, `ServerVehicleId`, `OrganisationId`, `VehicleId`, `ModelId`) in Create and Edit forms do not have corresponding `<span asp-validation-for="...">` tags. Client-side validation feedback for these fields is absent, meaning a user submitting an invalid (out-of-range or injected) FK value receives…
- **Reviewer reasoning**: Admin create/edit views expose FK dropdown IDs — information disclosure of internal GUIDs


### 83. V138 — Original: **FP** | Low | CWE-209
- **File**: `backend/WebApp/Areas/Admin/Views/Services/Index.cshtml:47 (primary; same null-forgiving pattern in Services/Details.cshtml:16, Services/Delete.cshtml:17, Vehicles/Index.cshtml:45, OrganisationVehicles/Index.cshtml:33, OrganisationVehicles/Details.cshtml:16)`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: The `!` null-forgiving operator is used extensively on navigation properties throughout the Services, Vehicles, and OrganisationVehicles views. If the database record has a null FK/navigation property (e.g., orphaned service record), ASP.NET Core will throw an unhandled `NullReferenceException`. If detailed error pages are enabled (developer exception page), this can leak stack traces, model type…
- **Reviewer reasoning**: Null-forgiving operator (!) is NRE risk, not a security vulnerability


### 84. V139 — Original: **TP** | Low | CWE-200
- **File**: `backend/WebApp/Areas/Admin/Views/Services/Index.cshtml:47`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: `Services/Index.cshtml` renders `ServedPerson!.Code` for every row in the list table. `Services/Details.cshtml` (Line 22) and `Services/Delete.cshtml` (Line 20) also expose this field. The field name `Code` in a person/customer context commonly represents a national/personal identification number or government-issued identifier. | Any user with read access to the Admin/Services/Index, Details, or…
- **Reviewer reasoning**: Services Index/Details renders Person.Code (isikukood) — PII exposed in admin UI


### 85. V140 — Original: **TP** | Low | CWE-400
- **File**: `frontend/src/stores/notificationStore.ts:36`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: The `pending` array has no maximum length guard. If `drain()` is never called (e.g., the `App.vue` watcher fails to mount or is conditionally unmounted), the array grows without bound for every API call. | In practice, exploitation requires a condition where `drain()` never fires combined with a high API call rate. More likely a reliability issue than a security one, but memory exhaustion could…
- **Reviewer reasoning**: Notification pending array has no max length — memory exhaustion vector


### 86. V141 — Original: **TP** | Low | CWE-16
- **File**: `frontend/src/views/pages/NotFound.vue:2`
- **OWASP**: A02 – Security Misconfiguration
- **Found by**: AI-CodeRabbit
- **Description**: The catch-all route (`notfound`) has no `requiresAuth: true` meta. `NotFound.vue` unconditionally imports and renders `FloatingConfigurator`. Depending on what `FloatingConfigurator` exposes (theme selector, layout config, etc.), this component is reachable by unauthenticated visitors at any 404 URL. | Impact depends on `FloatingConfigurator`'s capabilities (not visible in this PR). If it only…
- **Reviewer reasoning**: NotFound page renders FloatingConfigurator without requiresAuth — config exposed


### 87. V143 — Original: **FP** | Low | CWE-1000
- **File**: `backend/App.BLL/AppBLL.cs:33, 82`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: AI-CodeRabbit
- **Description**: OrganisationService is initialised as `new OrganisationService(BLLUOW, new OrganisationBLLMapper(), this)` and ServiceService as `new ServiceService(BLLUOW, new ServiceBLLMapper(), this)`. Passing the parent AppBLL creates a circular dependency at construction time. Any of the 14 sibling services exposed through IAppBLL become reachable from within OrganisationService and ServiceService, widening…
- **Reviewer reasoning**: AppBLL circular dependency is code smell, not a security vulnerability


### 88. V144 — Original: **TP** | Low | CWE-830
- **File**: `backend/WebApp/Program.cs:215`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: AI-Claude
- **Description**: CSP style-src and font-src directives whitelist https://fonts.cdnfonts.com — external dependency without SRI. Repeat of #17 from CSP perspective.
- **Reviewer reasoning**: CSP whitelists https://fonts.cdnfonts.com without SRI — external dependency risk


### 89. V145 — Original: **FP** | Low | CWE-400
- **File**: `brace-expansion:1.1.11`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: SCA-DepCheck
- **Description**: GHSA-v6h2-p8h4-qcjw: A vulnerability was found in juliangruber brace-expansion up to 1.1.11/2.0.1/3.0.0/4.0.0. It has been rated as problematic. Affected by this issue is the function expand of the file index.js. The manipulation leads to inefficient regular expression complexity. The attack may be launched remotely. Th
- **Reviewer reasoning**: brace-expansion version changed from 1.1.11 to 2.0.1 — vulnerability may be patched


### 90. V146 — Original: **TP** | Low | CWE-830
- **File**: `frontend/index.html:9`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: AI-Claude
- **Description**: External font stylesheet loaded from https://fonts.cdnfonts.com/css/lato without integrity attribute (no Subresource Integrity).
- **Reviewer reasoning**: External font stylesheet from cdnfonts.com loaded without integrity attribute


### 91. V147 — Original: **TP** | Low | CWE-23
- **File**: `vite:6.3.4`
- **OWASP**: A03 – Supply Chain Failures
- **Found by**: SCA-DepCheck
- **Description**: CVE-2025-58752: Vite is a frontend tooling framework for JavaScript. Prior to versions 7.1.5, 7.0.7, 6.3.6, and 5.4.20, any HTML files on the machine were served regardless of the `server.fs` settings. Only apps that explicitly expose the Vite dev server to the network (using --host or server.host config option) an
- **Reviewer reasoning**: vite:6.3.4 — CVE-2025-58752 (CWE-23) — relative path traversal


### 92. V148 — Original: **FP** | Low | CWE-319
- **File**: `compose.yaml:50`
- **OWASP**: A04 – Cryptographic Failures
- **Found by**: AI-CodeRabbit
- **Description**: The frontend Vite dev server uses an unencrypted `http://` URL to reach the backend. Within a single Docker Compose network this is an internal bridge network with no inter-host exposure. However, if the Compose stack is deployed across hosts (Docker Swarm, cloud overlay networks), traffic traverses the network unencrypted. | Low in single-host Docker Compose deployments. Elevated if orchestrated…
- **Reviewer reasoning**: HTTP between Docker containers is internal network — acceptable in compose


### 93. V149 — Original: **FP** | Low | CWE-256
- **File**: `frontend/src/types/RegisterDto.ts:3`
- **OWASP**: A04 – Cryptographic Failures
- **Found by**: AI-CodeRabbit
- **Description**: `RegisterDto` carries `password` as a plain `string`. The risk is not in the interface itself but in how it is used: if this DTO is ever serialized to `localStorage`, logged (e.g., via the `notificationStore`), or sent over non-TLS transport, the password is exposed in cleartext. | Low in isolation (interface only), but the combination with the console-logging pattern in `notificationStore` and…
- **Reviewer reasoning**: RegisterDto carrying password as string is standard DTO pattern, HTTPS assumed


### 94. V150 — Original: **TP** | Low | CWE-20
- **File**: `frontend/src/service/puksiir/ServiceApiService.ts:95`
- **OWASP**: A05 – Injection
- **Found by**: AI-CodeRabbit
- **Description**: `async getDashboardRevenueDaily(startDate: string, endDate: string)` interpolates both parameters directly into the query string without ISO-8601 format validation. TypeScript types alone do not enforce format at runtime. | If an attacker controls the call site (e.g., via URL manipulation triggering a component that reads date params from the route), arbitrary characters can be injected into the…
- **Reviewer reasoning**: ServiceApiService interpolates date strings directly into query params


### 95. V151 — Original: **TP** | Low | CWE-20
- **File**: `backend/App.Domain/Models/Customer/Authority.cs:19-20`
- **OWASP**: A06 – Insecure Design
- **Found by**: AI-CodeRabbit
- **Description**: `public DateTime ValidFrom { get; set; }` / `public DateTime? ValidUntil { get; set; }` — no model-level constraint ensures ValidUntil > ValidFrom. A record where ValidUntil precedes ValidFrom is logically invalid but currently storable. | Low at domain model level; depends on BLL enforcement. If BLL queries check `ValidFrom <= now <= ValidUntil` without also asserting `ValidUntil > ValidFrom`,…
- **Reviewer reasoning**: Authority ValidFrom/ValidUntil have no model-level constraint ensuring from < until


### 96. V152 — Original: **TP** | Low | CWE-20
- **File**: `backend/App.Domain/Models/Event/Service.cs:94`
- **OWASP**: A06 – Insecure Design
- **Found by**: AI-CodeRabbit
- **Description**: `[NotMapped] public string? CreatedByName { get; set; }` — no [MaxLength] constraint. Because it is [NotMapped], the database never enforces a bound. If this field is populated from a query (e.g., a JOIN fetching user display names) and then serialized into an API response or written to a log, there is no length or content guard at the model level. | Depends entirely on how this field is…
- **Reviewer reasoning**: Service.CreatedByName [NotMapped] has no MaxLength — unbounded string


### 97. V153 — Original: **TP** | Low | CWE-20
- **File**: `backend/App.Domain/Models/Identity/AppUser.cs:11`
- **OWASP**: A06 – Insecure Design
- **Found by**: AI-CodeRabbit
- **Description**: `[MaxLength(7)] public string? ScheduleColor { get; set; }` — MaxLength(7) matches the `#RRGGBB` format, but there is no regex or format validator enforcing it. A value like `</style><script>alert(1)</script>` is only 37 chars and is blocked by MaxLength, but a crafted 7-char payload is possible in some CSS contexts. | Very low at the domain layer; actual exploitability requires the API/view…
- **Reviewer reasoning**: ScheduleColor MaxLength(7) but no regex for #RRGGBB — accepts arbitrary 7-char strings


### 98. V155 — Original: **TP** | Low | CWE-20
- **File**: `backend/WebApp/Controllers/HomeController.cs:22-26`
- **OWASP**: A06 – Insecure Design
- **Found by**: AI-CodeRabbit
- **Description**: The `culture` string is passed unsanitised to `RequestCulture(culture)`, which calls `CultureInfo` internally. No validation against the two supported cultures (`et`, `en`) configured in `Program.cs` is performed. An attacker can set the culture cookie to any arbitrary BCP-47 tag or malformed string. | An attacker can set the culture cookie to an unsupported or crafted locale (e.g.,…
- **Reviewer reasoning**: HomeController SetLanguage accepts arbitrary culture string without validation — confirmed in source code (no allowlist, no regex)


### 99. V157 — Original: **TP** | Low | CWE-362
- **File**: `backend/App.DAL.EF/DataSeeding/AppDataInit.cs:27, 36, 47, 52, 60, 65, 72, 75`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-CodeRabbit
- **Description**: `roleManager.FindByNameAsync(roleName).Result`, `userManager.CreateAsync(user, password).Result`, `userManager.AddToRoleAsync(user, role).Result` — every async identity operation is synchronously blocked. | In an ASP.NET Core synchronization context, `.Result` on an incomplete `Task` can cause a thread-pool deadlock, causing the application startup to hang indefinitely. A hung startup effectively…
- **Reviewer reasoning**: DataSeeding uses .Result on async — deadlock risk in synchronous context


### 100. V158 — Original: **TP** | Low | CWE-521
- **File**: `backend/WebApp/Program.cs:37-42`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-Claude
- **Description**: No custom password policy configured beyond ASP.NET Identity defaults (min 6 chars). NIST 800-63B recommends minimum 8 characters.
- **Reviewer reasoning**: Default ASP.NET Identity password policy (min 6 chars) — below NIST 800-63B minimum of 8


### 101. V159 — Original: **FP** | Low | CWE-613
- **File**: `frontend/src/components/SessionExpiryWarning.vue:74-76`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-CodeRabbit
- **Description**: `onMounted(() => { checkInterval = setInterval(check, 30_000); })` — the initial `check()` is never called immediately on mount. If the component mounts after the session has already expired (e.g., user wakes a suspended laptop), detection is delayed by up to 30 seconds. | During the up-to-30-second window the dialog is not shown and `logout()` is not called, an already-expired session token may…
- **Reviewer reasoning**: SessionExpiryWarning 30s delay is UX issue, not a security vulnerability


### 102. V160 — Original: **TP** | Low | CWE-807
- **File**: `frontend/src/plugins/i18n.ts:7`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-CodeRabbit
- **Description**: `const savedLocale = localStorage.getItem('locale') || 'et-EE';` reads an arbitrary string from localStorage with no allowlist check before passing it as the active locale. An XSS vulnerability elsewhere on the same origin, or a malicious browser extension, could write a crafted locale key. | If an unexpected locale key is provided and a future `messages` bundle is added whose keys overlap with…
- **Reviewer reasoning**: i18n locale read from localStorage with no allowlist — arbitrary culture injection


### 103. V161 — Original: **TP** | Low | CWE-521
- **File**: `frontend/src/views/pages/AdminUserCreate.vue:22`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-CodeRabbit
- **Description**: `AdminUserCreate.vue` `doCreate()` performs `error.value = null` then immediately calls `IdentityService.register`. There is no minimum-length check, no complexity check, and no empty-password guard before the API call. `ChangePassword.vue` (same PR) correctly enforces `>= 8` characters and confirms match before submission. | A manager could submit an empty or trivially weak password.…
- **Reviewer reasoning**: AdminUserCreate performs no client-side password validation before API call


### 104. V162 — Original: **FP** | Low | CWE-204
- **File**: `frontend/src/views/pages/auth/ForgotPassword.vue:18-20`
- **OWASP**: A07 – Authentication Failures
- **Found by**: AI-CodeRabbit
- **Description**: When `IdentityService.forgotPassword` returns errors, the raw first error string from the backend is displayed verbatim to the user. If the backend returns distinct messages for known vs. unknown email addresses (e.g., "Email not found" vs. "Reset email sent"), this creates a user-enumeration oracle. | Depends entirely on backend behaviour. The frontend UI itself correctly shows a uniform success…
- **Reviewer reasoning**: ForgotPassword always returns Ok — finding about error display is incorrect


### 105. V163 — Original: **FP** | Low | CWE-476
- **File**: `backend/App.DAL.EF/Mappers/ServiceMapper.cs:52`
- **OWASP**: A08 – Integrity Failures
- **Found by**: AI-CodeRabbit
- **Description**: Both the DTO→domain direction (Line 52: `dalEntity.ServiceLines?.Select(l => _serviceLineMapper.Map(l)!).ToList()`) and the domain→DTO direction (Line 79: `domainEntity.ServiceLines?.Select(l => _serviceLineMapper.Map(l)!).ToList()`) use the null-forgiving operator to suppress compiler warnings. `ServiceLineMapper.Map()` returns `null` when given a `null` input. If a `null` element exists in the…
- **Reviewer reasoning**: ServiceMapper null propagation with ! operator is NRE risk, not security vuln


### 106. V164 — Original: **TP** | Low | CWE-20
- **File**: `backend/App.DTO/v1/Model.cs:20`
- **OWASP**: A08 – Integrity Failures
- **Found by**: AI-CodeRabbit
- **Description**: `ImageUrl` is constrained only by `[MaxLength(160)]`. There is no `[Url]` attribute or protocol allowlist. It accepts any string up to 160 characters, including `javascript:` URIs or `data:` URIs. | If the API response containing `ImageUrl` is rendered in a front-end `<img src>` or `<a href>` without additional sanitization, a stored `javascript:` URI could be triggered by user interaction. The…
- **Reviewer reasoning**: Model.ImageUrl has no [Url] attribute — accepts arbitrary string as URL


### 107. V165 — Original: **TP** | Low | CWE-532
- **File**: `backend/App.BLL/Mappers/MarkBLLMapper.cs:19, 29`
- **OWASP**: A09 – Logging Failures
- **Found by**: AI-CodeRabbit
- **Description**: `_logger.LogDebug("✅ BLLMapper: Mapping DAL to BLL: {`@Entity`}", entity)` and the inverse direction both serialize the full Mark entity object. The {`@Entity`} destructor in Serilog/Microsoft.Extensions.Logging will enumerate all properties. If logging is misconfigured to emit Debug level in production (e.g., appsettings.Production.json with "Default": "Debug"), the full Mark payload is written…
- **Reviewer reasoning**: MarkBLLMapper logs full entity objects at Debug level — may contain PII


### 108. V166 — Original: **TP** | Low | CWE-778
- **File**: `backend/WebApp/ApiControllers/AuthorityApiController.cs`
- **OWASP**: A09 – Logging Failures
- **Found by**: AI-Claude
- **Description**: No security logging in AuthorityApiController.
- **Reviewer reasoning**: AuthorityApiController has no security logging — no audit trail


### 109. V167 — Original: **TP** | Low | CWE-778
- **File**: `backend/WebApp/ApiControllers/ModelsApiController.cs`
- **OWASP**: A09 – Logging Failures
- **Found by**: AI-Claude
- **Description**: No security logging in ModelsApiController. MarksApiController has ILogger commented out.
- **Reviewer reasoning**: ModelsApiController has no security logging; MarksApiController has ILogger commented out


### 110. V168 — Original: **TP** | Low | CWE-778
- **File**: `backend/WebApp/ApiControllers/OrganisationApiController.cs`
- **OWASP**: A09 – Logging Failures
- **Found by**: AI-Claude
- **Description**: No security logging in OrganisationApiController.
- **Reviewer reasoning**: OrganisationApiController has no security logging


### 111. V169 — Original: **TP** | Low | CWE-778
- **File**: `backend/WebApp/ApiControllers/OrganisationVehicleApiController.cs`
- **OWASP**: A09 – Logging Failures
- **Found by**: AI-Claude
- **Description**: No security logging in OrganisationVehicleApiController.
- **Reviewer reasoning**: OrganisationVehicleApiController has no security logging


### 112. V170 — Original: **TP** | Low | CWE-778
- **File**: `backend/WebApp/ApiControllers/PersonApiController.cs`
- **OWASP**: A09 – Logging Failures
- **Found by**: AI-Claude
- **Description**: No security logging in PersonApiController — no ILogger injected, no audit trail for data access or modifications.
- **Reviewer reasoning**: PersonApiController has no ILogger injected — no audit trail for PII access


### 113. V171 — Original: **TP** | Low | CWE-778
- **File**: `backend/WebApp/ApiControllers/ScheduleApiController.cs`
- **OWASP**: A09 – Logging Failures
- **Found by**: AI-Claude
- **Description**: No security logging in ScheduleApiController.
- **Reviewer reasoning**: ScheduleApiController has no security logging


### 114. V172 — Original: **TP** | Low | CWE-778
- **File**: `backend/WebApp/ApiControllers/ScheduleEntryApiController.cs`
- **OWASP**: A09 – Logging Failures
- **Found by**: AI-Claude
- **Description**: No security logging in ScheduleEntryApiController.
- **Reviewer reasoning**: ScheduleEntryApiController has no security logging


### 115. V173 — Original: **TP** | Low | CWE-778
- **File**: `backend/WebApp/ApiControllers/ServiceApiController.cs`
- **OWASP**: A09 – Logging Failures
- **Found by**: AI-Claude
- **Description**: No security logging in ServiceApiController.
- **Reviewer reasoning**: ServiceApiController has no security logging


### 116. V174 — Original: **TP** | Low | CWE-778
- **File**: `backend/WebApp/ApiControllers/ServiceTypeApiController.cs`
- **OWASP**: A09 – Logging Failures
- **Found by**: AI-Claude
- **Description**: No security logging in ServiceTypeApiController.
- **Reviewer reasoning**: ServiceTypeApiController has no security logging


### 117. V175 — Original: **TP** | Low | CWE-778
- **File**: `backend/WebApp/ApiControllers/VatApiController.cs`
- **OWASP**: A09 – Logging Failures
- **Found by**: AI-Claude
- **Description**: No security logging in VatApiController.
- **Reviewer reasoning**: VatApiController has no security logging


### 118. V176 — Original: **TP** | Low | CWE-778
- **File**: `backend/WebApp/ApiControllers/VehicleController.cs`
- **OWASP**: A09 – Logging Failures
- **Found by**: AI-Claude
- **Description**: No security logging in VehicleController.
- **Reviewer reasoning**: VehicleController has no security logging


### 119. V177 — Original: **TP** | Low | CWE-778
- **File**: `backend/WebApp/Areas/Admin/Controllers/`
- **OWASP**: A09 – Logging Failures
- **Found by**: AI-Claude
- **Description**: All 9 MVC admin area controllers lack logging entirely — no ILogger, no audit trail for admin CRUD operations.
- **Reviewer reasoning**: All 9 MVC admin area controllers lack ILogger — no audit trail for admin CRUD


### 120. V178 — Original: **TP** | Low | CWE-532
- **File**: `backend/WebApp/Areas/Admin/Controllers/MarksController.cs:53-63, 95-102, 135`
- **OWASP**: A09 – Logging Failures
- **Found by**: AI-CodeRabbit
- **Description**: `Console.WriteLine($"✅ CREATE: {mark.MarkName} / {mark.MarkCode}")`, `Console.WriteLine($" • {kvp.Key}: {error.ErrorMessage}")`, and `Console.WriteLine($"🗑️ Deleted: {mark.MarkName}")` emit user-controlled data to stdout without sanitization. | In containerized or log-aggregated deployments, stdout is captured. An attacker can inject log-forging payloads (newlines, ANSI escape codes) into…
- **Reviewer reasoning**: MarksController uses Console.WriteLine with entity data — PII in stdout


### 121. V179 — Original: **TP** | Low | CWE-532
- **File**: `backend/WebApp/Areas/Admin/Controllers/VehiclesController.cs:24-27`
- **OWASP**: A09 – Logging Failures
- **Found by**: AI-CodeRabbit
- **Description**: Every `Index` page load for any admin emits all registration numbers at `Information` level with structured logging. Registration numbers are personal-data-adjacent (vehicle tracking identifiers) under GDPR. | Log files or SIEM ingestion that does not restrict access level could expose vehicle fleet data to operators, log viewers, or attackers who gain log read access. The logging fires on every…
- **Reviewer reasoning**: VehiclesController logs registration numbers at Information level


### 122. V180 — Original: **FP** | Low | CWE-390
- **File**: `frontend/src/service/puksiir/PersonApiService.ts:12-19`
- **OWASP**: A09 – Logging Failures
- **Found by**: AI-CodeRabbit
- **Description**: `getEmployees()` and `getMe()` perform Axios GET requests with no `try/catch` block, unlike all other services in the PR which wrap calls in `try/catch` and return `IResultObject<T>`. Uncaught promise rejections propagate to the caller and are not normalized into `{ errors: [...] }` shape. | A network failure or 5xx from the `PersonApi/employees` or `PersonApi/me` endpoint will throw an unhandled…
- **Reviewer reasoning**: PersonApiService no try/catch is error propagation pattern, not security vuln


### 123. V181 — Original: **TP** | Low | CWE-544
- **File**: `backend/WebApp/Program.cs:200`
- **OWASP**: A10 – Exceptional Conditions
- **Found by**: AI-Claude
- **Description**: Global error handler present (UseExceptionHandler) for non-dev. No custom error handler for API routes — unhandled API exceptions may produce default ASP.NET 500 responses.
- **Reviewer reasoning**: Global error handler present for non-dev, but no custom handler for API routes


### 124. V192 — Original: **TP** | Info | CWE-598
- **File**: `http://localhost:5032/api/v1/identity/Account/ConfirmEmail?userId=userId&token=token`
- **OWASP**: A06 – Insecure Design
- **Found by**: DAST-ZAP
- **Description**: Information Disclosure - Sensitive Information in URL [Scans: admin, haldusjuht, pesulaoperaator, puksiirijuht, api]
- **Reviewer reasoning**: ConfirmEmail accepts userId and token via URL query params (CWE-598) — sensitive tokens exposed in browser history, server logs, and Referer header; confirmed in AccountController.ConfirmEmail source

