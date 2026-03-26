# AI Security Analysis Methodology — Agent Instruction File

## Target Application
- Puksiir Towing Company (C# / .NET 10 + Vue 3 + PostgreSQL 16)
- Repo location: /Users/kaisaliiv/Projects/puksiir2026-security-tests
- Backend: C# / ASP.NET Core 10, layered architecture (WebApp, App.BLL, App.DAL.EF, App.Domain, App.API)
- Frontend: Vue 3 + TypeScript + PrimeVue
- Primary code: backend/WebApp/, backend/App.BLL/, backend/App.DAL.EF/, backend/App.Domain/, backend/App.API/, frontend/src/

## Method (VULSOLVER-style)
1. **Pattern detection**: grep searches for CWE-specific patterns
2. **Context analysis**: Read ±10-20 lines around each match
3. **Semantic evaluation**: Is this a real vulnerability?
4. **Classification**: TP (true positive), FP (false positive), Info (informational)

## Output format (per finding)
```
| # | File | Line | CWE | Description | Severity | TP/FP/Info |
```

## Severity scale (four-level, aligned with ZAP risk levels)
- **High**: Direct exploitation risk (e.g., SQLi, RCE, auth bypass)
- **Medium**: Requires additional conditions but realistic (e.g., info leak, CSRF)
- **Low**: Best practice violation, limited impact
- **Info**: Observations, not exploitable

## Rules
- Search ONLY for CWEs in your category
- Do not read files where grep found no matches — **exception**: to detect missing controls (e.g., controllers without [Authorize], endpoints without logging), read the main WebApp/ApiControllers/, App.BLL/Services/, and App.DAL.EF/Repositories/ files even without grep matches
- Do not read App.Tests/, TestResults/, bin/, obj/, Migrations/, node_modules/, dist/, k6/
- Map application specifics (directory structure, middleware chain, etc.) before starting grep searches — this helps exclude project-irrelevant patterns (e.g., Node.js CWEs in a C# application)
- Describe each finding concretely (which line, which function, what problem)
- If a vulnerability is a real issue in production code, mark it as TP
- **CWE overlap between categories**: OWASP's official CWE mapping creates duplicates (e.g., CWE-209 appears under both A02 and A06). Record the same finding in detail only once; in other categories, reference the earlier finding (e.g., "see A02 finding #3")
