# Initial Prompt for the AI Security Analysis Session

> This file is saved for appendices. Its content was given as the first message to a new Claude Code session.

---

## Prompt

You are a security analyst. Your task is to analyze the Puksiir Towing Company web application codebase for security vulnerabilities using the OWASP Top 10:2025 framework.

### Preparation

1. Read the methodology file:
   `/Users/kaisaliiv/Desktop/Lõputöö/ai-prompts/methodology.md`
2. Read all 10 category prompt files (read them all before starting analysis):
   - `/Users/kaisaliiv/Desktop/Lõputöö/ai-prompts/A01-broken-access-control.md`
   - `/Users/kaisaliiv/Desktop/Lõputöö/ai-prompts/A02-security-misconfiguration.md`
   - `/Users/kaisaliiv/Desktop/Lõputöö/ai-prompts/A03-supply-chain.md`
   - `/Users/kaisaliiv/Desktop/Lõputöö/ai-prompts/A04-cryptographic-failures.md`
   - `/Users/kaisaliiv/Desktop/Lõputöö/ai-prompts/A05-injection.md`
   - `/Users/kaisaliiv/Desktop/Lõputöö/ai-prompts/A06-insecure-design.md`
   - `/Users/kaisaliiv/Desktop/Lõputöö/ai-prompts/A07-authentication-failures.md`
   - `/Users/kaisaliiv/Desktop/Lõputöö/ai-prompts/A08-integrity-failures.md`
   - `/Users/kaisaliiv/Desktop/Lõputöö/ai-prompts/A09-logging-failures.md`
   - `/Users/kaisaliiv/Desktop/Lõputöö/ai-prompts/A10-exceptional-conditions.md`

### Target Application
- Repo: `/Users/kaisaliiv/Projects/puksiir2026-security-tests`
- Stack: C# / .NET 10 (ASP.NET backend) + Vue 3 / TypeScript (frontend) + PostgreSQL 16
- Backend code: `backend/WebApp/`, `backend/App.BLL/`, `backend/App.DAL.EF/`, `backend/App.Domain/`, `backend/App.API/`, `backend/App.DTO/`, `backend/App.BLL.DTO/`, `backend/App.DAL.DTO/`, `backend/App.Contracts.DAL/`, `backend/App.BLL.Contracts/`
- Frontend code: `frontend/src/`
- **Do not read** `bin/`, `obj/`, `Migrations/`, `App.Tests/`, `TestResults/`, `Base.*`, `Helpers/`, `node_modules/`, `dist/`, `k6/`
  - `node_modules/`, NuGet packages — dependency analysis is handled by the SCA layer (OWASP Dependency-Check)
  - `App.Tests/`, `TestResults/` — test code does not reach production; Semgrep excludes these as well, so the AI layer scope must be comparable
  - `Base.*`, `Helpers/` — generic base classes, not application-specific logic
  - `Migrations/` — auto-generated EF Core migration files

### Analysis Workflow
Process all 10 categories sequentially (A01 → A02 → … → A10):
1. For each category, run the grep searches defined in the prompt file against the repo
2. For each grep match, read ±15 lines of context
3. Evaluate semantically — is this a true vulnerability (TP), a false positive (FP), or an informational finding (Info)?
4. Classify severity: High / Medium / Low / Info
5. If the same finding is already recorded under a previous category — do not duplicate, reference as a repeat (e.g., "A05 (repeat: #5)")

### Output
Write **one consolidated report** to:
`/Users/kaisaliiv/Desktop/Lõputöö/ai-prompts/results/ai-security-report.md`

Report structure (as described in the methodology file):
1. **Findings table**: `| # | Prompt | File | Line | CWE | Vulnerability description | Severity | TP/FP/Info |`
2. **Summary**: Total findings, TP/FP/Info breakdown, severity distribution, per-category summary, duplicates summary

Start immediately by reading the methodology file.
