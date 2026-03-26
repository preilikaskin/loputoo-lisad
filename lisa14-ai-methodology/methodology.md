# AI Security Analysis Methodology — Agent Instruction File

## Target Application
- OWASP Juice Shop v19.1.1
- Repo location: /Users/kaisaliiv/Desktop/juice-shop-test-2026
- Language: TypeScript/JavaScript (Node.js backend + Angular frontend)
- Primary code: routes/, lib/, models/, server.ts, config/, data/, frontend/src/

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
- Do not read files where grep found no matches — **exception**: to detect missing controls (e.g., routes without auth middleware, endpoints without logging), read the main routes/, lib/, and models/ files even without grep matches
- Do not read tests (test/, spec/, e2e/) or node_modules/
- Map application specifics (directory structure, middleware chain, etc.) before starting grep searches — this helps exclude project-irrelevant patterns (e.g., PHP CWEs in a Node.js application)
- Describe each finding concretely (which line, which function, what problem)
- If a vulnerability is intentional (e.g., CTF-style challenge), still mark it as TP
- **CWE overlap between categories**: OWASP's official CWE mapping creates duplicates (e.g., CWE-209 appears under both A02 and A06). Record the same finding in detail only once; in other categories, reference the earlier finding (e.g., "see A02 finding #3")
