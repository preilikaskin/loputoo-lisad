# Lõputöö lisad

TalTech bakalaureusetöö täismahus lisad.

**Autor:** Kaisa Liiv
**Teema:** Veebirakenduste turvatestimise neljakihiline raamistik (DAST, SAST, SCA, TI)

See repositoorium sisaldab lõputöö lisade täisversioone. Lõputöö PDFs on iga lisa esitatud lühendatud ühe-leheküljelise kokkuvõttena koos viitega siia repositooriumisse.

## Sisu

### OWASP Juice Shop (Lisa 2–15)

| Lisa | Kaust | Kirjeldus |
|------|-------|-----------|
| 2 | `lisa02-dast-passive/` | DAST passiivse skaneerimise konfiguratsioon (ZAP) |
| 3 | `lisa03-dast-active-admin/` | DAST aktiivne skaneering — admin roll |
| 4 | `lisa04-dast-active-customer/` | DAST aktiivne skaneering — tavakasutaja roll |
| 5 | `lisa05-dast-active-accounting/` | DAST aktiivne skaneering — raamatupidaja roll |
| 6 | `lisa06-dast-active-deluxe/` | DAST aktiivne skaneering — Deluxe Member roll |
| 7 | `lisa07-dast-api/` | DAST API-skaneeringu konfiguratsioon |
| 8 | `lisa08-sast-semgrep/` | SAST Semgrep skaneerimise konfiguratsioon |
| 9 | `lisa09-sca-depcheck/` | SCA Dependency-Check konfiguratsioon |
| 10 | `lisa10-coderabbit/` | CodeRabbit `.coderabbit.yaml` konfiguratsioon |
| 11 | `lisa11-exploit-tests/` | Ekspluatatsioonitestide skript (`exploit_tests.py`) |
| 12 | `lisa12-cross-validation/` | Koodiülevaatuse ristvalideerimise prompt |
| 13 | `lisa13-agent-start/` | Claude Code agendi algprompt |
| 14 | `lisa14-ai-methodology/` | Claude Code agendi metoodikajuhis |
| 15 | `lisa15-owasp-prompts/` | OWASP Top 10 kategooriapõhised promptid (A01–A10) |

### Puksiir (Lisa 16–27)

| Lisa | Kaust | Kirjeldus |
|------|-------|-----------|
| 16 | `lisa16-puksiir-dast-passive/` | DAST passiivse skaneerimise konfiguratsioon (ZAP) |
| 17 | `lisa17-puksiir-dast-active-admin/` | DAST aktiivne skaneering — admin roll |
| 18 | `lisa18-puksiir-dast-active-accounting/` | DAST aktiivne skaneering — haldusjuhi roll |
| 19 | `lisa19-puksiir-dast-active-deluxe/` | DAST aktiivne skaneering — puksiirijuhi roll |
| 20 | `lisa20-puksiir-dast-active-customer/` | DAST aktiivne skaneering — pesulaoperaatori roll |
| 21 | `lisa21-puksiir-dast-api/` | DAST API-skaneeringu konfiguratsioon |
| 22 | `lisa22-puksiir-sast-semgrep/` | SAST Semgrep skaneerimise konfiguratsioon |
| 23 | `lisa23-puksiir-sca-depcheck/` | SCA Dependency-Check konfiguratsioon |
| 24 | `lisa24-puksiir-coderabbit/` | CodeRabbit `.coderabbit.yaml` konfiguratsioon |
| 25 | `lisa25-puksiir-exploit-tests/` | Ekspluatatsioonitestide skript (`exploit_tests.py`) |
| 26 | `lisa26-puksiir-agent-start/` | Claude Code agendi algprompt |
| 27 | `lisa27-puksiir-ai-methodology/` | Claude Code agendi metoodikajuhis |

## Sihtrakendused

- **OWASP Juice Shop v19.1.1** — kalibreerimiseks kasutatav haavatav testrakendus (Node.js)
- **Puksiir** — reaaltoodangu puksiiriettevõtte haldusrakendus (ASP.NET Core / .NET 10 + Vue 3 + PostgreSQL 16)

## Tööriistad

- **DAST:** OWASP ZAP 2.16.1 (Automation Framework)
- **SAST:** Semgrep OSS 1.151.0
- **SCA:** OWASP Dependency-Check 12.2.0
- **TI:** Claude Opus 4 (Claude Code) + CodeRabbit Pro
