# Lõputöö lisad

TalTech bakalaureusetöö täismahus lisad.

**Autor:** Kaisa Liiv
**Teema:** Veebirakenduste turvatestimise neljakihiline raamistik (DAST, SAST, SCA, TI)

See repositoorium sisaldab lõputöö lisade täisversioone. Lõputöö PDFs on iga lisa esitatud lühendatud kokkuvõttena koos viitega siia repositooriumisse.

## OWASP Juice Shop v19.1.1 (Lisa 2–15)

| Lisa | Fail | Kirjeldus |
|------|------|-----------|
| 2 | `lisa02-dast-baseline-passive.yaml` | DAST passiivne skaneering (ZAP) |
| 3 | `lisa03-dast-baseline-active-admin.yaml` | DAST aktiivne — admin roll |
| 4 | `lisa04-dast-baseline-active-customer.yaml` | DAST aktiivne — tavakasutaja roll |
| 5 | `lisa05-dast-baseline-active-accounting.yaml` | DAST aktiivne — raamatupidaja roll |
| 6 | `lisa06-dast-baseline-active-deluxe.yaml` | DAST aktiivne — Deluxe Member roll |
| 7 | `lisa07-dast-api-local.yaml` | DAST API-skaneering |
| 8 | `lisa08-sast-scan-config.yml` | SAST Semgrep konfiguratsioon |
| 9 | `lisa09-sca-scan-config.yml` | SCA Dependency-Check konfiguratsioon |
| 10 | `lisa10-coderabbit.yaml` | CodeRabbit konfiguratsioon |
| 11 | `lisa11-exploit-tests.py` | Ekspluatatsioonitestid (60+ testi) |
| 12 | `lisa12-cross-validation-prompt.md` | Ristvalideerimise prompt |
| 13 | `lisa13-agent-start-prompt.md` | Claude Code agendi algprompt |
| 14 | `lisa14-methodology.md` | Claude Code metoodikajuhis |
| 15 | `lisa15-A01-*.md` … `lisa15-A10-*.md` | OWASP Top 10 kategooriapromptid (10 faili) |

## Puksiiri haldusrakendus (Lisa 16–27)

| Lisa | Fail | Kirjeldus |
|------|------|-----------|
| 16 | `lisa16-dast-baseline-passive.yaml` | DAST passiivne skaneering (ZAP) |
| 17 | `lisa17-dast-baseline-active-admin.yaml` | DAST aktiivne — admin roll |
| 18 | `lisa18-dast-baseline-active-accounting.yaml` | DAST aktiivne — haldusjuhi roll |
| 19 | `lisa19-dast-baseline-active-deluxe.yaml` | DAST aktiivne — puksiirijuhi roll |
| 20 | `lisa20-dast-baseline-active-customer.yaml` | DAST aktiivne — pesulaoperaatori roll |
| 21 | `lisa21-dast-api-local.yaml` | DAST API-skaneering |
| 22 | `lisa22-sast-scan-config.yml` | SAST Semgrep konfiguratsioon |
| 23 | `lisa23-sca-scan-config.yml` | SCA Dependency-Check konfiguratsioon |
| 24 | `lisa24-coderabbit.yaml` | CodeRabbit konfiguratsioon |
| 25 | `lisa25-exploit-tests.py` | Ekspluatatsioonitestid (40 testi) |
| 26 | `lisa26-agent-start-prompt.md` | Claude Code agendi algprompt |
| 27 | `lisa27-methodology.md` | Claude Code metoodikajuhis |

## Tööriistad

- **DAST:** OWASP ZAP 2.16.1 (Automation Framework)
- **SAST:** Semgrep OSS 1.151.0
- **SCA:** OWASP Dependency-Check 12.2.0
- **TI:** Claude Opus 4 (Claude Code) + CodeRabbit Pro
