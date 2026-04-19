# Lõputöö lisad

TalTech bakalaureusetöö täismahus lisad.

**Autor:** Kaisa Liiv
**Teema:** Veebirakenduste turvatestimise neljakihiline raamistik (DAST, SAST, SCA, TI)

See repositoorium sisaldab lõputöö lisade täisversioone. Lõputöö PDFs on iga lisa esitatud lühendatud kokkuvõttena koos viitega siia repositooriumisse.

## OWASP Juice Shop v19.1.1 (Lisa 2–14)

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
| 12 | `lisa12-agent-start-prompt.md` | Claude Code agendi algprompt |
| 13 | `lisa13-methodology.md` | Claude Code metoodikajuhis |
| 14 | `lisa14-A01-*.md` … `lisa14-A10-*.md` | OWASP Top 10 kategooriapromptid (10 faili) |

## Puksiiri haldusrakendus (Lisa 15–26)

| Lisa | Fail | Kirjeldus |
|------|------|-----------|
| 15 | `lisa15-dast-baseline-passive.yaml` | DAST passiivne skaneering (ZAP) |
| 16 | `lisa16-dast-baseline-active-admin.yaml` | DAST aktiivne — admin roll |
| 17 | `lisa17-dast-baseline-active-haldusjuht.yaml` | DAST aktiivne — haldusjuhi roll |
| 18 | `lisa18-dast-baseline-active-puksiirijuht.yaml` | DAST aktiivne — puksiirijuhi roll |
| 19 | `lisa19-dast-baseline-active-pesulaoperaator.yaml` | DAST aktiivne — pesulaoperaatori roll |
| 20 | `lisa20-dast-api-local.yaml` | DAST API-skaneering |
| 21 | `lisa21-sast-scan-config.yml` | SAST Semgrep konfiguratsioon |
| 22 | `lisa22-sca-scan-config.yml` | SCA Dependency-Check konfiguratsioon |
| 23 | `lisa23-coderabbit.yaml` | CodeRabbit konfiguratsioon |
| 24 | `lisa24-exploit-tests.py` | Ekspluatatsioonitestid (40 testi) |
| 25 | `lisa25-agent-start-prompt.md` | Claude Code agendi algprompt |
| 26 | `lisa26-methodology.md` | Claude Code metoodikajuhis |

## Tööriistad

- **DAST:** OWASP ZAP 2.16.1 (Automation Framework)
- **SAST:** Semgrep OSS 1.151.0
- **SCA:** OWASP Dependency-Check 12.2.0
- **TI:** Claude Opus 4.6 (Claude Code) + CodeRabbit Pro
