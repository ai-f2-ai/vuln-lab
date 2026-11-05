# Vulnerabilità attese (mappa per il confronto)

Ogni voce è marcata nel codice con il commento `VULN-xx`. Contare con: `grep -rn "VULN-" projects .github`

| Progetto | Id | Categoria | CWE | Tool atteso |
|---|---|---|---|---|
| 01-flask | P01-P04, .env, deploy_key.pem | Segreti | 798 | Gitleaks, Trivy, Semgrep |
| 01-flask | P05 | SQL injection | 89 | Semgrep, Bandit |
| 01-flask | P06 | MD5 | 328 | Semgrep, Bandit |
| 01-flask | P07 | SSTI/XSS | 79/1336 | Semgrep, Bandit |
| 01-flask | P08 | Command injection | 78 | Semgrep, Bandit |
| 01-flask | P09 | Path traversal | 22 | Semgrep |
| 01-flask | P10, P11 | SSRF, TLS disattivato | 918/295 | Semgrep, Bandit |
| 01-flask | P12, P13 | pickle / yaml.load | 502 | Semgrep, Bandit |
| 01-flask | P14 | XML (XXE) | 611 | Semgrep, Bandit |
| 01-flask | P15 | eval | 95 | Semgrep, Bandit |
| 01-flask | P16 | Open redirect | 601 | Semgrep |
| 01-flask | P17 | PRNG debole | 338 | Bandit |
| 01-flask | P18 | Debug / bind 0.0.0.0 | 489/605 | Semgrep, Bandit |
| 01-flask | requirements.txt | CVE (Flask, Jinja2, PyYAML, Pillow, ...) | - | Trivy, OSV, pip-audit |
| 01-flask | Dockerfile | root, ADD URL, ENV segreto, 777, tag vecchio | - | Trivy, Hadolint, Checkov |
| 01-flask | iac/main.tf | S3 pubblico, SG aperto, DB non cifrato | - | Trivy, Checkov, tfsec |
| 02-express | N01-N14 | CORS, SQLi, XSS, cmd inj, traversal, proto-pollution, deserial., eval, JWT none, SHA1, ReDoS | vari | Semgrep |
| 02-express | N02-N04, .npmrc | Segreti (webhook, token npm, password DB) | 798 | Gitleaks |
| 02-express | package.json | CVE (express, lodash, minimist, marked, ...) | - | Trivy, npm audit, OSV |
| 02-express | k8s/deployment.yaml | privileged, hostPath, hostNetwork, root | - | Trivy, Checkov, kube-linter |
| 03-spring | J01-J12 | SQLi, Log4Shell, traversal, deserial., XXE, cmd inj, MD5, DES, Random | vari | Semgrep |
| 03-spring | pom.xml | CVE (log4j 2.14.1, jackson 2.9.8, commons-text 1.9, Spring Boot 2.3.0) | - | Trivy, OSV, Grype |
| 03-spring | application.properties | Actuator esposto, password in chiaro | - | Semgrep, Gitleaks |
| root | .github/workflows | pull_request_target, injection, write-all, action non fissata, curl\|bash | 94/829 | Semgrep, zizmor, Checkov |
| root | storia git | Segreto committato e rimosso | 798 | Gitleaks, TruffleHog |

## Falsi positivi da NON segnalare
Le rotte `/safe-search` (Flask), `/safe` (Express) e `/safe` (Spring) usano query parametrizzate.
