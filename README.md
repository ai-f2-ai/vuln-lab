# scanner-testbed

> **ATTENZIONE: contiene codice volutamente vulnerabile e segreti FINTI.** Non eseguirlo su reti o server esposti. Serve solo a collaudare strumenti di sicurezza (Semgrep, Gitleaks, Trivy, Checkov, ZAP, ...).

Tre progetti indipendenti (`projects/`), ognuno con vulnerabilità di codice, dipendenze obsolete, Dockerfile e (dove indicato) IaC:

| Progetto | Stack | Extra |
|---|---|---|
| `01-flask-shop` | Python / Flask | Terraform |
| `02-express-blog` | Node.js / Express | Kubernetes |
| `03-spring-bank` | Java / Spring Boot | Log4Shell, Actuator |

La mappa completa delle vulnerabilità attese è in [`EXPECTED.md`](EXPECTED.md). Le scansioni si lanciano con `tools/run-scans.sh`. Un `docker compose up --build` avvia le app (solo su 127.0.0.1) per le prove dinamiche con ZAP o Nuclei.

Nota: GitHub *push protection* e *secret scanning* possono bloccare il push dei segreti finti. In un repo di prova si può autorizzare il bypass o disattivare la funzione.
