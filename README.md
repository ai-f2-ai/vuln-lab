# 🧪 vuln-lab

**Un laboratorio di applicazioni volutamente vulnerabili per mettere alla prova gli scanner di sicurezza.**

> ⚠️ **ATTENZIONE** — Questo repository contiene codice insicuro *di proposito* e segreti **finti**.
> Non va mai distribuito in produzione, né esposto su reti pubbliche o server raggiungibili da internet.

---

## 🎯 Scopo

Uno scanner di sicurezza (SAST, SCA, secret scanning, IaC, DAST) è utile solo se si sa cosa riesce a trovare e cosa gli sfugge.
`vuln-lab` offre un **banco di prova con la soluzione già scritta**: ogni vulnerabilità è dichiarata in [`EXPECTED.md`](EXPECTED.md); quelle nel codice sorgente sono marcate con un commento `VULN-xx` (configurazioni e dipendenze, che non hanno marcatore, sono solo in `EXPECTED.md`).

Si può usare per:

- 📊 **confrontare gli strumenti** (Semgrep, Gitleaks, Trivy, Checkov, Bandit, ZAP...) misurando quante vulnerabilità trovano (veri positivi), quante ne perdono (falsi negativi) e quante segnalazioni inventano (falsi positivi);
- ⚙️ **validare una pipeline CI/CD** di sicurezza prima di applicarla ai repository reali;
- 🔧 **tarare regole e soglie** (regole Semgrep personalizzate, allowlist di Gitleaks, severità minima di Trivy);
- 🎓 **formare sviluppatori e team** mostrando esempi concreti di errori comuni e della loro correzione;
- 🧭 **collaudare i processi di triage**: gestione dei report SARIF, esclusioni, tracciamento delle correzioni.

## 🗂️ Contenuto

| Progetto | Stack | Cosa contiene |
|---|---|---|
| [`01-flask-shop`](projects/01-flask-shop) | Python / Flask | SQLi, SSTI/XSS, command injection, path traversal, SSRF, pickle, YAML, XXE, `eval`, open redirect, MD5, PRNG debole, debug attivo · Dockerfile · **Terraform** |
| [`02-express-blog`](projects/02-express-blog) | Node.js / Express | SQLi, XSS, command injection, prototype pollution, deserializzazione, `eval`, JWT `none`, SHA1, ReDoS, CORS aperto · Dockerfile · **Kubernetes** |
| [`03-spring-bank`](projects/03-spring-bank) | Java / Spring Boot | SQLi, **Log4Shell**, XXE, deserializzazione Java, command injection, DES/MD5, `Random`, Actuator esposto |
| [`.github/workflows`](.github/workflows) | GitHub Actions | `pull_request_target`, injection nel contesto, `write-all`, action non fissata, `curl \| bash` |

Trasversali a tutti i progetti:

- 🔑 **Segreti finti**: chiavi AWS, token GitHub e npm, webhook Slack, chiave privata RSA, file `.env`. Un token è anche presente **solo nella storia git** (committato e poi rimosso), per verificare la scansione dei commit passati.
- 📦 **Dipendenze con CVE note**: Flask 0.12, PyYAML 5.3, lodash 4.17.15, log4j 2.14.1, jackson 2.9.8, Spring Boot 2.3.0 e altre.
- 🐳 **Dockerfile** con cattive pratiche: utente root, immagini base obsolete, `ADD` da URL, segreti in `ENV`, `chmod 777`.
- ✅ **Controlli negativi**: in ogni progetto una rotta `/safe` usa query parametrizzate. Uno scanner non dovrebbe segnalarla.

## 🚀 Utilizzo

### 1. Scansioni statiche (nessuna esecuzione dell'app)

```bash
./tools/run-scans.sh      # lancia gli scanner installati e salva i report in out/
```

Oppure uno strumento per volta:

```bash
semgrep scan --config p/default --metrics=off --sarif -o out/semgrep.sarif projects/
gitleaks detect --source . --report-path out/gitleaks.json        # include la storia git
trivy fs --scanners vuln,secret,misconfig,license .
checkov -d . --framework terraform,kubernetes,dockerfile,github_actions
bandit -r projects/01-flask-shop
```

### 2. Scansioni dinamiche (DAST)

```bash
(cd projects/03-spring-bank && mvn -q package)   # il Dockerfile copia target/spring-bank-vuln-1.0.0.jar
docker compose up --build       # porte esposte solo su 127.0.0.1
zap-baseline.py -t http://127.0.0.1:5000
nuclei -u http://127.0.0.1:3000
```

Le applicazioni ascoltano su `5000` (Flask), `3000` (Express) e `8080` (Spring).

### 3. Confronto con le attese

1. Contare i marcatori distinti: `grep -rhoE "VULN-[A-Z][0-9]+" projects .github | sort -u | wc -l` (attesi 45)
2. Aprire [`EXPECTED.md`](EXPECTED.md) e confrontare, categoria per categoria, con i report in `out/`.
3. Annotare per ogni strumento: **trovate / mancate / segnalazioni in più**.

| Strumento | Categoria | Trovate | Mancate | Falsi positivi |
|---|---|:-:|:-:|:-:|
| Semgrep | SAST | | | |
| Gitleaks | Segreti | | | |
| Trivy | SCA / IaC / segreti | | | |
| ... | | | | |

## 🧱 Struttura

```
vuln-lab/
├── projects/
│   ├── 01-flask-shop/      # Python + Terraform
│   ├── 02-express-blog/    # Node.js + Kubernetes
│   └── 03-spring-bank/     # Java
├── .github/workflows/      # CI volutamente insicura
├── tools/run-scans.sh      # esecuzione degli scanner
├── docker-compose.yml
└── EXPECTED.md             # mappa delle vulnerabilità attese
```

## 🛡️ Precauzioni

- Tutte le credenziali sono **inventate**; nessuna è valida su servizi reali.
- Le porte del `docker-compose.yml` sono legate a `127.0.0.1`.
- GitHub *push protection* e *secret scanning* possono segnalare i segreti finti: è il comportamento atteso. Se serve, autorizzare il bypass per questo repository.
- Non copiare questo codice in progetti reali.

## ➕ Come estendere il laboratorio

1. Aggiungere la vulnerabilità con un commento `VULN-xx` accanto alla riga.
2. Registrarla in `EXPECTED.md` (progetto, categoria, CWE, strumento atteso).
3. Aggiungere, se possibile, la versione sicura corrispondente come controllo negativo.
