# Guida ai security scanner: come funzionano

Questa guida spiega, strumento per strumento, **come ragiona** uno scanner, **cosa riesce a trovare**, **dove sbaglia** e **come si lancia**. Gli strumenti segnati con ✅ sono quelli messi alla prova da `vuln-lab`.

> **Uso lecito.** Gli strumenti dinamici e di rete (sezioni 6, 8) inviano traffico d'attacco. Vanno usati solo su sistemi propri o per i quali si ha un'autorizzazione scritta. In questo laboratorio: solo contro `127.0.0.1`.

---

## 0. Concetti comuni

| Concetto | Significato |
|---|---|
| **Vero positivo** | Segnalazione corretta di una vulnerabilità reale |
| **Falso positivo** | Segnalazione di un problema che non esiste (rumore, tempo perso) |
| **Falso negativo** | Vulnerabilità reale che lo scanner non vede (il rischio peggiore) |
| **SARIF** | Formato JSON standard per i risultati degli scanner; GitHub, VS Code e molti altri lo leggono |
| **CWE** | Classificazione del *tipo* di debolezza (es. CWE-89 = SQL injection) |
| **CVE** | Identificativo di una vulnerabilità *specifica* in un prodotto e versione |
| **CVSS** | Punteggio di gravità 0-10 di una CVE |
| **EPSS** | Probabilità che una CVE venga sfruttata nei prossimi 30 giorni |
| **KEV** | Elenco CISA delle CVE già sfruttate attivamente: priorità massima |
| **SBOM** | Distinta dei componenti software (formati SPDX o CycloneDX) |
| **Taint analysis** | Segue i dati "non fidati" (sorgente, *source*) fino alle operazioni pericolose (destinazione, *sink*), controllando se passano da una funzione di bonifica (*sanitizer*) |
| **Reachability** | Verifica se il codice vulnerabile di una libreria è davvero richiamato dall'applicazione |

Famiglie di strumenti, in sintesi: **SAST** legge il *nostro* codice; **SCA** controlla il codice *altrui* che importiamo; **secret scanning** cerca credenziali; **IaC/container** controlla le configurazioni; **DAST** attacca l'app in esecuzione; **IAST/RASP** osservano dall'interno mentre gira.

---

## 1. SAST: analisi statica del codice

Il principio comune: il codice sorgente viene trasformato in una struttura analizzabile (token, albero sintattico/AST, grafo del flusso di controllo e dei dati) e confrontato con regole che descrivono schemi pericolosi. Il codice **non viene eseguito**.

### ✅ Semgrep
- **Come funziona.** Analizza il codice con parser per decine di linguaggi e lo confronta con regole in YAML scritte *come se fossero codice*. Una regola usa variabili jolly (`$X`) e operatori:
  ```yaml
  rules:
    - id: sql-concat
      languages: [python]
      severity: ERROR
      message: Query costruita per concatenazione
      pattern: $CURSOR.execute("..." + $INPUT)
  ```
  La **modalità taint** definisce `pattern-sources`, `pattern-sinks` e `pattern-sanitizers` per seguire i dati non fidati. La versione open source segue i flussi *all'interno di un file* (o funzione); l'analisi tra file è nella versione a pagamento.
- **Trova:** SQL/command injection, XSS, deserializzazione insicura, crittografia debole, segreti nel codice, configurazioni pericolose di framework.
- **Limiti:** non capisce il comportamento a runtime; senza taint cross-file perde i flussi lunghi; i falsi positivi dipendono dalla qualità delle regole.
- **Uso:**
  ```bash
  semgrep scan --config p/default --metrics=off --sarif -o out/semgrep.sarif projects/
  ```
  `--config auto` richiede l'invio di metriche a Semgrep: si evita con un ruleset esplicito.
- **Si estende** con regole proprie: ideale per vietare funzioni interne o far rispettare convenzioni aziendali.

### ✅ Bandit
- **Come funziona.** Costruisce l'AST di ogni file Python e, per ogni tipo di nodo (chiamata, import, stringa), esegue dei *plugin* di test identificati da codici `B1xx`-`B7xx` (es. `B602` = `subprocess` con `shell=True`, `B303` = hash MD5).
- **Ogni risultato** ha *severity* e *confidence*, utili per filtrare (`-ll -ii` = solo medio/alto).
- **Limiti:** solo Python; analisi per singolo nodo, senza flusso dei dati complesso (trova `eval()`, non dice se l'argomento è controllato dall'utente).
- **Uso:** `bandit -r projects/01-flask-shop -f json -o out/bandit.json`

### CodeQL
- **Come funziona.** Due fasi: (1) **estrazione**: si costruisce un *database* relazionale che rappresenta il codice (per i linguaggi compilati osserva la build); (2) **query** scritte in QL, linguaggio dichiarativo simile a Datalog, interrogano quel database. Offre analisi *global data flow* e taint tracking tra funzioni e file.
- **Trova:** vulnerabilità con flussi lunghi che i pattern semplici non vedono, e permette di cercare *varianti* di un bug noto.
- **Limiti:** più lento; richiede la build per Java, C/C++, C#; la licenza ne limita l'uso gratuito a progetti open source (o a GitHub Advanced Security).
- **Uso:** si abilita come workflow in GitHub (*Code scanning*), oppure da CLI: `codeql database create` e poi `codeql database analyze`.

### SonarQube / SonarCloud
- **Come funziona.** Un server centrale riceve l'analisi di uno scanner (`sonar-scanner`) e la conserva nel tempo. Combina regole di qualità (bug, code smell), **vulnerabilità** e **security hotspot** (punti da rivedere a mano). Le edizioni a pagamento aggiungono taint analysis più profonda.
- **Quality gate:** soglie (es. "nessuna vulnerabilità nuova") che fanno fallire la pipeline.
- **Punto di forza:** storico, dashboard, analisi del codice *nuovo*. **Limite:** per la sicurezza è meno incisivo di Semgrep/CodeQL nell'edizione Community.

### ESLint con plugin di sicurezza
- **Come funziona.** ESLint analizza l'AST di JavaScript/TypeScript; `eslint-plugin-security` aggiunge regole *euristiche* (`detect-eval-with-expression`, `detect-non-literal-fs-filename`, `detect-unsafe-regex`).
- **Limiti:** molti falsi positivi, perché le regole guardano la forma del codice e non seguono i dati. Utile come primo filtro rapido nell'editor.

### SpotBugs + Find Security Bugs (Java)
- **Come funziona.** Analizza il **bytecode** compilato (non i sorgenti) con *detector* che riconoscono schemi di bug. Il plugin Find Security Bugs aggiunge regole di sicurezza e un'analisi dei flussi non fidati (SQLi, XXE, deserializzazione, cifrari deboli).
- **Uso:** plugin Maven/Gradle; serve compilare prima il progetto.

### gosec, Brakeman, PHPStan
- **gosec (Go):** analizza AST e rappresentazione SSA del codice Go con regole `G1xx`-`G6xx` (credenziali, `exec`, TLS non verificato, permessi file).
- **Brakeman (Ruby on Rails):** conosce la struttura di Rails (controller, vista, modello) e segue i parametri della richiesta fino a query, rendering e redirect. Non esegue l'app.
- **PHPStan:** è un controllo di tipi e correttezza; la sicurezza arriva da estensioni, quindi non è uno scanner di vulnerabilità completo. Per PHP si affianca a Semgrep o a un SAST dedicato.

### Soluzioni commerciali (Snyk Code, Checkmarx, Fortify)
- **Come funzionano.** Stessa idea di CodeQL (modello del codice e query di flusso), con motori proprietari, supporto a più linguaggi, gestione dei workflow di correzione e, spesso, suggerimenti di fix. Snyk Code usa anche modelli di machine learning per le regole.
- **Quando servono:** conformità, supporto contrattuale, grandi basi di codice con molti team.

---

## 2. SCA: dipendenze e licenze

Il principio comune: (1) **inventario**: ricavare quali pacchetti e versioni si usano (da `requirements.txt`, `package-lock.json`, `pom.xml`, o dal database dei pacchetti di un'immagine); (2) **abbinamento**: confrontare ogni coppia pacchetto/versione con un database di vulnerabilità tenendo conto degli intervalli di versioni affette.

> Lo scanner dice che *esiste* una CVE, non che il vostro codice la attivi. Le dipendenze *transitive* (quelle delle dipendenze) sono la maggior parte del rischio.

### ✅ Trivy
- **Come funziona.** Un binario unico con più "scanner": `vuln` (pacchetti OS e librerie), `secret` (regex), `misconfig` (policy Rego su Dockerfile, Terraform, Kubernetes, CloudFormation) e `license`. Scarica un database (`trivy-db`, costruito da NVD, GitHub Advisory, avvisi delle distribuzioni) e lo confronta con l'inventario. Funziona su filesystem, immagini, repository git, SBOM e cluster.
- **Trova:** CVE nelle librerie e nei pacchetti dell'immagine, configurazioni IaC rischiose, segreti, licenze problematiche.
- **Limiti:** serve accesso di rete per aggiornare il database (o un mirror); una CVE senza fix disponibile resta comunque segnalata (opzione `--ignore-unfixed`).
- **Uso:**
  ```bash
  trivy fs --scanners vuln,secret,misconfig,license .
  trivy image miaimmagine:latest
  trivy config iac/
  ```
- **Nota:** `tfsec` è stato integrato in Trivy.

### OSV-Scanner
- **Come funziona.** Legge i file di lock/manifest e interroga il database **OSV** (osv.dev), che raccoglie avvisi da GitHub, PyPA, RustSec, Go e altri in un formato uniforme per ecosistema e intervallo di versioni. Le corrispondenze sono molto precise perché non passano dai CPE.
- **Uso:** `osv-scanner scan -r .`

### Grype + Syft
- **Syft** genera l'**SBOM**: cataloga pacchetti in immagini, directory e archivi, ed esporta SPDX o CycloneDX.
- **Grype** prende l'SBOM (o scansiona direttamente) e lo confronta con il proprio database; usa abbinamenti per ecosistema e, in mancanza, CPE.
- **Vantaggio:** si può generare l'SBOM una volta e riscansionarlo più volte nel tempo, quando escono nuove CVE, senza rianalizzare l'artefatto.
- **Uso:** `syft dir:. -o cyclonedx-json > sbom.json` e poi `grype sbom:sbom.json`.

### pip-audit, npm audit, OWASP Dependency-Check
- **pip-audit:** legge i requisiti (o l'ambiente installato) e interroga l'archivio di avvisi PyPA/OSV. `pip-audit -r requirements.txt`
- **npm audit:** invia l'albero delle dipendenze al registro npm, che risponde con gli avvisi applicabili. `npm audit fix` aggiorna dove possibile senza rompere i vincoli semver.
- **OWASP Dependency-Check:** raccoglie *evidenze* (nome del file, manifest, `pom.xml`) per dedurre un **CPE** e lo cerca nel database **NVD**. Copre Java/.NET, ma ha molti falsi positivi per l'abbinamento approssimativo dei CPE e richiede una chiave API NVD per aggiornarsi velocemente.

### Dependabot e Renovate
- **Come funzionano.** Non sono scanner di rapporto ma **bot**: osservano i manifest e aprono automaticamente *pull request* di aggiornamento. Dependabot segnala anche gli avvisi di sicurezza (da GitHub Advisory Database). Renovate è più configurabile (`renovate.json`, raggruppamenti, pianificazione, molti gestori di pacchetti).
- **Valore:** trasformano un report in una correzione concreta già pronta da rivedere.

### Snyk Open Source, Mend
- Database proprietari arricchiti da ricercatori, **prioritizzazione** (sfruttabilità, *reachability*), suggerimenti di aggiornamento e gestione delle policy aziendali.

### ScanCode, FOSSA (licenze)
- **ScanCode** confronta il testo dei file con un vasto insieme di testi di licenza e riconosce gli identificatori SPDX e i copyright. **FOSSA** aggiunge policy ("niente AGPL nel codice proprietario") e flussi di approvazione.

---

## 3. Secret scanning

Il principio comune: trovare stringhe che *sembrano* credenziali. Si usano **regole per formato** (le chiavi AWS iniziano con `AKIA`, i token GitHub con `ghp_`), **entropia** (stringhe casuali) e, talvolta, **verifica** presso il servizio.

> Un segreto rimosso da un file **resta nella storia git**. Va sempre **revocato e ruotato**, non solo cancellato.

### ✅ Gitleaks
- **Come funziona.** Regole in TOML con espressione regolare, parole chiave per un prefiltro veloce, soglia di entropia e liste di esclusione (*allowlist*). Legge la cronologia con `git log -p` e analizza le righe aggiunte di ogni commit, oltre alla directory di lavoro.
- **Uso:**
  ```bash
  gitleaks detect --source . --report-format sarif --report-path out/gitleaks.sarif
  ```
  Nelle versioni recenti i comandi `gitleaks git` e `gitleaks dir` sostituiscono `detect`.
- **Come hook:** in `pre-commit` blocca il commit *prima* che il segreto entri nella storia.
- **Limiti:** segreti senza formato riconoscibile (password in chiaro) o con entropia bassa sfuggono; non verifica se la chiave è valida.

### TruffleHog
- **Come funziona.** Ha centinaia di **detector** specifici per servizio e, soprattutto, **verifica** se la credenziale è ancora attiva chiamando l'API del servizio. Questo riduce i falsi positivi e permette di dare priorità ai segreti *vivi*. Scansiona git, bucket S3, immagini Docker, Slack e altro.
- **Attenzione:** la verifica invia la credenziale al servizio: usarla solo su segreti propri; si disattiva con `--no-verification`.

### detect-secrets
- **Come funziona.** Plugin (regex, entropia, parole chiave) e un file di **baseline** (`.secrets.baseline`) che registra i risultati noti. In CI segnala solo i segreti *nuovi*; `detect-secrets audit` permette di marcare a mano ogni risultato come vero o falso.

### GitHub secret scanning e push protection
- **Come funziona.** Confronta i contenuti con i formati definiti dai fornitori partner. La **push protection** controlla i commit *durante il `git push`* e lo rifiuta se trova un segreto, offrendo il bypass motivato (quanto accaduto in questo progetto). Il *secret scanning* classico, invece, genera avvisi sui segreti già nel repository.

### ggshield (GitGuardian)
- Client a riga di comando che invia il contenuto al servizio GitGuardian per l'analisi, utile come pre-commit e CI con dashboard e gestione degli incidenti.

---

## 4. IaC, container e configurazioni

Il principio comune: i file di configurazione vengono letti come dati strutturati e controllati con **regole/policy** (Python, YAML, Rego/OPA) che esprimono buone pratiche (cifratura attiva, nessun accesso pubblico, nessun container privilegiato).

### ✅ Checkov
- **Come funziona.** Trasforma Terraform, CloudFormation, Kubernetes, Dockerfile, GitHub Actions ecc. in un **grafo di risorse** e applica controlli con id tipo `CKV_AWS_20` ("il bucket S3 non deve essere pubblico"). I controlli *a grafo* verificano anche le relazioni (es. un security group collegato a un database).
- **Uso:** `checkov -d . --framework terraform,kubernetes,dockerfile,github_actions`

### ✅ Hadolint
- **Come funziona.** Costruisce l'AST del Dockerfile e applica regole `DL3xxx` (tag `latest`, `ADD` al posto di `COPY`, nessun `USER`) e `SC2xxx` tramite **ShellCheck** sui comandi `RUN`.
- **Uso:** `hadolint projects/01-flask-shop/Dockerfile`

### tfsec, Terrascan, KICS
- **tfsec:** analizzatore Terraform, oggi assorbito in Trivy.
- **Terrascan:** policy Rego (OPA) su Terraform, Kubernetes, Helm. Verificare lo stato di manutenzione prima di adottarlo.
- **KICS (Checkmarx):** query Rego su molti formati IaC, con report ricchi.

### kube-linter, kube-score, Kubesec
- Leggono i **manifest** Kubernetes (anche da Helm) e assegnano un punteggio o segnalano: container privilegiati, assenza di limiti di risorse, `hostPath`, immagini `latest`, root.

### kube-bench, kubescape
- **kube-bench** gira *sul nodo* e controlla la configurazione del cluster rispetto al **CIS Kubernetes Benchmark**.
- **kubescape** controlla manifest e cluster in esecuzione rispetto a quadri come NSA, MITRE ATT&CK e CIS.

### Docker Scout, Clair, Anchore
- Scansionano le **immagini**: ne estraggono i livelli, inventariano i pacchetti e li confrontano con avvisi di sicurezza. **Clair** è un servizio con indicizzatore e abbinatore usato dai registri; **Anchore** (con Syft/Grype) aggiunge policy; **Docker Scout** è integrato in Docker Desktop e Docker Hub.

### Prowler, ScoutSuite, CloudSploit
- **Come funzionano.** Usano le **API del cloud** in sola lettura (credenziali con permessi di consultazione) per elencare utenti, bucket, reti, chiavi e confrontarli con benchmark CIS e best practice. Non guardano il codice ma l'**ambiente reale** già distribuito: individuano la deriva rispetto all'IaC.

---

## 5. CI/CD e supply chain

### ✅ zizmor
- **Come funziona.** Analisi statica dei workflow GitHub Actions: rileva *template injection* (`${{ github.event.pull_request.title }}` dentro `run:`), trigger pericolosi (`pull_request_target`), permessi eccessivi, azioni non fissate a uno SHA, credenziali persistenti in `checkout`.
- **Uso:** `zizmor .github/workflows/`

### OpenSSF Scorecard
- **Come funziona.** Interroga le API del repository ed esegue controlli (protezione dei branch, revisione del codice, dipendenze fissate, permessi dei token, presenza di `SECURITY.md`, uso di SAST). Dà un punteggio da 0 a 10 per controllo. Misura le **pratiche del progetto**, non le sue vulnerabilità.

### Sigstore / cosign
- **Come funziona.** Firma di artefatti e immagini *senza chiavi a lunga durata* (*keyless*): l'identità è provata con OIDC (es. GitHub Actions), **Fulcio** emette un certificato di breve durata e la firma viene registrata nel log pubblico **Rekor**. In verifica si controlla *chi* ha firmato.
- **Uso:** `cosign sign immagine@sha256:...` e `cosign verify ...`

### SLSA verifier e in-toto
- Verificano la **provenienza**: attestazioni firmate che dichiarano quale sorgente, quale builder e quali passaggi hanno prodotto un artefatto. Il livello SLSA indica quanto la build è resistente alla manomissione.

### CycloneDX e SPDX
- Non sono scanner ma **formati di SBOM**. Servono a scambiare l'inventario dei componenti e a rieseguire le verifiche quando escono nuove CVE.

---

## 6. DAST: test dell'applicazione in esecuzione

Il principio comune: l'app viene avviata e lo scanner si comporta da **attaccante esterno** (*black box*): invia richieste, osserva risposte, tempi e comportamenti. Non conosce il codice, quindi non produce numeri di riga, ma conferma che il problema è **sfruttabile**.

### ✅ OWASP ZAP
- **Come funziona.** È un **proxy** che si interpone tra browser e app. Lo **spider** (e lo *AJAX spider* per le app JavaScript) scopre pagine e parametri. Lo scanner **passivo** analizza il traffico senza modificarlo (intestazioni mancanti, cookie senza `HttpOnly`); lo scanner **attivo** invia payload d'attacco (SQLi, XSS, traversal) e valuta le risposte. Supporta autenticazione, contesti e importazione di OpenAPI.
- **Modalità:** `zap-baseline.py` (solo passiva, veloce, adatta alla CI), `zap-full-scan.py` (anche attiva), `zap-api-scan.py` (da specifica API).
- **Uso:** `zap-baseline.py -t http://127.0.0.1:5000`

### ✅ Nuclei
- **Come funziona.** Esegue **template** YAML scritti dalla community: ognuno descrive una richiesta (HTTP, DNS, TCP...) e dei *matcher* sulla risposta (stato, parole, regex). Molto veloce e preciso su vulnerabilità note, esposizioni (`/actuator/env`) e configurazioni errate; meno adatto a trovare bug *nuovi* nella logica della vostra app.
- **Uso:** `nuclei -u http://127.0.0.1:8080`

### Burp Suite
- Proxy di intercettazione con **Repeater** (rinvio manuale), **Intruder** (variazioni automatiche di parametri), **Scanner** (a pagamento) e estensioni. È lo strumento principale per i test manuali dei penetration tester.

### Nikto
- Confronta il server con un grande database di file e configurazioni pericolose note (script di esempio, versioni obsolete, intestazioni). Veloce ma *rumoroso* e poco discreto; non cerca bug applicativi.

### sqlmap
- **Come funziona.** Verifica se un parametro è iniettabile con più tecniche: *boolean-based blind*, *time-based blind*, basate su errori, `UNION`, query impilate. Identifica il DBMS e può estrarre dati. È uno strumento d'attacco: usarlo solo su bersagli autorizzati.

### Wapiti, w3af, Arachni
- Scanner black-box *a moduli* che provano XSS, SQLi, inclusione di file e altro. **Arachni** non è più sviluppato; **w3af** è datato. Utili per confronto, ma oggi ZAP e Nuclei sono più mantenuti.

### Dastardly, Invicti, Acunetix
- **Dastardly** è uno scanner gratuito basato su Burp pensato per la CI. **Invicti** e **Acunetix** sono prodotti commerciali che cercano di *confermare* automaticamente la vulnerabilità (*proof-based scanning*) per ridurre i falsi positivi.

---

## 7. IAST e RASP: dall'interno dell'applicazione

### IAST (Contrast Security, Seeker)
- **Come funziona.** Un **agente** strumenta l'applicazione (per esempio il bytecode Java) e osserva i dati mentre i test (manuali o automatici) la usano. Quando un dato non fidato arriva a un punto pericoloso senza bonifica, segnala la vulnerabilità **con la riga di codice esatta**.
- **Pro:** pochi falsi positivi, risultati precisi. **Contro:** vede solo il codice effettivamente percorso dai test e rallenta l'app.

### RASP (OpenRASP) e Falco
- **RASP** vive nel processo dell'applicazione, riconosce un attacco *mentre avviene* (es. una query SQL anomala) e può bloccarlo. **OpenRASP** è un'implementazione open source.
- **Falco** è diverso: osserva le **chiamate di sistema** (via eBPF) di container e host e applica regole ("una shell è stata aperta in un container web"). È rilevamento di comportamenti anomali, non analisi dell'applicazione.

---

## 8. API, rete, fuzzing e infrastruttura

### Schemathesis, RESTler
- **Schemathesis:** parte da una specifica **OpenAPI/GraphQL** e fa *property-based testing* (libreria Hypothesis): genera input validi e al limite, e controlla errori `5xx` e risposte non conformi allo schema.
- **RESTler (Microsoft):** fuzzing *stateful*: deduce le dipendenze tra richieste (la risposta di un `POST` fornisce l'id da usare in un `GET`) e percorre sequenze realistiche per scovare bug di sicurezza e affidabilità.

### Nmap, Masscan
- **Nmap:** scoperta di host e porte (scansione SYN, UDP), rilevamento di servizi e versioni (`-sV`) e script **NSE** per controlli specifici. `nmap -sV 127.0.0.1`
- **Masscan:** stessa idea ma con uno stack TCP asincrono proprio, in grado di scansionare intere reti in pochi minuti; meno informazioni sui servizi.

### OpenVAS / Greenbone, Nessus
- Scanner di vulnerabilità per **server e dispositivi**: scoprono gli host, identificano servizi e versioni e lanciano migliaia di test (**NVT** in Greenbone, *plugin* in Nessus) alimentati da un *feed* aggiornato. Possono anche accedere con credenziali per controllare patch e configurazioni locali.

### testssl.sh, sslyze
- Controllano la configurazione **TLS**: versioni di protocollo, suite di cifratura, certificato, e vulnerabilità note (Heartbleed, ROBOT, POODLE). `testssl.sh` è uno script shell; `sslyze` una libreria Python utilizzabile in automatico.

### AFL++, libFuzzer, Jazzer
- **Fuzzing guidato dalla copertura.** Il programma viene compilato con strumentazione che misura quali rami del codice si eseguono. Il fuzzer muta gli input e **conserva quelli che aprono nuovi percorsi**, finché non provoca un crash (overflow, accesso fuori limiti, eccezione).
- **AFL++:** processo esterno (file/stdin); **libFuzzer:** nello stesso processo, molto veloce, per librerie C/C++; **Jazzer:** analogo per la JVM.
- **Ideale per** parser e codice che elabora formati binari; richiede di scrivere un piccolo *fuzz target*.

### Lynis, OpenSCAP
- **Lynis:** script che controlla un sistema Linux (permessi, servizi, kernel, SSH, aggiornamenti) e calcola un *hardening index* con suggerimenti.
- **OpenSCAP:** applica contenuti **SCAP** (XCCDF/OVAL) per verificare la conformità a profili come CIS o DISA STIG e produce report e correzioni.

---

## 9. Come leggere e usare i risultati

1. **Triage per gravità e sfruttabilità**: CVSS da solo non basta; incrociate con **EPSS** e **KEV**, e chiedetevi se il codice vulnerabile è raggiungibile.
2. **Deduplicare**: più strumenti segnalano lo stesso problema; confrontate per file/riga/CWE (è lo scopo di `EXPECTED.md`).
3. **Gestire i falsi positivi** in modo tracciabile: annotazione `# nosemgrep`, baseline di `detect-secrets`, `.gitleaksignore`, `.trivyignore` con motivazione e scadenza.
4. **Spostare i controlli a monte** (*shift left*): più un problema viene trovato presto, meno costa correggerlo.
5. **Correggere la causa, non il sintomo**: per un segreto, revocarlo; per una CVE, aggiornare (o sostituire) la libreria; per una injection, usare query parametrizzate.

## 10. Percorso consigliato con questo laboratorio

1. Eseguire `./tools/run-scans.sh`.
2. Aprire `EXPECTED.md` e compilare la tabella di confronto del `README.md` (trovate, mancate, falsi positivi).
3. Ripetere con un secondo strumento della stessa famiglia (per esempio Bandit dopo Semgrep, o Trivy dopo Gitleaks sui segreti) e confrontare.
4. Avviare l'app (`docker compose up --build`) e lanciare ZAP e Nuclei **solo su 127.0.0.1**.
5. Scrivere una regola Semgrep personalizzata che catturi una vulnerabilità sfuggita agli altri strumenti.
