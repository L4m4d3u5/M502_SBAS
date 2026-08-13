# Security Analyse – secure-calendar-training

**Projekt:** secure-calendar-training
**Datum:** 13.08.2026
**Name / Gruppe:** Sebastian Schneuwly

> **Hinweis zur Lesart:** Alle mit `🔧 Methodik` markierten Kästen erklären *wie* ich zu
> der jeweiligen Aussage gekommen bin (welcher Befehl, welche Quelle, welche Überlegung).
> Sie gehören nicht zur eigentlichen Abgabe, sondern dienen der Nachvollziehbarkeit.

---

## 0. Vorgehen im Überblick

Die Analyse folgt einer festen Pipeline. Jeder Schritt beantwortet genau eine Frage:

| Schritt | Frage | Werkzeug |
|---|---|---|
| 1. Inventar | *Was ist überhaupt installiert?* | `npm ls`, `npm ls --all` |
| 2. Detektion | *Wozu gibt es bekannte Schwachstellen?* | `npm audit`, `npm audit --json` |
| 3. Attribution | *Direkt oder transitiv? Wer zieht das rein?* | `npm ls <pkg>`, `npm why`, `isDirect` im JSON |
| 4. Verifikation | *Stimmt die Meldung? Wie gut ist die Quelle?* | GitHub Advisory DB, NVD, Commit/Patch |
| 5. Kontextualisierung | *Trifft das **diese** App?* | Code-Review, Adapter-/Runtime-Analyse |
| 6. Remediation | *Was tun – und bricht dann etwas?* | `npm install <pkg>@latest`, `npm run build` |
| 7. Verifikation des Fixes | *Ist es wirklich weg?* | `npm audit` (Exit-Code!), Build + Smoke-Test |

Der entscheidende Punkt für die Praxis: **Schritt 2 ist billig, Schritt 5 ist die
eigentliche Arbeit.** `npm audit` liefert eine kontextfreie Liste. Ob ein `high`-Finding
für die eigene App wirklich `high` ist, entscheidet erst der Blick in den Code.

> **🔧 Methodik – Warum überhaupt eine Pipeline?**
> Ohne festen Ablauf landet man schnell in einem der zwei typischen Fehlermodi:
> *(a)* blindes `npm audit fix --force`, das Major-Upgrades einspielt und die App bricht,
> oder *(b)* Audit-Fatigue – 6 Findings, "ist ja nur eine Übungs-App", nichts passiert.
> Die Pipeline erzwingt, dass zwischen Detektion und Aktion eine Bewertung liegt.

---

## 1. Gefundene Sicherheitsmeldungen

_Tragt hier alle Findings aus `npm audit` ein._

**Ausgangslage nach `npm install`:** npm meldet bereits beim Install
`6 vulnerabilities (1 moderate, 5 high)`. Es gibt also **schon vor dem eigentlichen Audit**
einen Hinweis auf Sicherheitsprobleme – npm führt am Ende jeder Installation automatisch
einen Audit-Lauf aus und gibt nur die Zusammenfassung aus.

**`npm audit` bestätigt das:** 6 betroffene Packages – **5 × high, 1 × moderate, 0 × critical**.
Baumgrösse: 89 Packages (11 prod, 79 dev, 23 optional) bei nur 12 direkten Dependencies.

| Nr. | Package | Version | Severity | Advisory (CVE / GHSA) |
|---|---|---|---|---|
| 1 | axios | 0.21.1 | **high** (24 Advisories: 8 high, 15 moderate, 1 low) | u. a. GHSA-pjwm-pj3p-43mv / CVE-2026-44492 (NO_PROXY-Bypass → SSRF, CVSS 8.6) · GHSA-cph5-m8f7-6c5x / CVE-2021-3749 (ReDoS, 7.5) · GHSA-jr5f-v2jv-69x6 / CVE-2025-27152 (SSRF + Credential Leak) · GHSA-wf5p-g6vw-rhxx / CVE-2023-45857 (XSRF-Token-Leak, 6.5) · GHSA-pf86-5x62-jrwf / CVE-2026-42033 (Prototype Pollution, 7.4) |
| 2 | lodash | 4.17.19 | **high** (5 Advisories: 2 high, 3 moderate) | GHSA-r5fr-rjxr-66jc / CVE-2026-4800 (Code Injection via `_.template`, CVSS 8.1) · GHSA-35jh-r3h4-6jhm / CVE-2021-23337 (Command Injection, 7.2) · GHSA-29mw-wpgm-hmr9 / CVE-2020-28500 (ReDoS, 5.3) · GHSA-f23m-r3pf-42rh / CVE-2026-2950 + GHSA-xxjr-mmjv-4gpg / CVE-2025-13465 (Prototype Pollution in `_.unset`/`_.omit`, je 6.5) |
| 3 | moment | 2.29.1 | **high** (2 Advisories) | GHSA-8hfj-j24r-96c4 / CVE-2022-24785 (Path Traversal in `moment.locale`, CVSS 7.5) · GHSA-wc69-rhjr-hc9g / CVE-2022-31129 (ReDoS beim String-Parsing, 7.5) |
| 4 | nanoid | 3.1.25 | **high** (4 Advisories: 2 high, 2 moderate) | GHSA-2v37-7h3g-55p8 / CVE-2026-67213 (Endlosschleife bei `size = 0`, 5.9) · GHSA-28wg-ghj8-5hjv / CVE-2026-67214 (Endlosschleife bei negativer `size`, 5.9) · GHSA-qrpm-p2h7-hrv2 / CVE-2021-23566 (Information Exposure, 5.5) · GHSA-mwcw-c2x4-8c55 / CVE-2024-55565 (vorhersagbare IDs bei nicht-ganzzahliger `size`, 4.3) |
| 5 | vite | 4.3.9 | **high** (16 Advisories: 3 high, 11 moderate, 2 low) | GHSA-c24v-8rfc-w8vw / CVE-2024-23331 (`server.fs.deny`-Bypass, CVSS 7.5) · GHSA-fx2h-pf6j-xcff / CVE-2026-53571 (fs.deny-Bypass Windows, 7.5) · GHSA-vg6x-rcgg-rjx6 / CVE-2025-24010 (beliebige Websites können den Dev-Server abfragen, 6.5) · GHSA-64vr-g452-qvp3 / CVE-2024-45812 (DOM Clobbering → XSS, 6.4) |
| 6 | esbuild | 0.17.19 | moderate (1 Advisory) | GHSA-67mh-4wv8-2f99 (**kein CVE vergeben**) – jede Website kann Requests an den Dev-Server senden und die Antwort lesen, CVSS 5.3 |

**Empfohlene Fixes laut Audit-Ausgabe:** alle nur über `npm audit fix --force`, weil die
Zielversionen ausserhalb der in `package.json` fixierten Ranges liegen:
axios → 0.21.4, lodash → 4.18.1, moment → 2.30.1, nanoid → 3.3.18, vite → 4.5.14
(letzteres behebt esbuild gleich mit).

> **🔧 Methodik – Was `npm audit` technisch tut**
> `npm audit` schickt den aufgelösten Dependency-Baum (aus `package-lock.json`) an den
> Registry-Endpoint `/-/npm/v1/security/audits/quick` und bekommt die Advisories zurück,
> die auf die installierten Versionen matchen. Datenbasis ist die **GitHub Advisory
> Database** – npm-Advisories werden dorthin gespiegelt. Zwei Konsequenzen:
> 1. **Es braucht Netz**, und das Ergebnis ist ein Momentaufnahme-Snapshot. Derselbe
>    Befehl kann morgen mehr Findings liefern, ohne dass sich eine Zeile Code geändert hat
>    (neue Advisories) – genau das ist hier bei axios passiert: 24 Advisories, viele davon
>    lange nach dem Release von 0.21.1 publiziert.
> 2. **Nur bekannte Schwachstellen** werden gefunden. `npm audit` ist keine
>    Code-Analyse, kein SAST, und findet weder Zero-Days noch Bugs im eigenen Code.
>
> **Auswertung mit `--json`:** Die Textausgabe ist bei 24 axios-Advisories unbrauchbar.
> Ich habe deshalb `npm audit --json` genommen und gezielt ausgewertet:
> ```bash
> npm audit --json > audit-before.json
> node -e "
>   const a = require('./audit-before.json');
>   for (const [name, v] of Object.entries(a.vulnerabilities)) {
>     console.log('###', name, '| range:', v.range, '| sev:', v.severity, '| direkt:', v.isDirect);
>     v.via.filter(x => typeof x !== 'string')
>          .forEach(x => console.log('   -', x.url.split('/').pop(), x.severity,
>                                    '| CVSS:', x.cvss && x.cvss.score, '|', x.title));
>   }
>   console.log(a.metadata.vulnerabilities);
> "
> ```
> Wichtige Felder im JSON: `isDirect` (direkt/transitiv), `range` (betroffene Versionen),
> `via` (Kette der Ursachen – Strings = andere Packages, Objekte = echte Advisories),
> `effects` (welche Packages durch dieses mitbetroffen sind), `fixAvailable`
> (inkl. `isSemVerMajor`).
>
> **Severity-Lesart – wichtig:** Die Severity *am Package* ist das **Maximum** über alle
> seiner Advisories, nicht ein Durchschnitt. `axios: high` heisst also nicht "alles an
> axios ist high", sondern "mindestens ein Advisory ist high". Und der CVSS-Score ist ein
> **Base Score** – kontextfrei, ohne Wissen über meine App. Genau deshalb gibt es Kapitel 4.

---

## 2. Betroffene Packages

_Beschreibt für jedes Finding, ob es sich um eine direkte oder transitive Dependency handelt._

| Package | Direkt / Transitiv | Eingebunden durch |
|---|---|---|
| axios | **Direkt** (prod) | `dependencies` in `package.json` (`axios@0.21.1`), importiert in `src/App.tsx:5` |
| lodash | **Direkt** (prod) | `dependencies` (`lodash@4.17.19`), importiert in `src/App.tsx:3` |
| moment | **Direkt** (prod) | `dependencies` (`moment@2.29.1`), importiert in `src/App.tsx:2` |
| nanoid | **Direkt** (prod) | `dependencies` (`nanoid@3.1.25`), importiert in `src/App.tsx:4`; zusätzlich **transitiv** über `vite → postcss → nanoid@3.3.18` – diese zweite Instanz ist *nicht* betroffen |
| vite | **Direkt** (dev) | `devDependencies` (`vite@4.3.9`) – Build-Tool, landet nicht im Browser-Bundle |
| esbuild | **Transitiv** | `vite@4.3.9 → esbuild@0.17.19` – nirgends selbst eingebunden, kommt nur über vite mit |

**Dependency Tree (`npm ls`, Ebene 1) – 12 direkte Dependencies:**

- `dependencies` (6): axios, lodash, moment, nanoid, react, react-dom
- `devDependencies` (6): @types/lodash, @types/react, @types/react-dom,
  @vitejs/plugin-react, typescript, vite

**Transitive Dependencies:** alles, was `npm ls --all` zusätzlich zeigt – insgesamt
**89 Packages**. Die grössten Blöcke: `@vitejs/plugin-react → @babel/core → …` (Babel zieht
allein ~30 Packages: parser, traverse, types, browserslist, caniuse-lite …),
`vite → esbuild / postcss / rollup`, `axios → follow-redirects`,
`react-dom → scheduler → loose-envify → js-tokens`.

**Was bedeutet `deduped`?**
Der Hinweis bedeutet, dass ein Package an dieser Stelle im Baum zwar *benötigt* wird, aber
**nicht nochmals installiert** wurde, weil bereits eine range-kompatible Version weiter oben
in `node_modules/` liegt. npm hebt Packages so weit wie möglich an die Wurzel
(*Hoisting*) und teilt sie zwischen allen Konsumenten. Beispiele hier:

```
├─┬ react-dom@18.2.0
│ ├── react@18.2.0 deduped        ← react liegt schon auf Top-Level
│ └─┬ scheduler@0.23.2
│   └── loose-envify@1.4.0 deduped
```

Praktische Konsequenzen:
- **Ein `deduped`-Eintrag = dieselbe Instanz im Speicher.** Bei stateful Packages
  (React, singleton-artige Libs) ist das der Unterschied zwischen "funktioniert" und
  "zwei React-Kopien, Hooks-Error".
- **Für Security heisst es: eine Version = eine Fundstelle.** Ohne Dedupe kann dasselbe
  Package in mehreren Versionen im Baum liegen – dann kann eine Instanz gepatcht sein und
  eine andere nicht. Genau das ist hier bei **nanoid** der Fall: `nanoid@3.1.25` auf
  Top-Level (verwundbar, aus `package.json`) und `nanoid@3.3.18` unter `postcss`
  (nicht verwundbar). Kein Dedupe, weil die Ranges inkompatibel sind – deshalb zwei Kopien.

**Warum auch transitive Dependencies ein Sicherheitsproblem sind:**

1. **Gleiche Rechte, gleicher Prozess.** Transitiver Code läuft mit denselben Privilegien
   wie eigener Code – im Browser mit vollem DOM-/Storage-Zugriff, im Build-Prozess mit
   Dateisystem- und Netzzugriff. Node kennt keine Sandbox pro Package.
2. **Man hat sie nicht ausgewählt und sieht sie nicht.** In `package.json` stehen 12
   Einträge, installiert sind 89. Der Grossteil der Angriffsfläche ist unsichtbar, wenn
   man nur `package.json` liest.
3. **Man kann sie nicht direkt patchen.** Die Version bestimmt das Parent-Package.
   Genau das zeigt esbuild hier: die Lücke steckt in `esbuild@0.17.19`, behoben wird sie
   aber über ein Update von **vite** – `npm install esbuild@latest` wäre wirkungslos
   gewesen, weil vite@4.3.9 weiterhin `esbuild@^0.17.5` verlangt hätte.
   (Notfall-Werkzeuge dafür: `overrides` in `package.json`, oder `npm-force-resolutions`.)
4. **Sie sind das Einfallstor für Supply-Chain-Angriffe.** `event-stream`, `ua-parser-js`,
   `node-ipc` – in allen Fällen war das kompromittierte Package eine transitive
   Dependency, die kaum jemand bewusst installiert hatte.

> **🔧 Methodik – Direkt vs. transitiv sauber bestimmen**
> Drei sich ergänzende Wege, alle habe ich benutzt:
> ```bash
> npm ls                    # Ebene 1 = exakt die direkten Dependencies
> npm ls <paket> --all      # zeigt ALLE Pfade zu einem Package im Baum
> npm why <paket>           # (npm ≥ 7) "warum ist das hier?" – Begründungskette
> ```
> Der `npm ls nanoid --all`-Aufruf war hier entscheidend – er hat die zweite,
> nicht-verwundbare Instanz unter `postcss` sichtbar gemacht, die man in der
> Audit-Ausgabe nicht sieht:
> ```
> ├── nanoid@3.1.25            ← direkt, verwundbar
> └─┬ vite@4.3.9
>   └─┬ postcss@8.5.26
>     └── nanoid@3.3.18        ← transitiv, nicht betroffen
> ```
> Gegenprobe im JSON: `vulnerabilities.nanoid.isDirect === true`, und die `effects`-Liste
> von esbuild enthält `["vite"]` – das ist die maschinenlesbare Version von
> "esbuild ist transitiv und zieht vite mit rein".

---

## 3. Quelle und Glaubwürdigkeit

_Wählt mindestens zwei Findings aus und bewertet die Informationsquelle._

> **🔧 Methodik – Wie ich die Advisories verifiziert habe**
> `npm audit` liefert **nur die GHSA-ID und einen Link** – keine CVE-Nummer, keine
> technischen Details. Man *muss* also zur Primärquelle. Statt 6 Seiten von Hand zu öffnen,
> habe ich die öffentliche GitHub-Advisory-API abgefragt (kein Token nötig, read-only):
> ```bash
> curl -s https://api.github.com/advisories/GHSA-35jh-r3h4-6jhm | jq \
>   '{cve: .cve_id, severity, cvss: .cvss.score, published: .published_at,
>     affected: [.vulnerabilities[] | {pkg: .package.name,
>                range: .vulnerable_version_range, fixed: .first_patched_version}]}'
> ```
> Damit bekommt man in einem Rutsch: CVE-Mapping, CVSS-Vektor, betroffene Ranges,
> erste gepatchte Version, Publikationsdatum und die referenzierten Commits/Issues.
> Die drei relevanten Quellen und ihr Verhältnis zueinander:
>
> | Quelle | Rolle | Stärke | Schwäche |
> |---|---|---|---|
> | **GitHub Advisory DB** (`github.com/advisories`) | Kuratierte DB, Basis für `npm audit` | Ökosystem-genaue Versions-Ranges, verlinkt Patch-Commit, oft schneller als NVD | GitHub-zentriert |
> | **NVD / NIST** (`nvd.nist.gov`) | Autoritatives CVE-Register | Herstellerneutral, CVSS-Vektor offiziell | Ranges oft unpräzise/zu breit, Verzögerung bei der Anreicherung |
> | **Repo selbst** (Commit, Release Notes, Issue) | Ground Truth | Man sieht den echten Fix-Diff | Nicht normiert, manchmal gar nicht kommuniziert |
>
> Faustregel: **GHSA für "betrifft mich?", NVD für "wie schlimm generell?",
> Patch-Commit für "was genau war kaputt?".**

### Finding 1: Package **lodash**

- **Advisory-Link:** https://github.com/advisories/GHSA-35jh-r3h4-6jhm
  (NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-23337)
- **CVE / GHSA:** CVE-2021-23337 / GHSA-35jh-r3h4-6jhm · publiziert 06.05.2021 ·
  CVSS 3.1 Base Score **7.2 (High)** · CWE-77 / CWE-94 (Command / Code Injection)
- **Betroffene Versionen:** `lodash < 4.17.21` (installiert: **4.17.19 → betroffen**).
  Das Advisory listet zusätzlich `lodash-es`, `lodash.template`, `lodash-rails` –
  die gleiche Codebasis wird über mehrere npm-Packages verteilt.
- **Fix-Version:** **4.17.21**
- **Beschreibung der Schwachstelle:**
  `_.template()` kompiliert einen String zu einer JS-Funktion – intern via `Function()`.
  Die Option `variable` (der Name der Daten-Variable im generierten Code) wurde ungeprüft
  in den generierten Quelltext interpoliert. Ein Angreifer, der `variable` kontrolliert,
  kann aus dem Bezeichner ausbrechen und beliebigen Code in die kompilierte Funktion
  einschleusen – in Node ist das RCE, im Browser XSS mit vollem Kontext.
  Der Fix in 4.17.21 validiert `options.variable` gegen eine Whitelist für gültige
  JS-Bezeichner (`reIsIdentifier`) und wirft sonst.
  **Voraussetzung für die Ausnutzung:** `_.template()` wird mit angreifer-kontrollierter
  `variable`-Option aufgerufen. Das ist ein enger Pfad – wichtig für Kapitel 4.
- **Glaubwürdigkeit der Quelle:** **Sehr hoch.**
  - Reserviert und publiziert von **Snyk** als CNA, gegengeprüft von GitHub Security Lab,
    in NVD übernommen – drei unabhängige Instanzen mit derselben Aussage.
  - Das Advisory verlinkt den **konkreten Fix-Commit** im `lodash/lodash`-Repo; der Diff
    ist öffentlich nachvollziehbar (man kann die Prüfung im Code selbst sehen).
  - Der Maintainer hat den Fix in einem regulären Release ausgeliefert und die Version
    ist als `first_patched_version` maschinenlesbar hinterlegt.
  - Versions-Range ist **präzise und plausibel** (`< 4.17.21`) und deckt sich mit dem
    Commit-Datum – kein Hinweis auf eine überbreite, pauschale Angabe.
  - Für die Praxis wichtig: die Quelle sagt klar, *unter welcher Bedingung* die Lücke
    greift. Advisories ohne diese Angabe sind deutlich schwerer zu bewerten.

### Finding 2: Package **moment**

- **Advisory-Link:** https://github.com/advisories/GHSA-8hfj-j24r-96c4
  (NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-24785)
- **CVE / GHSA:** CVE-2022-24785 / GHSA-8hfj-j24r-96c4 · publiziert 04.04.2022 ·
  CVSS 3.1 Base Score **7.5 (High)** · CWE-22 / CWE-27 (Path Traversal)
- **Betroffene Versionen:** `moment < 2.29.2` (installiert: **2.29.1 → betroffen**)
- **Fix-Version:** **2.29.2**
- **Beschreibung der Schwachstelle:**
  `moment.locale(name)` lädt Locale-Dateien serverseitig per `require()`, wobei `name`
  in den Pfad eingebaut wurde. Ein Name wie `../../../../etc/passwd` bzw. ein Pfad auf
  eine beliebige `.js`-Datei führt dazu, dass Dateien ausserhalb des Locale-Verzeichnisses
  geladen werden – bis hin zum Ausführen fremden JS-Codes, wenn der Angreifer eine
  `.js`-Datei platzieren kann. Der Fix sanitisiert den Locale-Namen vor dem Auflösen.
  **Voraussetzung:** Die Anwendung ruft `moment.locale()` (oder `moment.updateLocale`) mit
  benutzergesteuertem Namen auf **und** läuft in Node (im Browser gibt es kein `require`
  auf das Dateisystem).
- **Glaubwürdigkeit der Quelle:** **Sehr hoch.**
  - Das Advisory stammt **vom Moment.js-Projekt selbst** (GitHub Security Advisory,
    publiziert über das eigene Repo) – also vom Maintainer, der die betroffene Codestelle
    kennt. Höhere Autorität als ein Drittmelder geht kaum.
  - Es enthält eine explizite **Workaround-Angabe** ("Locale-Namen gegen eine Whitelist
    prüfen, falls kein Upgrade möglich") – ein typisches Merkmal sorgfältig gepflegter
    Advisories und ein starkes Signal, dass jemand die Lücke wirklich verstanden hat.
  - CVE über GitHub als CNA vergeben, in NVD gespiegelt, CVSS-Vektor identisch.
  - Range und Fix-Version stimmen mit dem Release-Verlauf von moment überein
    (2.29.2 ist ein Patch-Release, das genau diesen Fix enthält).
  - Kleiner Praxis-Hinweis: Moment.js ist offiziell **im Maintenance-Mode** – das Projekt
    empfiehlt selbst Alternativen (Luxon, date-fns, Temporal API). Für die
    Glaubwürdigkeit des Advisories irrelevant, für die *strategische* Bewertung aber
    durchaus: ein Package, das nur noch Security-Fixes bekommt, ist mittelfristig
    ein Risiko für sich.

### Finding 3 (Kontrastfall): Package **esbuild** – transitiv, GHSA ohne CVE

- **Advisory-Link:** https://github.com/advisories/GHSA-67mh-4wv8-2f99
- **CVE / GHSA:** **GHSA-67mh-4wv8-2f99 – kein CVE zugewiesen** · publiziert 10.02.2025 ·
  CVSS 3.1 Base Score **5.3 (Moderate)** · CWE-346 (Origin Validation Error)
- **Betroffene Versionen:** `esbuild <= 0.24.2` (installiert: **0.17.19 → betroffen**)
- **Fix-Version:** **0.25.0**
- **Beschreibung der Schwachstelle:**
  Der esbuild-Dev-Server setzte `Access-Control-Allow-Origin: *` und prüfte den `Origin`
  von Requests nicht. Jede beliebige Website, die man im Browser offen hat, während
  lokal `npm run dev` läuft, kann damit `fetch('http://localhost:5173/src/App.tsx')`
  absetzen **und die Antwort lesen** – also Quellcode aus dem laufenden Dev-Server
  exfiltrieren. Vite@4.3.9 ist über denselben Mechanismus betroffen
  (GHSA-vg6x-rcgg-rjx6).
- **Glaubwürdigkeit der Quelle:** **Hoch – aber mit Einschränkung.**
  - Publiziert als GitHub Security Advisory im esbuild-Repo, mit klarer technischer
    Beschreibung und benannter Fix-Version. Der Fix (Origin-Prüfung) ist im Release
    0.25.0 nachvollziehbar.
  - **Aber: kein CVE.** Wer nur die NVD abfragt oder einen Scanner benutzt, der
    ausschliesslich auf CVE-IDs matcht, findet dieses Finding **nicht**. Das ist die
    praktisch wichtigste Lektion dieses Kapitels: Die CVE-Datenbank ist **nicht**
    vollständig für npm-Ökosystem-Schwachstellen. GHSA ist hier die Primärquelle,
    nicht die abgeleitete.
  - Besonders anschaulich im direkten Vergleich: Das **inhaltlich gleiche** Problem bei
    vite (GHSA-vg6x-rcgg-rjx6, derselbe Angriffsvektor, ebenfalls CVSS 6.5) **hat** eine
    CVE-Nummer – **CVE-2025-24010**. Zwei Advisories zur selben Klasse von Bug, eines
    mit und eines ohne CVE. Ob eine CVE vergeben wird, hängt vom Meldeweg und vom
    zuständigen CNA ab, nicht von der Schwere. Das ist ein guter Grund, GHSA-IDs im
    eigenen Tracking als führenden Schlüssel zu verwenden und CVE nur als Zusatzfeld.
  - Bewertung des CVSS: 5.3 (moderate) ist der kontextfreie Base Score. Für einen
    Entwickler mit `npm run dev` und offenem Browser ist die reale Ausnutzbarkeit
    höher als "moderate" nahelegt – siehe Kapitel 4.

---

## 4. Relevanz für die Applikation

_Bewertet jedes Finding im Kontext der Kalender-App._

> **🔧 Methodik – Wie ich Relevanz bestimme (4 Filter)**
> Die Severity aus dem Audit ist ein **Base Score ohne Kontext**. Um von "high" auf
> "betrifft mich" zu kommen, lege ich vier Filter an, in dieser Reihenfolge:
>
> **Filter 1 – Wird das Package überhaupt geladen?**
> ```bash
> grep -rn "from 'lodash'\|from \"lodash\"" src/    # Import vorhanden?
> ```
> Hier: alle 4 prod-Packages werden in `src/App.tsx` importiert. Kein "toter" Fund.
>
> **Filter 2 – Wird die *konkret betroffene API* aufgerufen?**
> Das ist der wirksamste Filter und der, den Scanner nicht können. Ein Advisory zu
> `_.template()` ist irrelevant, wenn die App nur `_.sortBy()` benutzt. Also: Advisory
> lesen → betroffene Funktion identifizieren → im Code danach greppen.
> ```bash
> grep -rn "_\.\|moment\.\|nanoid(" src/
> ```
>
> **Filter 3 – In welcher Runtime läuft der Code?**
> Entscheidend, weil viele npm-Packages **zwei Implementierungen** ausliefern. Bei axios
> lässt sich das direkt beweisen – das `browser`-Feld in `axios/package.json` ersetzt den
> Node-HTTP-Adapter durch einen Stub:
> ```json
> "browser": {
>   "./lib/adapters/http.js": "./lib/helpers/null.js",
>   "./lib/platform/node/index.js": "./lib/platform/browser/index.js"
> }
> ```
> Gegenprobe im gebauten Bundle – Beweis statt Vermutung:
> ```bash
> npm run build
> grep -o "XMLHttpRequest" dist/assets/*.js | wc -l              # → 2  (XHR-Adapter drin)
> grep -c "Proxy-Authorization\|no_proxy\|proxy-from-env" dist/assets/*.js   # → 0  (Node-Code raus)
> ```
> (Bewusst `grep -o | wc -l` statt `grep -c`: Das Bundle ist minifiziert und besteht aus
> sehr wenigen Zeilen – `grep -c` zählt *Zeilen mit Treffer*, nicht Treffer. Beim
> Negativ-Nachweis ist das egal, 0 bleibt 0; beim Positiv-Nachweis nicht.)
> Ergebnis: **Der gesamte Node-Adapter von axios ist nicht im Bundle.** Damit sind alle
> Proxy-/NO_PROXY-/SSRF-/`maxRedirects`-Advisories – also die Mehrheit der 24 axios-Findings –
> für diese App faktisch nicht erreichbar.
>
> **Filter 4 – Ist der Eingabepfad von aussen kontrollierbar, und was steht auf dem Spiel?**
> ReDoS ist nur relevant, wenn ein Angreifer den zu parsenden String bestimmt.
> Prototype Pollution als *Gadget* ist nur relevant, wenn es überhaupt eine
> Pollution-Primitive in der App gibt. Und bei einer reinen Client-App ohne Backend,
> ohne Auth und ohne Persistenz ist der maximale Schaden strukturell begrenzt.

**Architektur-Kontext dieser App** (Basis für alle Bewertungen):

- Reine **Client-Side SPA** (React 18 + Vite). **Kein eigenes Backend, kein Server,
  kein Node zur Laufzeit.**
- **Keine Authentifizierung, keine Sessions, keine Cookies, kein `localStorage`.**
  Termine leben ausschliesslich im React-State und sind beim Reload weg.
- Der einzige Netzwerkzugriff ist ein `GET` auf eine **fest verdrahtete** öffentliche
  Demo-URL (`https://jsonplaceholder.typicode.com/todos`, `src/App.tsx:17`) – ohne
  Credentials, ohne `withCredentials`, ohne Auth-Header.
- Verarbeitete Daten: Termin-Titel, Datum, Uhrzeit, Beschreibung – **keine
  personenbezogenen oder sensiblen Daten**, keine Weitergabe an Dritte.
- Genutzte Library-APIs (vollständige Liste aus `src/App.tsx`):
  `moment(iso).format()`, `moment().add()` · `_.sortBy()`, `_.groupBy()` ·
  `nanoid()` (immer **ohne Argument**) · `axios.get(url)`.

| Package | Wird verwendet? | Betroffene Funktion genutzt? | Läuft im Browser / Build? | Relevanz | Begründung |
|---|---|---|---|---|---|
| **vite** | Ja | **Ja** (Dev-Server) | Build / Dev | **mittel** | GHSA-vg6x-rcgg-rjx6 / CVE-2025-24010: Jede besuchte Website kann während laufendem `npm run dev` den Dev-Server abfragen und Antworten lesen → Quellcode-Exfiltration vom Entwicklerrechner. Realistisch ausnutzbar (Dev + Browser laufen praktisch immer parallel), aber Angriff auf die *Entwicklungsumgebung*, nicht auf die ausgelieferte App. Die `server.fs.deny`-Bypasses (CVE-2024-23331 u. a.) setzen zusätzlich einen exponierten Server (`--host`) voraus → für sich genommen niedriger. Kein vite-Code landet im Produktions-Bundle. |
| **esbuild** | Ja (transitiv über vite) | **Ja** (Dev-Server) | Build / Dev | **mittel** | Identischer Angriffsvektor wie vite (GHSA-67mh-4wv8-2f99, CWE-346). Gleiche Bewertung, gleiche Einschränkung: Dev-Zeit-Risiko, kein Laufzeit-Risiko für Endnutzer. |
| **axios** | Ja (`axios.get`, `src/App.tsx:95`) | **Teilweise / nur Randfälle** | **Browser** (XHR-Adapter) | **niedrig** | Die grosse Mehrheit der 24 Advisories betrifft den **Node-HTTP-Adapter** (NO_PROXY-Bypass, SSRF, Proxy-Authorization-Leaks, `maxRedirects`/`maxContentLength`) – im Bundle nachweislich **nicht enthalten** (siehe Filter 3). Browser-relevant blieben theoretisch: ReDoS (CVE-2021-3749, Input ist aber eine hartkodierte URL) und CVE-2023-45857 (XSRF-Token-Leak – die App nutzt weder XSRF-Token noch `withCredentials`). Die Prototype-Pollution-**Gadgets** setzen eine bereits vorhandene Pollution-Primitive voraus, die es hier nicht gibt. Keine Credentials im Spiel. |
| **lodash** | Ja (`_.sortBy`, `_.groupBy`) | **Nein** | Browser | **niedrig** | Die beiden high-Findings betreffen `_.template()` (CVE-2021-23337, CVE-2026-4800) – **wird nirgends aufgerufen**. Die Prototype-Pollution-Advisories betreffen `_.unset()` / `_.omit()` – ebenfalls nicht verwendet. Der ReDoS (CVE-2020-28500) sitzt in `_.trim`/`_.toNumber` – nicht verwendet. `_.sortBy` und `_.groupBy` sind von keinem der 5 Advisories betroffen. → Verwundbarer Code ist im Bundle, wird aber nicht erreicht. |
| **moment** | Ja (`format`, `add`) | **Nein** | Browser | **niedrig** | Der Path Traversal (CVE-2022-24785) betrifft `moment.locale()` mit dynamischem Namen und **`require()` in Node** – die App ruft `moment.locale()` gar nicht auf und läuft nicht in Node. Der ReDoS (CVE-2022-31129) greift beim Parsen langer, nicht-ISO-Datumsstrings; die geparsten Werte stammen aus `<input type="date">` (Browser erzwingt `YYYY-MM-DD`) bzw. werden intern mit `moment().add()` berechnet. Kein realistischer Angreiferpfad. Zusätzlich: ReDoS in einer reinen Client-App friert nur den eigenen Tab ein – Self-DoS. |
| **nanoid** | Ja (`nanoid()`, 6 Aufrufstellen) | **Nein** | Browser | **niedrig** | **Alle vier Advisories setzen ein `size`-Argument voraus** (`size = 0`, negative `size`, nicht-ganzzahlige `size`) – die App ruft konsequent `nanoid()` **ohne Argument** auf und nutzt damit den Default-Pfad mit `crypto.getRandomValues()`. Zudem sind die IDs reine React-Keys für lokale Termine, nicht sicherheitsrelevant (keine Tokens, keine URLs, keine Ratekritikalität). |

**Zusammenfassende Relevanz-Bewertung:**

| Relevanz | Findings | Konsequenz |
|---|---|---|
| hoch | – | – |
| **mittel** | vite, esbuild | Dev-Server-Exposure gegenüber beliebigen Websites – betrifft den Entwicklerrechner, nicht die ausgelieferte App. **Höchste tatsächliche Priorität**, obwohl esbuild formal nur `moderate` ist. |
| **niedrig** | axios, lodash, moment, nanoid | Verwundbarer Code ist im Bundle vorhanden, die betroffenen APIs werden nicht aufgerufen bzw. der Node-Pfad ist gar nicht eingebunden. |
| nicht relevant / unklar | – | – |

**Die zentrale Beobachtung:** Fünf von sechs Findings sind formal `high`, aber keines
davon ist für diese App `hoch` relevant. Umgekehrt ist esbuild formal nur `moderate`,
aber praktisch das am ehesten ausnutzbare Problem. **Severity ≠ Risiko.**

**Wichtige Einschränkung – warum trotzdem alles gepatcht wird:** "Niedrige Relevanz"
heisst *nicht* "nicht handeln". Die Bewertung gilt für den **heutigen** Code. Sobald
jemand `_.template()` einbaut, `moment.locale()` aus einem URL-Parameter setzt oder
`nanoid(len)` mit variabler Länge aufruft, kippt die Einstufung sofort – ohne dass das
Advisory sich geändert hätte. Die Relevanzbewertung dient der **Priorisierung**
(was zuerst, was mit Deployment-Fenster), nicht der Rechtfertigung von Nichtstun.
Da hier alle Updates ohnehin verfügbar und günstig waren, wurde alles behoben.

---

## 5. Massnahmen

_Beschreibt, welche Massnahmen ihr ergriffen habt._

### Schritt 1: `npm audit fix` – bewusst zuerst probiert, ohne Wirkung

```bash
npm audit fix
# → keine Änderung. Danach weiterhin: 6 vulnerabilities (1 moderate, 5 high)
```

**Warum es nichts tut:** `package.json` pinnt alle Versionen **exakt** (`"lodash": "4.17.19"`
ohne `^` oder `~`). `npm audit fix` darf per Definition nur innerhalb des deklarierten
Ranges aktualisieren – und ein exakter Pin *ist* ein Range mit genau einem Element.
Deshalb die Meldung `Will install X, which is outside the stated dependency range` und
der Verweis auf `--force`.

**`npm audit fix --force` habe ich bewusst nicht benutzt.** Es ignoriert die deklarierten
Ranges *und* SemVer-Major-Grenzen und schreibt `package.json` in einem einzigen Rutsch um –
ohne dass man je Package entscheidet, ob man den Major-Sprung will. Bei 6 Packages, davon
mehrere mit Major-Bump, ist das ein unkontrollierbarer Change. Stattdessen: Package für
Package, mit Build dazwischen.

### Schritt 2: Gezielte Updates

```bash
# Runtime-Dependencies (landen im Browser-Bundle)
npm install moment@latest lodash@latest axios@latest nanoid@latest
# → added 23 packages, changed 4 packages | danach: 2 vulnerabilities (1 moderate, 1 high)

# Build-Toolchain (Dev-/Build-Zeit)
npm install -D vite@latest @vitejs/plugin-react@latest
# → added 10 packages, removed 42 packages | danach: found 0 vulnerabilities
```

| Package | Massnahme | Befehl | Alt → Neu | SemVer |
|---|---|---|---|---|
| moment | Update auf latest | `npm install moment@latest` | 2.29.1 → **2.30.1** | minor |
| lodash | Update auf latest | `npm install lodash@latest` | 4.17.19 → **4.18.1** | minor |
| axios | Update auf latest | `npm install axios@latest` | 0.21.1 → **1.19.0** | **major** |
| nanoid | Update auf latest | `npm install nanoid@latest` | 3.1.25 → **6.0.1** | **major ×3** |
| vite | Update auf latest (dev) | `npm install -D vite@latest` | 4.3.9 → **8.2.1** | **major ×4** |
| @vitejs/plugin-react | Peer-Kompatibilität zu vite 8 | `npm install -D @vitejs/plugin-react@latest` | 4.0.0 → **6.0.5** | **major ×2** |
| esbuild | *keine direkte Massnahme* – **aus dem Baum entfernt** | (Folge des vite-Updates) | 0.17.19 → **nicht mehr vorhanden** | – |

> **🔧 Methodik – Drei Dinge, die hier bemerkenswert sind**
>
> **1. `@vitejs/plugin-react` musste mit, obwohl es kein Finding hatte.**
> Das Plugin deklariert vite als **Peer-Dependency**. Version 4.0.0 akzeptiert `vite@^4`,
> nicht `vite@^8`. Ein Update von vite allein hätte einen `ERESOLVE`-Peer-Konflikt oder –
> schlimmer – ein stillschweigend inkompatibles Setup ergeben. **Lehre:** Security-Updates
> ziehen oft nicht-sicherheitsrelevante Updates nach; die Einheit der Änderung ist selten
> ein einzelnes Package.
>
> **2. esbuild wurde nicht gepatcht, sondern ist verschwunden.**
> ```bash
> npm ls esbuild --all
> # → (empty)
> node -e "console.log(Object.keys(require('vite/package.json').dependencies))"
> # → [ 'lightningcss', 'picomatch', 'postcss', 'rolldown', 'tinyglobby' ]
> ```
> Vite 8 verwendet **rolldown** statt esbuild/rollup. Das Finding ist also nicht durch
> "esbuild auf 0.25.0" behoben, sondern weil das verwundbare Package die Dependency-Kette
> verlassen hat. **Das ist eine dritte Art von Remediation** neben "updaten" und
> "ersetzen": *das Parent hat den Abhängigkeitsbaum umgebaut.* Der Audit-Vorschlag lautete
> ursprünglich "vite → 4.5.14" (esbuild bleibt drin, aber gepatcht); der Weg über
> `@latest` war ein anderer und hat mehr Angriffsfläche entfernt.
>
> **3. `npm install <pkg>@latest` ändert die Versions-Strategie.**
> Aus exakten Pins wurden Caret-Ranges:
> ```diff
> -    "axios": "0.21.1",
> +    "axios": "^1.19.0",
> ```
> Das ist ein bewusster, dokumentierter Nebeneffekt: `^` erlaubt künftig automatische
> Patch-/Minor-Updates beim nächsten frischen `npm install` – gut für Security-Patches,
> aber nur akzeptabel, weil `package-lock.json` committet wird und CI mit `npm ci`
> reproduzierbar installiert. Wer exakte Pins will, muss stattdessen
> `npm install --save-exact <pkg>@<version>` verwenden.

### Nebeneffekt auf die Baumgrösse

| | vorher | nachher |
|---|---|---|
| Packages gesamt | 89 | **82** |
| davon `prod` | 11 | **36** |
| davon `dev` | 79 | **47** |

Der prod-Anteil ist deutlich gewachsen: axios 1.x hat vier eigene Runtime-Dependencies
(`follow-redirects`, `form-data`, `https-proxy-agent`, `proxy-from-env`), die einen
Teilbaum von ~25 Packages nachziehen (`combined-stream`, `mime-types`, `es-set-tostringtag`, …).
axios 0.21.1 hatte nur `follow-redirects`.

**Bewertung:** Das ist ein realer Trade-off, kein reiner Gewinn – mehr prod-Packages
bedeuten mehr künftige Angriffsfläche und mehr Audit-Rauschen. Hier vertretbar, weil
der Grossteil davon (form-data, https-proxy-agent, proxy-from-env) **Node-Code ist,
den das `browser`-Feld beim Bundling wieder herausschneidet** – im ausgelieferten Bundle
landet er nicht. Für eine App, die axios nur für einen einzigen `GET` braucht, wäre
`fetch()` allerdings die strukturell bessere Lösung: null Dependencies, keine
Advisory-Historie. **Empfehlung als Follow-up**, nicht Teil dieser Übung.

---

## 6. Ergebnis nach der Behebung

_Fügt hier die Ausgabe von `npm audit` nach dem Fix ein._

```
$ npm audit
found 0 vulnerabilities

$ echo $?
0
```

Metadaten aus `npm audit --json`:

```json
{
  "vulnerabilities": {
    "info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0, "total": 0
  },
  "dependencies": {
    "prod": 36, "dev": 47, "optional": 26, "peer": 0, "peerOptional": 0, "total": 82
  }
}
```

**Offene Findings nach Fix:** **0** (Ziel der Übung war "keine `critical`/`high`" –
erreicht wurden 0 Findings über alle Severity-Stufen).

**App noch lauffähig?** **Ja** – auf drei Ebenen verifiziert:

```bash
$ npm run build      # tsc && vite build
✓ 72 modules transformed.
dist/index.html                   0.40 kB │ gzip:   0.28 kB
dist/assets/index-C_pyfwX6.css    3.54 kB │ gzip:   1.19 kB
dist/assets/index-DoOYB0Fh.js   324.97 kB │ gzip: 110.31 kB
✓ built in 226ms

$ npm run dev
VITE v8.2.1  ready in 464 ms
➜  Local:   http://localhost:5173/

$ curl -s http://localhost:5173/ | head -3
<!DOCTYPE html>
<html lang="de">
```

1. **Typecheck** – `tsc` läuft im `build`-Script vor vite und meldet **keine Fehler**.
   Das ist der wichtigste automatische Nachweis: die Major-Bumps von axios (0.x → 1.x)
   und nanoid (3.x → 6.x) haben keine im Code verwendete Signatur gebrochen.
2. **Produktions-Build** – erfolgreich, 72 Module, Bundle 325 kB (110 kB gzip).
3. **Dev-Server** – startet, liefert HTML aus, `/src/App.tsx` wird korrekt zu
   ES-Modulen transformiert (HMR-Preamble von `@vitejs/plugin-react` vorhanden).

**Kommentar:**

**Warum die Major-Upgrades trotzdem nicht gebrochen haben.** Das war nicht selbstverständlich
und ist der Grund, warum jeder Schritt mit Build verifiziert wurde:

- **axios 0.21 → 1.19:** Die App nutzt nur `axios.get<T>(url)`. Diese Signatur ist über
  den Major-Wechsel stabil geblieben; die Breaking Changes von 1.0 betreffen vor allem
  `AxiosRequestConfig`-Typen, `paramsSerializer`, den `data`-Umgang bei `form-data` und
  Node-spezifische Optionen – alles hier nicht verwendet.
- **nanoid 3 → 6:** nanoid ist seit v4 **ESM-only**. In einem CommonJS-Node-Projekt wäre
  das ein harter Bruch; hier bundelt Vite ohnehin ESM, deshalb unproblematisch. Der
  Aufruf `nanoid()` ohne Argument ist unverändert gültig. **Als Nebeneffekt sind auch alle
  vier nanoid-Advisories strukturell entschärft**, weil sie ausschliesslich den
  `size`-Parameter betreffen.
- **vite 4 → 8:** Grösster Sprung, aber die App hat eine minimale `vite.config.ts`
  (nur das React-Plugin) und nutzt keine Vite-APIs im Code. Wenig Konfiguration =
  wenig Bruchfläche.

**Bekannte, nicht-sicherheitsrelevante Warnung.** Build und Dev-Server geben aus:

```
(!) Your Vite config uses features that are unsupported by `configLoader: 'native'` …
  - ESM syntax in a file loaded as CommonJS (vite.config.ts:1:1).
    Use a `.mjs` extension or set "type": "module" in the closest package.json
```

Das ist eine **Deprecation-Warnung**, kein Fehler – Vite 8 wird künftig den nativen
Config-Loader als Default nutzen. Behebbar mit `"type": "module"` in `package.json`.
Ich habe das **bewusst nicht** gemacht, um den Diff dieser Übung auf
sicherheitsrelevante Änderungen zu beschränken. Empfohlener Follow-up.

**Was diese Übung methodisch gezeigt hat:**

1. **`npm audit fix` scheitert an exakten Pins.** Wer alle Versionen ohne `^` festnagelt,
   schaltet den automatischen Security-Fix-Pfad ab – und braucht dafür einen bewussten,
   regelmässigen manuellen Prozess (Dependabot/Renovate) als Ersatz.
2. **Severity ≠ Relevanz.** 5 × `high` im Audit, 0 × `hoch` in der Kontextbewertung –
   und das formal harmloseste Finding (esbuild, `moderate`) war das praktisch
   ausnutzbarste. Wer nur nach Severity priorisiert, arbeitet an den falschen Dingen.
3. **Die Runtime-Frage entscheidet am meisten.** Der Nachweis, dass der Node-Adapter von
   axios nicht im Bundle landet, hat ~18 von 24 axios-Advisories in einem Schritt
   entwertet – überprüfbar mit einem `grep` im gebauten Bundle statt mit Vermutungen.
4. **GHSA ist die Primärquelle für npm, nicht CVE.** Das esbuild-Finding hat gar keine
   CVE-Nummer. Ein rein CVE-basierter Scanner hätte es übersehen.
5. **Ein Fix ist erst verifiziert, wenn Audit *und* Build *und* Smoke-Test grün sind.**
   `found 0 vulnerabilities` allein ist wertlos, wenn die App nicht mehr startet.

---

## 7. Dokumentation (Übersichtstabelle, README Teil 7)

| Package | Direkt / Transitiv | Problem | Quelle | Severity | Relevanz | Massnahme | Ergebnis |
|---|---|---|---|---|---|---|---|
| axios | Direkt (prod) | SSRF/Proxy-Leaks (Node-Adapter), CSRF, ReDoS, Prototype-Pollution-Gadgets | GHSA-jr5f-v2jv-69x6 (CVE-2025-27152), GHSA-cph5-m8f7-6c5x (CVE-2021-3749) u. a. (24) | High | niedrig | Update auf 1.19.0 | **behoben** |
| lodash | Direkt (prod) | Command/Code Injection via `_.template`, Prototype Pollution, ReDoS | GHSA-r5fr-rjxr-66jc (CVE-2026-4800), GHSA-35jh-r3h4-6jhm (CVE-2021-23337) | High | niedrig | Update auf 4.18.1 | **behoben** |
| moment | Direkt (prod) | Path Traversal in `moment.locale`, ReDoS | GHSA-8hfj-j24r-96c4 (CVE-2022-24785), GHSA-wc69-rhjr-hc9g (CVE-2022-31129) | High | niedrig | Update auf 2.30.1 | **behoben** |
| nanoid | Direkt (prod) | Endlosschleife / vorhersagbare IDs bei ungültigem `size` | GHSA-2v37-7h3g-55p8 (CVE-2026-67213), GHSA-mwcw-c2x4-8c55 (CVE-2024-55565) | High | niedrig | Update auf 6.0.1 | **behoben** |
| vite | Direkt (dev) | Dev-Server von beliebigen Origins abfragbar, `server.fs.deny`-Bypasses | GHSA-vg6x-rcgg-rjx6 (CVE-2025-24010), GHSA-c24v-8rfc-w8vw (CVE-2024-23331) | High | mittel | Update auf 8.2.1 (+ plugin-react 6.0.5) | **behoben** |
| esbuild | Transitiv (via vite) | Dev-Server-CORS: jede Website kann Quellcode auslesen | GHSA-67mh-4wv8-2f99 (kein CVE) | Moderate | mittel | Kein direkter Fix – vite 8 nutzt rolldown, esbuild aus dem Baum entfernt | **behoben** |

---

## Anhang A: Verwendete Befehle (vollständig, in Reihenfolge)

```bash
# --- Analyse ---
npm install                              # 6 vulnerabilities (1 moderate, 5 high)
npm ls                                   # 12 direkte Dependencies
npm ls --all                             # vollständiger Baum, 89 Packages
npm ls nanoid --all                      # zwei Instanzen aufgedeckt (3.1.25 / 3.3.18)
npm ls esbuild --all                     # transitiv via vite bestätigt
npm audit                                # Textausgabe
npm audit --json > audit-before.json     # maschinenlesbar für die Auswertung

# --- Verifikation der Quellen ---
curl -s https://api.github.com/advisories/GHSA-35jh-r3h4-6jhm   # CVE, CVSS, Ranges, Fix
# (analog für GHSA-8hfj-j24r-96c4, GHSA-67mh-4wv8-2f99, …)

# --- Relevanz: welche APIs werden wirklich benutzt? ---
grep -rn "_\.\|moment\.\|nanoid(\|axios\." src/
node -e "console.log(require('axios/package.json').browser)"     # Adapter-Mapping
grep -c "XMLHttpRequest" dist/assets/*.js                        # → 2
grep -c "Proxy-Authorization\|no_proxy" dist/assets/*.js         # → 0

# --- Behebung ---
npm audit fix                                                    # ohne Wirkung (exakte Pins)
npm install moment@latest lodash@latest axios@latest nanoid@latest
npm install -D vite@latest @vitejs/plugin-react@latest

# --- Verifikation des Fixes ---
npm audit          # found 0 vulnerabilities
npm run build      # tsc + vite build, erfolgreich
npm run dev        # Dev-Server startet, App erreichbar
```

## Anhang B: `npm ls --all` vor dem Fix (Auszug)

```
secure-calendar-training@1.0.0
├── @types/lodash@4.14.182
├─┬ @types/react-dom@18.0.11
│ └── @types/react@18.0.28 deduped
├─┬ @types/react@18.0.28
│ ├── @types/prop-types@15.7.15
│ ├── @types/scheduler@0.26.0
│ └── csstype@3.2.3
├─┬ @vitejs/plugin-react@4.0.0
│ ├─┬ @babel/core@7.29.7
│ │ ├─┬ @babel/code-frame@7.29.7
│ │ │ ├── @babel/helper-validator-identifier@7.29.7
│ │ │ ├── js-tokens@4.0.0 deduped
│ │ │ └── picocolors@1.1.1 deduped
│ │ ├─┬ @babel/generator@7.29.8
│ │ │ ├── @babel/parser@7.29.8 deduped
│ │ │ ├── @babel/types@7.29.8 deduped
│ │ │ ├─┬ @jridgewell/gen-mapping@0.3.13
│ │ │ │ ├── @jridgewell/sourcemap-codec@1.5.5
│ │ │ │ └── @jridgewell/trace-mapping@0.3.31 deduped
│ │ │ └── jsesc@3.1.0
│ │ ├─┬ @babel/helper-compilation-targets@7.29.7
│ │ │ ├── @babel/compat-data@7.29.7
│ │ │ ├─┬ browserslist@4.28.8
│ │ │ │ ├── caniuse-lite@1.0.30001809
│ │ │ │ ├── electron-to-chromium@1.5.402
│ │ │ │ └── node-releases@2.0.53
│ │ │ └── semver@6.3.1 deduped
│ │ ├── … (weitere @babel/*-Packages)
│ ├── react-refresh@0.14.2
│ └── vite@4.3.9 deduped
├─┬ axios@0.21.1
│ └── follow-redirects@1.16.0
├── lodash@4.17.19
├── moment@2.29.1
├── nanoid@3.1.25                      ← direkt, verwundbar
├─┬ react-dom@18.2.0
│ ├─┬ loose-envify@1.4.0
│ │ └── js-tokens@4.0.0
│ ├── react@18.2.0 deduped
│ └─┬ scheduler@0.23.2
│   └── loose-envify@1.4.0 deduped
├─┬ react@18.2.0
│ └── loose-envify@1.4.0 deduped
├── typescript@5.0.4
└─┬ vite@4.3.9
  ├─┬ esbuild@0.17.19                  ← transitiv, verwundbar
  │ ├── @esbuild/linux-x64@0.17.19
  │ └── … (21 × UNMET OPTIONAL DEPENDENCY für andere Plattformen)
  ├─┬ postcss@8.5.26
  │ ├── nanoid@3.3.18                  ← zweite Instanz, NICHT verwundbar
  │ ├── picocolors@1.1.1
  │ └── source-map-js@1.2.1
  ├─┬ rollup@3.30.0
  │ └── UNMET OPTIONAL DEPENDENCY fsevents@~2.3.2
  └── … (weitere UNMET OPTIONAL DEPENDENCY: less, sass, stylus, sugarss, terser)
```

> **🔧 Methodik – Was `UNMET OPTIONAL DEPENDENCY` bedeutet**
> Kein Fehler. Das sind `optionalDependencies` bzw. optionale Peers, die npm bewusst nicht
> installiert hat: die plattformspezifischen esbuild-Binaries (auf Linux/x64 wird nur
> `@esbuild/linux-x64` installiert, die 21 anderen nicht) sowie optionale Präprozessoren,
> die vite nur nutzt, *wenn* man sie selbst installiert (sass, less, stylus, terser).
> Für die Security-Analyse relevant: **sie sind nicht auf der Platte und damit kein Risiko** –
> aber sie tauchen in den `optional: 23`-Zählern der Audit-Metadaten auf, was die
> Baumgrösse grösser wirken lässt, als sie ist.

## Anhang C: `npm ls` nach dem Fix

```
secure-calendar-training@1.0.0
├── @types/lodash@4.14.182
├── @types/react-dom@18.0.11
├── @types/react@18.0.28
├── @vitejs/plugin-react@6.0.5     (war 4.0.0)
├── axios@1.19.0                   (war 0.21.1)
├── lodash@4.18.1                  (war 4.17.19)
├── moment@2.30.1                  (war 2.29.1)
├── nanoid@6.0.1                   (war 3.1.25)
├── react-dom@18.2.0
├── react@18.2.0
├── typescript@5.0.4
└── vite@8.2.1                     (war 4.3.9)
```

## Anhang D: Empfohlene Follow-ups (ausserhalb des Übungsumfangs)

1. **`"type": "module"` in `package.json`** – beseitigt die Vite-Config-Loader-Warnung.
2. **axios durch `fetch()` ersetzen** – die App braucht genau einen `GET`. Das entfernt
   ~25 prod-Packages und eine Library mit sehr aktiver Advisory-Historie.
3. **moment durch Luxon / date-fns / `Intl.DateTimeFormat` ersetzen** – moment ist offiziell
   im Maintenance-Mode (nur noch Security-Fixes) und nicht tree-shakeable: die monolithische
   Prototype-API zieht den kompletten Core ins Bundle (~59 kB minified), obwohl die App nur
   `format()` und `add()` nutzt.
   *Verifiziert:* Die Locale-Dateien (756 kB im `node_modules`) landen hier **nicht** im
   Bundle – im Output ist nur die englische Monatsliste enthalten:
   ```bash
   grep -o "Januar\|février\|Enero" dist/assets/*.js | sort | uniq -c
   #  1 Januar   ← nur Teilstring von "January_February_…", keine de/fr/es-Locale
   ```
   Nebenbei erklärt das, warum `formatDate()` trotz `'dddd, DD. MMMM YYYY'` englische
   Wochentage ausgibt: es wird nirgends eine Locale geladen. Ein funktionaler Bug, der
   bei dieser Analyse mit aufgefallen ist – **kein** Security-Problem, aber ein guter
   Anlass für den Umstieg auf `Intl.DateTimeFormat('de-CH', …)`.
4. **lodash-Nutzung prüfen** – `_.sortBy` und `_.groupBy` sind heute mit
   `Array.prototype.sort` bzw. `Object.groupBy` nativ verfügbar; die gesamte Dependency
   könnte entfallen.
5. **`@types/*` und `typescript` aktualisieren** – nicht sicherheitsrelevant, aber
   `@types/react@18.0.28` passt nicht mehr zum Rest der Toolchain.
6. **Automatisierung** – `npm audit` in die CI-Pipeline (`npm audit --audit-level=high`,
   Exit-Code ≠ 0 bricht den Build) plus Dependabot/Renovate für automatische PRs.
   Ohne Automatisierung ist dieser Report am Tag nach der Abgabe wieder veraltet.
