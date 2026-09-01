### Fragen – SAST

Beantworte die folgenden Fragen schriftlich (in `answers/sast-answers.md`):

**F1.** Wie viele Schwachstellen hat Snyk Code insgesamt gefunden?  
Trage die Ergebnisse in die Tabelle ein:

| Schweregrad | Anzahl |
|-------------|--------|
| Critical    | 0 |
| High        | 8 |
| Medium      | 10 |
| Low         | 10 |

---

**F2.** Snyk meldet eine **SQL Injection**. Beantworte:
- In welcher Datei und Zeile befindet sich die Schwachstelle?
- Warum ist String-Konkatenation in SQL-Queries gefährlich?
- Welcher Angriff wäre möglich? Gib ein Beispiel-Payload an.

---

**F3.** Snyk meldet **Hardcoded Credentials**. Beantworte:
- Welche Werte wurden als hartcodierte Secrets erkannt?
    - Der JWT_SECRET auf [Zeile 18](./../bookstore-api/server.js).
    - Der DB Passwort auf [Zeile 20](./../bookstore-api/server.js).
    - Die User Passwörter auf [Zeilen 34-36](./../bookstore-api/server.js).
- Warum ist das ein Sicherheitsproblem, auch wenn die Werte "geheim" aussehen?
    - Der Code wird auf GitHub versioniert und wenn das Repo nicht privat ist, dann sehen alle die Credentials
- Wie sollten Secrets in einer echten Applikation gespeichert werden?
    - Als eine ENV Variable. Lokal in einer `.env` Datei. Auf GitHub im Secret Storage. 

---

**F4.** Snyk meldet **Insecure Hashing** (MD5). Beantworte:
- Wo im Code wird MD5 verwendet?
    - [server.js Zeile 71](./../bookstore-api/server.js)
- Warum ist MD5 für das Hashing von Passwörtern ungeeignet?
    1. Kollisionen (das bekanntere, hier aber das unwichtigere)
    - MD5 ist seit 2004 gebrochen — man kann in Sekunden zwei verschiedene Eingaben mit gleichem Hash erzeugen. Für Signaturen und Integritätsprüfungen ist das fatal. Für Passwortspeicherung ist es fast irrelevant: der Angreifer braucht kein Kollisionspaar, sondern das Urbild zum konkreten Hash in der Datenbank.
    2. Geschwindigkeit (das eigentliche Problem)
    - MD5 wurde auf Durchsatz optimiert. Genau diese Eigenschaft ist bei Passwörtern eine Katastrophe. Eine moderne GPU rechnet MD5 in der Größenordnung von zehn Milliarden Hashes pro Sekunde. Ein achtstelliges Passwort aus Klein-, Großbuchstaben und Ziffern hat rund 2·10¹⁴ Kombinationen — das ist im Brute-Force-Bereich von Stunden, nicht Jahren. Reale Passwörter aus Wörterbuchlisten fallen in Sekunden.
    Dazu kommt: crypto.createHash('md5') hat kein Salt. Gleiche Passwörter erzeugen denselben Hash. Folgen:
    - Rainbow Tables — vorberechnete Tabellen für Milliarden gängiger Passwörter, Lookup statt Rechnen.
    - Ein Angreifer knackt nicht Konten einzeln, sondern die ganze Tabelle auf einmal — jeder Kandidat wird einmal gehasht und gegen alle Datensätze verglichen.
    - Man erkennt an identischen Hashes sofort, welche Nutzer dasselbe Passwort verwenden.
    - Der entscheidende Punkt in einem Satz: Passwort-Hashing muss absichtlich langsam und pro Benutzer unterschiedlich sein. MD5 ist beides nicht.
    - Welche Alternativen gibt es?
        - Argon2id
        - Bcrypt

---

**F5.** Beim Dependency-Scan (`snyk test`) werden verwundbare Pakete gefunden. Beantworte:
- Welche 2 Pakete weisen die kritischsten CVEs auf?
    - axios@0.21.1
    - multer@1.4.4
- Was bedeutet CVE-Nummer und CVSS-Score?
    - CVE ist die eindeutige ID eines vulnerablem Packages
    - CVSS sagt wie kritisch (0-10) eine Vulnerabilität ist.
- Wie würde man diese Abhängigkeiten aktualisieren?
    - Multer auf Version 2.0.1 oder höher aktualisieren
    - Axios auf Version 0.31.1, 1.15.1 oder höher aktualisieren

---

**F6.** Bewertung:  
Ordne **drei** der gefundenen SAST-Schwachstellen nach deiner Einschätzung in diese Matrix ein:

| Schwachstelle | Wahrscheinlichkeit (1–5) | Auswirkung (1–5) | Risikostufe (W × A) |
|---------------|--------------------------|-------------------|----------------------|
| axios@0.21.1 | 5 | 4 | 20 |
| multer@1.4.4 | 1 (package ist direktnicht gebraucht) | 4 | 4 |
| lodash@4.17.4 | 5 | 3 | 15 |

---