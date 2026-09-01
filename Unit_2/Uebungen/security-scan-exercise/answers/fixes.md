## Teil 4 – Fix (Optional / Bonus)

Wähle **zwei** der gefundenen Schwachstellen aus und behebe sie im Code.

Erstelle danach einen neuen Scan und zeige, dass die Lücke nicht mehr gefunden wird.

Dokumentiere deine Fixes in `answers/fixes.md`:
- Welche Schwachstelle wurde behoben?
- Was wurde geändert? (Code vorher / nachher)
- Wurde die Lücke im neuen Scan noch gefunden?

### Hinweise zu möglichen Fixes

| Schwachstelle         | Mögliche Lösung                                         |
|-----------------------|---------------------------------------------------------|
| SQL Injection         | Prepared Statements / Parameterisierte Queries          |
| XSS                   | Output escapen (z.B. `he` Library) / CSP Header setzen |
| Command Injection     | `exec` vermeiden, Input-Whitelist verwenden             |
| Path Traversal        | `path.resolve` + Prefix-Check verwenden                 |
| Hardcoded Secrets     | `.env`-Datei + `dotenv` Package                         |
| MD5 Passwort-Hashing  | `bcrypt` oder `argon2` verwenden                        |
| Schwacher JWT-Secret  | Langen zufälligen Secret aus `.env` lesen               |
| Fehlende Auth         | Middleware zur Token-Prüfung vor der Route              |

---
