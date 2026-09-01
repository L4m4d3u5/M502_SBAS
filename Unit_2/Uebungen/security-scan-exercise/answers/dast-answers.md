## Teil 2 – DAST (Dynamic Application Security Testing)

Analysiere die **laufende Applikation** mit OWASP ZAP oder manuellen HTTP-Requests.

### App starten

```bash
node server.js
# → http://localhost:5000
```

### Option A: OWASP ZAP (automatisch)

1. OWASP ZAP öffnen
2. **Automated Scan** → URL: `http://localhost:5000`
3. Scan starten und Report exportieren (HTML/JSON)

### Option B: Manuelle Tests mit curl / Postman

Führe die folgenden Requests aus und notiere, was passiert:

**Test 1 – Reflected XSS:**
```bash
curl "http://localhost:5000/books/search?q=<script>alert('XSS')</script>"
```

**Test 2 – Path Traversal:**
```bash
curl "http://localhost:5000/files?name=../../package.json"
```

**Test 3 – Command Injection:**
```bash
curl -X POST "http://localhost:5000/admin/cmd" \
  -H "Content-Type: application/json" \
  -d '{"run": "whoami"}'
```

**Test 4 – Open Redirect:**
```bash
curl -v "http://localhost:5000/redirect?to=https://evil.example.com"
```

**Test 5 – Broken Access Control:**
```bash
# Buch löschen ohne Authentifizierung
curl -X DELETE "http://localhost:5000/books/1"
```

### Fragen – DAST

Beantworte die folgenden Fragen (in `answers/dast-answers.md`):

**F7.** Was gibt **Test 1** (XSS) zurück?  
- Wird der Script-Tag im Browser ausgeführt? Was bedeutet das für Benutzer?
- Wie nennt man diese Art von XSS (Reflected vs. Stored)?

---

**F8.** Was gibt **Test 2** (Path Traversal) zurück?  
- Welche Datei konnte ausgelesen werden?
- Welche Gefahr besteht, wenn ein Angreifer `/etc/passwd` oder `.env` lesen kann?

---

**F9.** Was gibt **Test 3** (Command Injection) zurück?  
- Was wird ausgegeben? Welcher OS-Benutzer führt die Applikation aus?
- Welche schlimmeren Befehle könnte ein Angreifer ausführen?

---

**F10.** Was beobachtest du bei **Test 5** (Broken Access Control)?  
- Konnte ein nicht-authentifizierter User ein Buch löschen?
- Was fehlt in der Route `/books/:id` (DELETE)?

---

**F11.** Vergleich SAST vs. DAST:  
Fülle die Tabelle aus:

| Kriterium                          | SAST | DAST |
|------------------------------------|------|------|
| App muss laufen?                   |      |      |
| Findet Lücken im Code?             |      |      |
| Findet Laufzeit-Verhalten?         |      |      |
| False Positives möglich?           |      |      |
| Geeignet für CI/CD?                |      |      |

---
