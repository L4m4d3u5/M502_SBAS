## Teil 3 – Bewertung & Priorisierung

Erstelle in `answers/risk-assessment.md` eine Gesamtliste aller gefundenen Schwachstellen:

| # | Schwachstelle         | Gefunden durch | CVSS (1–10) | Auswirkung            | Priorität (H/M/L) |
|---|-----------------------|----------------|-------------|-----------------------|-------------------|
| 1 | axios@0.21.1 | snyk test | 9.1 | Auswirkung auf HTTP Requests | H |
| 2 | cookie-parser@1.4.6 | snyk test | 6.3 | Auswirkung auf Cookie | H |
| 3 | express@4.17.1 | snyk test | 7.5 | HTTP Anfragen | H |
| 4 | jsonwebtoken@8.5.1 | snyk test | 6.8 | JWT Auswirkung | H |
| 5 | lodash@4.17.4 | snyk test | 7.3 | performance | H |
| 6 | multer@1.4.4 | snyk test | 9.2 | Gefahr bei API Anfragen| L |
| 7 | Cross Site Scripting | ZAP | 10 | Gefahr durch scripting | H |

---
