# Sicherheit

## Netzwerk

- Die MCP-Server und die optionale slskd-Web-UI binden im Compose-Standard nur an `127.0.0.1`.
- Nur der Soulseek-Peer-Port `50300/tcp` wird für Peer-Verbindungen am Host veröffentlicht.
- Für Fernzugriff NetBird, WireGuard oder einen authentisierten Reverse Proxy verwenden.
- MCP-Endpunkte nicht ungeschützt ins Internet stellen.
- API-Keys und Bearer-Tokens niemals über ein unverschlüsseltes fremdes Netzwerk übertragen.

## Secret-Isolation

Jeder Dienst erhält nur die Zugangsdaten, die er benötigt:

| Secret | Besitzer |
|---|---|
| `SLSKD_API_KEY` | `mcp-soulseek` |
| Soulseek Benutzer/Passwort | `slskd` |
| `TRAXX_TOKEN` | `mcp-traxx` |

Ein Orchestrator wie `traxx-releaseradar` benötigt weder den slskd-Key noch den Traxx-Token. Er ruft ausschließlich die MCP-Tools auf. Dadurch landen Zielsystem-Credentials nicht in der Produktdatenbank oder im Web-UI-Prozess.

- `.env` wird ignoriert und darf nicht committet werden.
- slskd-Web-Passwort und API-Key müssen zufällig und lang sein.
- Für Traxx einen dedizierten Token mit minimal notwendigen Upload-/Music-Rechten verwenden.
- Secrets in Produktion über Docker Secrets, Kubernetes Secrets, SOPS oder einen Vault bereitstellen.

## Least Privilege

- `SLSKD_REMOTE_CONFIGURATION` bleibt im Beispiel deaktiviert.
- Das Traxx-MCP erhält das Download-Volume nur lesend.
- Der Soulseek-MCP besitzt nur seinen eigenen Kandidaten-Cache.
- Der Release Radar besitzt keine direkten Zielsystem-Zugangsdaten.
- Container laufen als unprivilegierter Benutzer.

## Datei- und Pfadschutz

- Remote-Kandidaten akzeptieren nur bekannte Audio- und Sidecar-Erweiterungen.
- EXE, MSI, BAT, CMD, PowerShell, VBS, JS, JAR, LNK und ähnliche ausführbare Formate werden entfernt.
- Zielpfade werden segmentweise bereinigt; `..` und absolute Pfade sind unzulässig.
- Traxx-Imports lösen Pfade kanonisch auf und prüfen, dass sie innerhalb von `DOWNLOADS_DIR` liegen.
- Ein Orchestrator sollte den von `queue_album_folder` zurückgegebenen `local_path` unverändert weiterverwenden.

## Rechte-Gate

Download- und Import-Tools verlangen eine bestätigte Rechtebasis. Bei `licensed`, `artist-permission` und `other-documented-permission` ist zusätzlich eine Referenz erforderlich.

Das Gate verhindert unbeabsichtigte Seiteneffekte, ersetzt aber keine rechtliche Prüfung. Betreiber sind dafür verantwortlich, Soulseek und Traxx ausschließlich für Inhalte zu verwenden, die sie besitzen, lizenziert haben, gemeinfrei sind oder für die eine ausdrückliche Erlaubnis besteht.

## MCP-Authentisierung

Der aktuelle lokale MVP schützt die MCPs primär über Netzwerkisolation. Vor einer Veröffentlichung über Host- oder Standortgrenzen sollte eine der folgenden Varianten ergänzt werden:

- mTLS zwischen Orchestrator und MCP,
- OAuth beziehungsweise MCP Authorization,
- ein Reverse Proxy mit Service-Token,
- eine private Overlay-Verbindung mit zusätzlicher Firewall-Regel.

Die MCP-Schnittstelle ist eine privilegierte Maschinensteuerung und darf nicht wie eine öffentliche Such-API behandelt werden.
