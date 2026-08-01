# Sicherheit

## Netzwerk

- Control Plane, MCP-Server und slskd-Web-UI binden im Compose-Standard nur an `127.0.0.1`.
- Nur der Soulseek-Peer-Port `50300/tcp` ist extern veröffentlicht.
- Für Fernzugriff NetBird, WireGuard oder einen authentisierten Reverse Proxy verwenden.
- API-Keys und Bearer-Tokens nicht über unverschlüsseltes, fremdes Netzwerk übertragen.

## Secrets

- `.env` wird ignoriert und darf nicht committet werden.
- `APP_SECRET`, Dashboard-Passwort, slskd-Web-Passwort und API-Key müssen zufällig sein.
- Spotify-Tokens werden verschlüsselt gespeichert; die Sicherheit hängt direkt von `APP_SECRET` ab.
- Ein Wechsel von `APP_SECRET` macht bestehende Spotify-Tokens unlesbar und erfordert erneutes Verbinden.

## Least Privilege

- Für Traxx einen dedizierten Token mit Upload-/Music-Rechten verwenden.
- slskd-Key nur im privaten Docker-Netz bzw. mit CIDR-Begrenzung einsetzen.
- `SLSKD_REMOTE_CONFIGURATION` bleibt im Stack deaktiviert.
- Das Traxx-MCP kann nur Dateien unter `DOWNLOADS_DIR` lesen.

## Datei- und Pfadschutz

- Remote-Kandidaten akzeptieren nur bekannte Audio- und Sidecar-Erweiterungen.
- EXE, MSI, BAT, CMD, PowerShell, VBS, JS, JAR, LNK und ähnliche ausführbare Formate werden entfernt.
- Zielpfade werden segmentweise bereinigt; `..` und absolute Pfade sind unzulässig.
- Traxx-Imports lösen Pfade kanonisch auf und prüfen, dass sie innerhalb des Download-Roots liegen.

## Rechte-Gate

Das Gate verhindert unbeabsichtigte Vollautomatik und verlangt für Download/Import eine angegebene Rechtebasis. Es ersetzt keine rechtliche Prüfung. Betreiber sind dafür verantwortlich, Soulseek und Traxx ausschließlich für Inhalte zu verwenden, die sie besitzen, lizenziert haben, gemeinfrei sind oder für die eine ausdrückliche Erlaubnis besteht.

## Web-UI

- Dashboard-Basic-Auth aktivieren.
- Bei Veröffentlichung hinter einem Reverse Proxy zwingend TLS, zusätzliche SSO-/WAF-Authentisierung und Origin-/CSRF-Schutz am Proxy vorsehen.
- Standardmäßig nur über localhost oder Management-VPN verwenden.
