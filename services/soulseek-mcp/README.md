# Soulseek MCP

Eigenständiger MCP-Service für slskd/Soulseek.

## Aufgaben

- slskd-API und Suchparameter persistent konfigurieren
- Soulseek- sowie slskd-Webzugang in die überwachte `slskd.yml` schreiben
- vollständige Albumordner und Multi-Disc-Strukturen bewerten
- sichere komplette Ordner als einen Download-Batch anlegen
- Downloadstatus normalisieren

Die `slskd.yml` liegt auf einem gemeinsamen persistenten Volume, wird atomar mit
Dateirechten `0600` geschrieben und enthält zwangsläufig die Soulseek-Zugangsdaten,
weil slskd selbst diese Datei liest. MCP-Antworten geben keine dieser Secrets zurück.

## Relevante Tools

```text
configure_slskd
get_configuration
health
search_album
get_album_candidate
queue_album_folder
get_download_batch
wait_for_download
browse_user
```

`configure_slskd` bleibt mit bisherigen Clients kompatibel. Die zusätzlichen
Felder `soulseek_username`, `soulseek_password`, `web_username`, `web_password`
und `listen_port` aktivieren die vollständige Web-UI-basierte Ersteinrichtung.

## Verbindungs-Selbstheilung

`health` und `search_album` prüfen den tatsächlichen Soulseek-Loginstatus. Ist
slskd erreichbar, aber ausgeloggt, wird standardmäßig genau ein Connect
ausgelöst und höchstens 12 Sekunden darauf gewartet. Ein gemeinsamer Lock
verhindert parallele Connect-Aufrufe; nach einem Versuch gilt 30 Sekunden
Cooldown. Damit führen abgelehnte Zugangsdaten weder zu Endlosschleifen noch zu
einem Reconnect-Sturm. Die Grenzen sind über `configure_slskd` oder
`SLSKD_AUTO_RECONNECT`, `SLSKD_RECONNECT_WAIT_SECONDS` und
`SLSKD_RECONNECT_COOLDOWN_SECONDS` konfigurierbar. Geheimnisse werden dabei
weder geloggt noch in Antworten aufgenommen.

## Freigabe-Scan

`shared_files` stammt aus dem von slskd bereits aufgebauten Share-Cache. Neue
Dateien im nach `/music` gemounteten Hostordner erscheinen deshalb erst nach
einem Scan: beim Start mit `SLSKD_FORCE_SHARE_SCAN=true`, nach dem konfigurierten
`SLSKD_SHARE_CACHE_RETENTION`-Intervall oder nach `PUT /api/v0/shares`. Der
Hostpfad wird von Docker Compose relativ zum Compose-Projekt aufgelöst. Bei
mehreren Git-Worktrees sollte `SLSKD_SHARE_PATH` daher ein absoluter Pfad sein;
ein gleichnamiger Ordner in einem anderen Worktree wird nicht automatisch
gemountet.
