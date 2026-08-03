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
