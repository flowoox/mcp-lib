# Traxx MCP

Unabhängiger Connector für Traxx/BeMusic 3.x.

Er nutzt die nativen Schnittstellen:

- TUS-Upload unter `/api/v1/tus/`
- `POST /api/v1/tracks/{fileEntry}/extract-metadata`
- `POST /api/v1/tracks`
- Artist-, Album-, Playlist- und Track-Routen unter `/api/v1`
- `POST /api/v1/import-media/single-item`

`diagnose_upload` lädt eine Datei hoch, gibt die relevanten TUS-Header zurück
und testet die Metadatenextraktion. So lässt sich eine abweichende FileEntry-
URL deiner Instanz über `file_url_template` konfigurieren, ohne Code zu ändern.
