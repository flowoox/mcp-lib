# Traxx / BeMusic Connector

## Verifizierte Schnittstellen aus der Traxx-3.1.6-Codebasis

Der Connector ist auf die aktuelle `flowoox/traxx-dev`-Codebasis ausgerichtet:

- `/api/v1/tus/` für resumable Uploads
- `POST /api/v1/tracks/{fileEntry}/extract-metadata`
- `POST /api/v1/tracks`
- `GET /api/v1/tracks`
- `GET /api/v1/albums`
- `POST /api/v1/import-media/single-item`

`ModifyTracks` verlangt mindestens `name`, `duration` und `artists`. `CrupdateTrack` akzeptiert unter anderem `src`, `image`, `album_id`, `number`, `genres` und synchronisiert hochgeladene FileEntries anhand der URL.

## Importsequenz

Für jede Audiodatei:

1. Datei lokal prüfen und Tags/Dauer lesen.
2. TUS-Upload mit Metadaten `filename`, `filetype`, `uploadType`, `clientName`, `clientMime`, `clientSize`.
3. `FileEntry`-ID aus Response-Header, JSON oder numerischer TUS-Location bestimmen.
4. BeMusic-Metadatenextraktion mit `autoMatchAlbum=true` auslösen.
5. Artist-/Album-ID, Titel, Dauer, Tracknummer, Genres und Cover übernehmen.
6. Erst wenn eine verwendbare `src`-URL vorhanden ist, `POST /api/v1/tracks` ausführen.

## Warum `TRAXX_FILE_URL_TEMPLATE` optional ist

TUS standardisiert Upload-Erzeugung und Chunk-Transfer, aber nicht die anwendungsspezifische URL, die BeMusic später als `Track.src` erwartet. Je nach Common-/FileEntry-Version kann diese URL in einem Header, im JSON oder über eine separate FileEntry-Route bereitgestellt werden.

Der Connector rät diese URL nicht. Eine Datei wird als `unresolved` gemeldet, wenn nur die Upload-Location bekannt ist. Nach einem echten Probe-Upload kann eine Vorlage gesetzt werden:

```env
TRAXX_FILE_URL_TEMPLATE=/api/dein-pfad/{file_entry_id}
```

Verfügbare Platzhalter:

- `{file_entry_id}`
- `{upload_url}`
- `{base_url}`

## Live-Probe

1. `TRAXX_TOKEN` mit Upload-/Music-Rechten setzen.
2. Eine kleine autorisierte Audiodatei unter `data/downloads/probe/` ablegen.
3. Über den Traxx-MCP `upload_track_file` ausführen.
4. `upload_url`, `file_entry_id`, `file_url`, Response-Header und Traxx-Logs prüfen.
5. Falls `file_url` leer bleibt, die FileEntry-Route der Instanz bestimmen und die Vorlage setzen.
6. Erst danach einen Albumimport mit `dry_run=false` ausführen.
