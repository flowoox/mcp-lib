# mcp-lib

Containerisierte MCP-Sammlung für den Musik-Workflow:

```text
Spotify-Profilanalyse
        ↓
5 neue Albumempfehlungen pro Tag
        ↓
slskd / Soulseek: vollständigen Remote-Ordner auswählen
        ↓
Album als ein Download-Batch in /downloads ablegen
        ↓
Traxx / BeMusic: TUS-Upload, Metadaten lesen, Artist/Album matchen, Tracks anlegen
```

Das Repository enthält zwei getrennte MCP-Server und ein kleines Control-Plane-Web-UI:

| Dienst | Aufgabe | Standardadresse |
|---|---|---|
| `mcp-soulseek` | Albumordner suchen, bewerten und als vollständigen slskd-Batch laden | `http://127.0.0.1:8081/mcp` |
| `mcp-traxx` | Traxx/BeMusic API, TUS-Upload und Albumordner-Import | `http://127.0.0.1:8082/mcp` |
| `control-plane` | Spotify OAuth, Benutzerwahl, täglicher Flow, Queue und Status | `http://127.0.0.1:8080` |
| `slskd` | Soulseek-Daemon und Web-UI | `http://127.0.0.1:5030` |

## Was der MVP bereits kann

- Mehrere Spotify-Benutzer verbinden und einen aktiven Benutzer wählen.
- Private Top-Artists und Top-Tracks über `user-top-read` analysieren.
- Bereits häufig gehörte, gespeicherte und früher vorgeschlagene Alben ausfiltern.
- Standardmäßig täglich fünf neue, zum Geschmack passende Alben vorschlagen.
- slskd-Suchergebnisse nach **echtem Remote-Ordner** gruppieren.
- `CD1`, `CD2`, `Disc 1`, `Disk 2` als ein Multi-Disc-Album zusammenführen.
- FLAC/lossless, vollständige Trackzahl, freie Slots, Geschwindigkeit und Queue bewerten.
- Alle Audiodateien plus Cover, CUE, LOG, M3U und weitere sichere Beilagen als **einen Batch** laden.
- Ausführbare und scriptfähige Dateien aus Kandidaten entfernen.
- Downloads pollen und abgeschlossene Albumordner erkennen.
- Traxx 3.1.6 über den vorhandenen TUS-Endpunkt und die native `/api/v1`-API ansprechen.
- Metadaten lokal mit Mutagen und serverseitig mit BeMusic/getID3 auslesen.
- Alle lokalen Pfade auf das konfigurierte `/downloads`-Verzeichnis begrenzen.
- Seiteneffekte mit einer expliziten Rechtebasis absichern.

## Schnellstart

```bash
cp .env.example .env
openssl rand -hex 32      # als APP_SECRET eintragen
openssl rand -base64 36   # für Dashboard-, slskd- und API-Kennwörter verwenden
mkdir -p data/{state,downloads,incomplete,shares,slskd}
docker compose up -d --build
```

Danach:

1. `http://127.0.0.1:5030` öffnen und den slskd-/Soulseek-Status prüfen.
2. `http://127.0.0.1:8080` öffnen.
3. Spotify-Profil verbinden.
4. `Jetzt entdecken` ausführen.
5. Ein vorgeschlagenes Album mit passender Rechtebasis freigeben.
6. Nach abgeschlossenem Download den Traxx-Import prüfen oder starten.

Der Soulseek-Listen-Port `50300/tcp` wird absichtlich am Host veröffentlicht. HTTP-UI und MCP-Ports sind im Compose-Standard ausschließlich an `127.0.0.1` gebunden.

## Spotify einrichten

In einer Spotify Developer App muss der Callback exakt dem Wert aus `.env` entsprechen:

```env
SPOTIFY_CLIENT_ID=...
SPOTIFY_REDIRECT_URI=http://127.0.0.1:8080/spotify/callback
```

Jeder gewünschte Spotify-Benutzer verbindet sein Profil einmal per OAuth. Die Access- und Refresh-Tokens werden mit einem aus `APP_SECRET` abgeleiteten Fernet-Schlüssel verschlüsselt in SQLite gespeichert. Ein beliebiges öffentliches Spotify-Profil reicht nicht aus, weil private Top-Items die Einwilligung des jeweiligen Benutzers erfordern.

## slskd einrichten

Mindestens diese Werte setzen:

```env
SLSKD_API_KEY=MINDESTENS_16_ZEICHEN_BESSER_32
SLSKD_USERNAME=admin
SLSKD_PASSWORD=LANGES_WEB_PASSWORT
SLSKD_SLSK_USERNAME=dein_soulseek_name
SLSKD_SLSK_PASSWORD=dein_soulseek_passwort
```

Der MCP sendet den Key als `X-API-Key`. Die Automatisierung verwendet:

- `POST /api/v0/searches`
- `GET /api/v0/searches/{id}?includeResponses=true`
- `POST /api/v0/transfers/downloads/batches`
- `GET /api/v0/transfers/downloads/batches/{id}`
- `GET /api/v0/users/{username}/browse`

Ein Album wird nicht aus einzelnen unabhängigen Treffern zusammengesetzt. Es wird ein vollständiger, konsistenter Ordner eines Peers ausgewählt und als Batch übergeben.

## Traxx / BeMusic einrichten

```env
TRAXX_URL=https://traxx.app.wohnhaas.ch
TRAXX_TOKEN=...
TRAXX_TUS_ENDPOINT=/api/v1/tus/
```

Der Token benötigt in BeMusic Berechtigungen zum Hochladen und Erstellen/Aktualisieren von Musik, Artists und Alben.

Die vorhandene Traxx-Codebasis stellt bereits bereit:

- TUS unter `/api/v1/tus/`
- `POST /api/v1/tracks`
- `POST /api/v1/tracks/{fileEntry}/extract-metadata`
- Artist-, Album-, Track- und Playlist-Routen unter `/api/v1`
- Spotify-/Deezer-Metadatenimport unter `/api/v1/import-media/single-item`

### Ein verbleibender Live-Abgleich

Die konkrete Traxx-Instanz muss einmal zeigen, wie der TUS-Upload die `FileEntry`-ID bzw. die anschließend als `Track.src` verwendbare URL zurückgibt. Der Adapter erkennt verbreitete Header-/JSON-Felder und numerische TUS-IDs automatisch. Falls die Instanz nur eine ID liefert, wird nach dem ersten Probe-Upload eine Vorlage gesetzt:

```env
TRAXX_FILE_URL_TEMPLATE=/DEIN/PFAD/{file_entry_id}
```

Bis diese Zuordnung bestätigt ist, bleibt der Albumimport standardmäßig im Dry-Run bzw. meldet die betroffenen Dateien als `unresolved`, anstatt kaputte Track-Einträge zu erzeugen. Details stehen in [`docs/TRAXX.md`](docs/TRAXX.md).

## Automatik und Rechte-Gate

Die tägliche **Discovery** ist standardmäßig aktiv. Automatischer Download und Import sind absichtlich aus:

```env
AUTO_DOWNLOAD=false
AUTO_IMPORT=false
AUTHORIZED_LIBRARY=false
```

Für eine Bibliothek, deren Inhalte vollständig eigene Kopien, lizenziert, gemeinfrei oder ausdrücklich freigegeben sind, kann die Automatik explizit aktiviert werden:

```env
AUTHORIZED_LIBRARY=true
AUTO_DOWNLOAD=true
AUTO_IMPORT=true
DEFAULT_RIGHTS_BASIS=licensed
DEFAULT_RIGHTS_REFERENCE=interne-lizenz-oder-katalogreferenz
```

Zulässige Rechtebasen:

- `owned-copy`
- `licensed`
- `public-domain`
- `artist-permission`
- `other-documented-permission`

`licensed`, `artist-permission` und `other-documented-permission` verlangen eine Referenz. Das Gate ist sowohl im Web-UI als auch in beiden MCP-Seiteneffekten aktiv.

## MCP-Tools

### Soulseek MCP

- `health`
- `search_album`
- `get_album_candidate`
- `queue_album_folder`
- `list_downloads`
- `get_download_batch`
- `browse_user`

### Traxx MCP

- `health`
- `list_tracks`
- `list_albums`
- `inspect_local_track`
- `upload_track_file`
- `import_album_folder`
- `import_spotify_metadata`

Beide Server nutzen Streamable HTTP und liegen standardmäßig unter `/mcp`.

## Entwicklung

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
make check
```

Die Tests decken aktuell Album-/Multi-Disc-Gruppierung, Kandidatenfilter, Rechte-Gate, Spotify-Ranking, Pfadschutz und Downloadstatus ab.

## Repository-Konvention für zukünftige MCPs

Gemeinsame Clients, Authentisierung, State und Sicherheitsfunktionen bleiben unter `src/mcp_lib/`. Ein neuer MCP erhält ein eigenes Modul `mcp_<name>.py`, einen Console-Entry-Point in `pyproject.toml`, einen separaten Compose-Service und eine kurze Dokumentation unter `docs/`.

## Dokumentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/TRAXX.md`](docs/TRAXX.md)
- [`docs/SECURITY.md`](docs/SECURITY.md)
