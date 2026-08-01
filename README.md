# mcp-lib

Wiederverwendbare, unabhängig deploybare MCP-Dienste für Musiksysteme.

Dieses Repository enthält **keine Produktlogik, kein Spotify-OAuth, keinen Scheduler und kein Web-UI**. Diese anwendungsspezifische Orchestrierung liegt im separaten Repository `flowoox/traxx-releaseradar`.

## Dienste

| Dienst | Verantwortung | Standard-Endpunkt |
|---|---|---|
| `mcp-soulseek` | slskd durchsuchen, vollständige Albumordner bewerten und als einen Download-Batch einreihen | `http://127.0.0.1:8081/mcp` |
| `mcp-traxx` | Traxx/BeMusic über die native API und TUS ansprechen, Tracks beziehungsweise Albumordner importieren | `http://127.0.0.1:8082/mcp` |
| `slskd` | optionaler Soulseek-Daemon für den lokalen Beispiel-Stack | `http://127.0.0.1:5030` |

```text
beliebiger MCP-Client / Orchestrator
              │
       Streamable HTTP
       ┌──────┴──────┐
       │             │
 mcp-soulseek    mcp-traxx
       │             │
     slskd       Traxx/BeMusic
       │             │
       └──── /downloads ────┘
```

Die MCPs kennen weder Spotify-Benutzer noch Empfehlungshistorie oder tägliche Flows. Dadurch können sie später genauso von ChatGPT, Claude, OpenWebUI, PocketOps, n8n oder einem anderen Produkt verwendet werden.

## Schnellstart

```bash
cp .env.example .env
# Soulseek-, slskd- und Traxx-Zugangswerte eintragen
docker compose up -d --build
```

Danach:

```text
Soulseek MCP  http://127.0.0.1:8081/mcp
Traxx MCP     http://127.0.0.1:8082/mcp
slskd UI      http://127.0.0.1:5030
```

Die HTTP-Ports sind im Beispiel nur an Loopback gebunden. Der Soulseek-Listen-Port wird für Peer-Verbindungen veröffentlicht.

## Container

Der gemeinsame Dockerfile besitzt zwei getrennte Targets:

```bash
docker build --target soulseek -t mcp-soulseek .
docker build --target traxx -t mcp-traxx .
```

Die CI veröffentlicht daraus getrennte Images:

```text
ghcr.io/flowoox/mcp-soulseek:<tag>
ghcr.io/flowoox/mcp-traxx:<tag>
```

Ein Produkt sollte diese Images versioniert referenzieren und nicht Python-Interna aus diesem Repository importieren.

## Soulseek MCP

Der Dienst gruppiert Suchantworten nach tatsächlichem Remote-Ordner und Peer. `CD1`, `CD2`, `Disc 1`, `Disk 2` und ähnliche Unterordner werden als ein Multi-Disc-Album behandelt. Ausführbare oder scriptfähige Dateien werden aus Kandidaten entfernt.

### Tools

- `health`
- `search_album`
- `get_album_candidate`
- `queue_album_folder`
- `list_downloads`
- `get_download_batch`
- `browse_user`

`queue_album_folder` lädt alle unterstützten Dateien des ausgewählten Kandidaten als **einen slskd-Batch**. Der Kandidaten-Cache ist ausschließlich lokaler Zustand des Soulseek-MCPs.

Wichtige Variablen:

```env
SLSKD_URL=http://slskd:5030
SLSKD_API_KEY=...
STATE_DB=/data/soulseek-mcp.sqlite3
DOWNLOADS_DIR=/downloads
MCP_PORT=8081
```

## Traxx / BeMusic MCP

Der Dienst kapselt die vorhandene Traxx-/BeMusic-API:

- TUS-Upload unter `/api/v1/tus/`
- Track-, Artist-, Album- und Playlist-Routen unter `/api/v1`
- serverseitige Metadatenextraktion
- Spotify-/Deezer-Metadatenimport

### Tools

- `health`
- `list_tracks`
- `list_albums`
- `inspect_local_track`
- `upload_track_file`
- `import_album_folder`
- `import_spotify_metadata`

Lokale Pfade werden auf `DOWNLOADS_DIR` begrenzt. Ein Live-Import lädt Audiodateien per TUS hoch, liest Metadaten, ordnet Artist und Album zu und erstellt anschließend Track-Datensätze.

Wichtige Variablen:

```env
TRAXX_URL=https://traxx.example
TRAXX_TOKEN=...
TRAXX_TUS_ENDPOINT=/api/v1/tus/
DOWNLOADS_DIR=/downloads
MCP_PORT=8082
```

Die konkrete Traxx-Installation muss einmal zeigen, wie ihr TUS-Endpunkt die endgültige `FileEntry`-ID beziehungsweise die als `Track.src` nutzbare URL zurückgibt. Falls nötig, wird dafür `TRAXX_FILE_URL_TEMPLATE` gesetzt. Bis diese Zuordnung feststeht, kann `import_album_folder` im Dry-Run verwendet werden.

## Rechte-Gate

Download- und Import-Tools verlangen eine explizite Rechtebestätigung. Unterstützte Grundlagen:

- `owned-copy`
- `licensed`
- `public-domain`
- `artist-permission`
- `other-documented-permission`

Für lizenzierte oder ausdrücklich erlaubte Inhalte muss eine Referenz mitgegeben werden. Das Gate schützt den MCP unabhängig davon, welcher Client ihn aufruft.

## Entwicklung

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
make check
```

Die Tests prüfen unter anderem Multi-Disc-Gruppierung, Kandidatenfilter, Rechte-Gate, TUS-Auflösung, Pfadbegrenzung und den service-lokalen Kandidaten-Cache.

## Konvention für weitere MCPs

Jeder MCP erhält:

1. ein eigenes Servermodul `mcp_<name>.py`,
2. eigene Settings und nur den dafür notwendigen Zustand,
3. einen Console-Entry-Point,
4. ein separates Docker-Target beziehungsweise Image,
5. einen dokumentierten Tool-Vertrag,
6. keine Abhängigkeit von einem konkreten Produkt oder dessen UI.

## Zugehöriges Produkt

`flowoox/traxx-releaseradar` ist der erste Orchestrator. Dort liegen Spotify-Profilanalyse, Benutzerwahl, täglicher Zeitplan, Empfehlungshistorie, Queue-Status und Web-UI. Die Kommunikation mit diesem Repository erfolgt ausschließlich über MCP Streamable HTTP.

## Dokumentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/TRAXX.md`](docs/TRAXX.md)
- [`docs/SECURITY.md`](docs/SECURITY.md)
