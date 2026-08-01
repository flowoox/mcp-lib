# Architektur von mcp-lib

## Verantwortungsgrenze

`mcp-lib` ist eine Sammlung wiederverwendbarer MCP-Dienste. Es enthält bewusst keine Produkt- oder Workflowlogik.

```text
┌──────────────────────────────────────────────┐
│ Produkt / Agent / Orchestrator               │
│ z. B. traxx-releaseradar                     │
│ Spotify · Scheduler · UI · Workflow-State    │
└───────────────────┬──────────────────────────┘
                    │ MCP · Streamable HTTP
          ┌─────────┴─────────┐
          │                   │
┌─────────▼─────────┐ ┌───────▼──────────┐
│ mcp-soulseek      │ │ mcp-traxx        │
│ Suche · Matching  │ │ Upload · Import  │
│ Kandidaten-Cache  │ │ BeMusic API/TUS  │
└─────────┬─────────┘ └───────┬──────────┘
          │ slskd REST         │ REST + TUS
┌─────────▼─────────┐ ┌───────▼──────────┐
│ slskd / Soulseek  │ │ Traxx / BeMusic  │
└─────────┬─────────┘ └───────┬──────────┘
          └──────── /downloads ┘
```

Der Orchestrator darf die Python-Module der MCPs nicht als Bibliothek importieren. Er verwendet ausschließlich deren dokumentierte Tools. Dadurch können Dienste unabhängig veröffentlicht, ausgetauscht, skaliert und von mehreren Produkten verwendet werden.

## Soulseek MCP

Der Soulseek-Dienst besitzt nur die für slskd notwendige Konfiguration und einen kleinen lokalen SQLite-Cache für Suchkandidaten.

Ablauf:

1. `search_album` startet eine slskd-Suche.
2. Antworten werden nach Peer und tatsächlicher Albumwurzel gruppiert.
3. Disc-Unterordner werden zusammengeführt.
4. Kandidaten werden nach Vollständigkeit, Format, Peer-Status und Geschwindigkeit bewertet.
5. Der Client wählt eine `candidate_id`.
6. `queue_album_folder` übergibt die vollständige Dateiliste als einen Batch an slskd.
7. Der Orchestrator verfolgt den Batch über `get_download_batch`.

Persistenz:

```text
/data/soulseek-mcp.sqlite3
```

Darin liegen ausschließlich temporäre Albumkandidaten. Spotify-Token, Empfehlungshistorie und Produktstatus gehören nicht in diesen Dienst.

## Traxx MCP

Der Traxx-Dienst ist zustandsarm. Er kapselt:

- BeMusic-/Traxx-Authentisierung,
- TUS-Uploads,
- lokale Audioanalyse,
- serverseitige Metadatenextraktion,
- Artist-/Album-Zuordnung,
- Track- und Albumimporte.

Der Dienst hat lesenden Zugriff auf das gemeinsame Download-Volume. Alle angeforderten Pfade werden gegen `DOWNLOADS_DIR` geprüft, damit ein MCP-Client keine beliebigen Hostdateien lesen kann.

## Gemeinsames Download-Volume

Bei einem lokalen Stack teilen slskd, Soulseek-MCP und Traxx-MCP denselben logischen Downloadpfad:

```text
/downloads
```

Der Soulseek-MCP gibt nach dem Einreihen sowohl das relative Ziel als auch den absoluten Containerpfad zurück. Der Orchestrator speichert diesen Wert und übergibt ihn nach Abschluss an `mcp-traxx.import_album_folder`.

Bei verteilten Deployments kann `/downloads` durch NFS, S3-FUSE, ein Object-Storage-Staging oder einen separaten Transfer-MCP ersetzt werden. Die Produktlogik muss dafür nicht in `mcp-lib` verschoben werden.

## Zuständigkeit des Release Radars

`flowoox/traxx-releaseradar` verwaltet:

- Spotify OAuth und verschlüsselte Tokens,
- mehrere Spotify-Profile und die aktive Auswahl,
- Geschmacksanalyse und Album-Ranking,
- Deduplizierung und Historie,
- täglichen Scheduler,
- Rechtebasis der konkreten Empfehlung,
- Download-/Importstatus,
- Web-UI und Operator-Aktionen.

Die Grenze ist absichtlich streng:

```text
Release Radar → MCP-Tool → MCP-Service → Zielsystem
```

Nicht erlaubt:

```text
Release Radar → import mcp_lib.slskd / mcp_lib.traxx
Release Radar → direkte slskd-REST-Aufrufe
Release Radar → direkte BeMusic-REST- oder TUS-Aufrufe
```

## Versionierung

Die beiden Services werden als getrennte Images gebaut:

```text
ghcr.io/flowoox/mcp-soulseek:<version>
ghcr.io/flowoox/mcp-traxx:<version>
```

Orchestratoren pinnen ein Tag oder einen Digest. Tool-Verträge werden möglichst abwärtskompatibel erweitert. Brechende Änderungen erhalten eine neue Hauptversion des jeweiligen MCP-Dienstes.

## Sicherheit

- HTTP-Endpunkte sind im Beispiel nur an Loopback gebunden.
- Zugangsdaten für slskd und Traxx verbleiben im jeweiligen MCP-Container.
- Seiteneffekte benötigen eine Rechtebestätigung.
- lokale Pfade sind auf `/downloads` begrenzt.
- ausführbare Dateien werden nicht als Albumbeilage übernommen.
- der Orchestrator benötigt weder den slskd-API-Key noch den Traxx-Bearer-Token.
