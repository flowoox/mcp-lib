# Architektur

## Komponenten

```text
┌──────────────────────────────┐
│ Control Plane · FastAPI      │
│ OAuth · UI · Scheduler       │
└──────────────┬───────────────┘
               │ shared SQLite
       ┌───────┴────────┐
       │                │
┌──────▼──────┐  ┌──────▼──────┐
│ Soulseek MCP│  │ Traxx MCP   │
│ FastMCP     │  │ FastMCP     │
└──────┬──────┘  └──────┬──────┘
       │ REST            │ REST + TUS
┌──────▼──────┐  ┌──────▼──────┐
│ slskd       │  │ Traxx       │
│ Soulseek    │  │ BeMusic     │
└──────┬──────┘  └─────────────┘
       │
       ▼
  /downloads (gemeinsames Volume)
```

## Täglicher Ablauf

1. Scheduler wählt das aktive Spotify-Profil.
2. Access Token wird bei Bedarf per Refresh Token erneuert.
3. Top-Artists und Top-Tracks werden geladen.
4. Gespeicherte, häufig gehörte und bereits vorgeschlagene Alben werden ausgeschlossen.
5. Artist-Alben werden gewichtet und fünf neue Kandidaten gespeichert.
6. Ohne Auto-Download wartet jeder Kandidat auf eine Freigabe im UI.
7. slskd führt eine Suche aus und liefert Responses mit Peer, Dateien, Queue und Geschwindigkeit.
8. Der Matcher bildet Gruppen aus `Peer + Albumwurzel` und klappt Disc-Unterordner zusammen.
9. Der bestbewertete vollständige Ordner wird als `DownloadBatch` mit kompletter Dateiliste eingereiht.
10. Polling erkennt den abgeschlossenen Batch.
11. Traxx lädt jede Audiodatei mit TUS hoch, liest Metadaten und erstellt Track-Datensätze.

## Persistenz

SQLite läuft im WAL-Modus und liegt standardmäßig unter `/data/mcp-lib.sqlite3`. Gespeichert werden:

- verschlüsselte Spotify-Tokens und Profilauswahl
- OAuth-State und PKCE-Verifier
- Albumempfehlungen und Status
- gecachte slskd-Albumkandidaten
- Download-/Importreferenzen
- Vorschlagshistorie zur Deduplizierung
- Jobstatus

## Statusmodell

```text
recommended
  → searching
  → needs_review | not_found | queue_failed
  → downloading | queued_untracked
  → downloaded | download_failed
  → importing
  → imported | import_needs_configuration | import_failed
```

## Skalierung

Für den MVP teilen sich drei Python-Prozesse eine SQLite-Datei. WAL, kurze Transaktionen und ein `busy_timeout` verhindern typische Sperrkonflikte. Für mehrere Hosts oder hohe Parallelität lässt sich `StateStore` später gegen PostgreSQL austauschen, ohne die Connectoren oder MCP-Tools zu ändern.
