# mcp-lib

Wiederverwendbare, voneinander unabhängige MCP-Dienste. Produktlogik gehört
nicht in dieses Repository.

## Images

```text
ghcr.io/flowoox/mcp-soulseek:0.2.0
ghcr.io/flowoox/mcp-spulseek:0.2.0  # Kompatibilitätsalias für den Tippfehler
ghcr.io/flowoox/mcp-traxx:0.1.0
```

## Dienste

### Soulseek MCP

Wrapper für `slskd`. Konfiguriert Soulseek-Konto, Webzugang und API-Key über MCP, schreibt die überwachte `slskd.yml`, sucht und bewertet vollständige Albumordner, fasst `CD1`, `CD2`, `Disc 1` und ähnliche Unterordner zusammen und lädt alle unterstützten Dateien eines ausgewählten Ordners als einen Batch.

### Traxx MCP

Wrapper für Traxx/BeMusic 3.x. Nutzt den nativen TUS-Endpunkt, die vorhandene
Metadatenextraktion sowie die Artist-, Album- und Track-API. Ein Diagnose-Tool
protokolliert TUS-Antworten, damit Instanzunterschiede ohne Änderungen am
Orchestrator abgeglichen werden können.

## Lokal entwickeln

```bash
docker compose -f compose.dev.yml up --build
```

Die MCP-Endpunkte liegen intern beziehungsweise lokal unter:

```text
http://127.0.0.1:8081/mcp
http://127.0.0.1:8082/mcp
```

Jeder Service besitzt sein eigenes `pyproject.toml`, Dockerfile, Tests und
Runtime-Konfiguration. `packages/mcp-common` enthält ausschließlich kleine,
produktneutrale Hilfsfunktionen.
