# mcp-lib

Wiederverwendbare, voneinander unabhängige MCP-Dienste. Produktlogik gehört
nicht in dieses Repository.

## Images

```text
ghcr.io/flowoox/mcp-soulseek:0.3.1
ghcr.io/flowoox/mcp-spulseek:0.3.1  # Kompatibilitätsalias für den Tippfehler
ghcr.io/flowoox/mcp-traxx:0.3.1
```

## Vertragsfamilie

Jeder Dienst veröffentlicht über `get_capabilities` einen stabilen MCP-Vertrag:

```text
flowoox.music-acquisition v1.x
flowoox.music-library-import v1.x
```

Service-/Image-Versionen und Vertragsversionen sind getrennt. Innerhalb v1 sind additive Tools und Felder kompatibel; semantische Brüche erfordern einen neuen Vertrags-Major. Beide Dienste verwenden für die Übergabe relativer Albumartefakte das Schema `shared-volume`.

## Dienste

### Soulseek MCP

Wrapper für `slskd`. Konfiguriert Soulseek-Konto, Webzugang und API-Key über MCP, schreibt die überwachte `slskd.yml`, sucht und bewertet vollständige Albumordner, fasst `CD1`, `CD2`, `Disc 1` und ähnliche Unterordner zusammen und lädt alle unterstützten Dateien eines ausgewählten Ordners als einen Batch. Die erwartete Trackzahl wird exakt geprüft. Deterministische Batch-IDs und ein bestehender-Batch-Check machen Wiederholungen nach Timeouts oder Prozessabbrüchen idempotent.

### Traxx MCP

Wrapper für Traxx/BeMusic 3.x. Nutzt den nativen TUS-Endpunkt, die vorhandene
Metadatenextraktion sowie die Artist-, Album- und Track-API. Track- und
Album-Artists werden getrennt behandelt, mehrere Gastkünstler bleiben erhalten
und ein lokal gespeichertes Cover wird gegenüber externen Hotlinks bevorzugt.
Ein persistentes Import-Ledger verhindert doppelte abgeschlossene Importe;
teilweise oder noch nicht konfigurierte Importe bleiben erneut ausführbar. Ein
Diagnose-Tool protokolliert TUS-Antworten, damit Instanzunterschiede ohne
Änderungen am Orchestrator abgeglichen werden können.

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
