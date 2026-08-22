# mcp-archive

Zweite Bezugsquelle neben Soulseek: offen lizenzierte Alben vom **Internet
Archive**. Der Connector spricht denselben Vertrag wie `soulseek-mcp`
(`flowoox.music-acquisition` 1.2), damit die Pipeline beide Quellen über einen
Codepfad ansteuern kann — Suche → Kandidaten → Warteschlange → Statusabfrage,
fertige Dateien im gemeinsamen `/downloads`-Volume.

## Warum das Internet Archive

Gemessen im August 2026 gegen die laufenden APIs:

| | Internet Archive | Jamendo |
|---|---|---|
| Zugangsdaten | keine | `client_id` nötig, ohne Registrierung antwortet jeder Aufruf mit `code 5, "Invalid Client Id"` |
| Audio-Items | 13 934 791, davon 1 928 182 mit Creative-Commons-Lizenz | rund 600 000 Tracks |
| Prüfsummen | md5, sha1 und Grösse pro Datei | keine |
| Lizenz pro Item | `licenseurl` im Metadatensatz | pauschal CC |

Ausschlaggebend war die fehlende Registrierung: der Connector ist ohne
Kontoanlage betriebsbereit, und jede Datei lässt sich nach der Übertragung
gegen die veröffentlichte md5 prüfen — etwas, das ein Peer-Netz nicht bietet.

## Die Lizenzschranke

Angeboten wird ein Item nur, wenn seine Lizenz **aus den Metadaten lesbar**
ist und Weitergabe erlaubt:

- alle sechs Creative-Commons-Lizenzen → `rights_basis: licensed`,
  die Lizenz-URL wird als `rights_reference` mitgeführt
- CC0 und Public Domain Mark → `rights_basis: public-domain`
- alles andere, **einschliesslich Items ganz ohne `licenseurl`**, wird
  abgelehnt und der Grund in `rejected` genannt

Das ist bewusst streng. Gemessen: sämtliche Items der Sammlungen
`freemusicarchive` und `etree` im Stichprobenumfang tragen **kein**
`licenseurl`. Aus der Sammlung auf eine Erlaubnis zu schliessen würde
„unbekannt“ in „erlaubt“ verwandeln.

NC und ND werden akzeptiert: beide beschränken kommerzielle Nutzung und
Bearbeitung, nicht das Anfertigen einer unveränderten Kopie.

## Outbound-Sicherheitsgrenze

`mcp-archive` ist bewusst **kein generischer HTTP-Client**. Der persistierbare
`base_url`-Parameter bleibt aus Kompatibilitätsgründen im MCP-Vertrag, akzeptiert
aber ausschließlich den kanonischen Ursprung `https://archive.org`.

Jeder ausgehende API- und Download-Request wird vor dem Senden erneut geprüft.
Automatische Redirects sind deaktiviert; jeder 30x-Hop wird einzeln auf HTTPS,
Port 443 und einen Host unter `archive.org` validiert. Zusätzlich muss die
vollständige aktuelle DNS-Antwort ausschließlich global routbare IPv4-/IPv6-
Adressen enthalten. Loopback, RFC1918/ULA, Link-Local, Multicast, unspecified,
reserved und IPv4-mapped lokale Ziele werden fail-closed blockiert. Damit kann
ein MCP-Aufrufer weder die Basis-URL noch einen Redirect als SSRF-Pivot auf
interne/Metadata-Ziele verwenden. Upstream-Fehlertexte werden nicht in MCP-
Fehlerantworten gespiegelt.

Internet-Archive-Storage-Nodes wie `*.archive.org` bleiben für legitime
Download-Redirects erlaubt. Neue externe Hosts müssen nicht als breite Allowlist
nachgetragen werden; wenn sich die Archive-Infrastruktur ändert, wird die
konkrete Policy geprüft und bewusst angepasst.

## Gemessene Eigenheiten der API

Jede davon steht als Test mit Begründung im Code.

| Beobachtung | Folge |
|---|---|
| Ein nicht existierendes Item antwortet mit **HTTP 200 und `{}`**, nicht 404 | Der Statuscode taugt nicht als Antwort auf „gibt es das?“ |
| `length` steht **im selben Item** als `"04:32"` und als `"272.24"` | Beide Schreibweisen werden gelesen; sonst geht die Dauer verloren, gegen die der Traxx-Import prüft |
| `track` kommt als `"1"`, als `"1/9"` und als `"2-05"` | Erst an `/` trennen, sonst wird `1/9` zu 19 |
| Das Format heisst im Suchindex `FLAC`, im Metadatensatz `Flac` | Vergleich case-insensitiv, Schlüssel ist die Dateiendung |
| `collection` und `creator` sind mal Zeichenkette, mal Liste | Eine Zeichenkette zu iterieren ergäbe eine Liste von Buchstaben |
| Jedes Item enthält Ableitungen (`Ogg Vorbis`, `64Kbps MP3`) neben dem Original | Ohne Entdopplung lädt ein Album zwei- bis dreifach |
| Die fachliche Suche `creator:(…) AND title:(…)` lieferte 2 Treffer, dieselben Wörter als Freitext 10 — acht davon Podcasts | Erst fachlich suchen, erst danach verbreitern |

## Werkzeuge

`get_capabilities`, `configure_archive`, `get_configuration`, `health`,
`search_album`, `get_album_candidate`, `queue_album_folder`,
`list_downloads`, `get_download_batch`, `wait_for_download`.

`queue_album_folder` prüft die Rechteangabe über
`mcp_common.rights.validate_rights` wie der Soulseek-Connector. Fehlt eine
`rights_reference`, wird die Lizenz-URL des Items eingesetzt — dann steht in
der Prüfspur, *unter welcher* Lizenz kopiert wurde.

## Betrieb

Kein Konto, keine Zugangsdaten. Der Dienst hört auf Port 8083 und braucht nur
Netzzugang zu `archive.org` sowie das gemeinsame `/downloads`-Volume.

```bash
pytest -q services/archive-mcp/tests
ruff check services/archive-mcp/src services/archive-mcp/tests
```
