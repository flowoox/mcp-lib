# Soulseek MCP

Unabhängiger MCP-Server für `slskd`.

## Werkzeuge

- `configure_slskd`
- `get_configuration`
- `health`
- `search_album`
- `get_album_candidate`
- `queue_album_folder`
- `list_downloads`
- `get_download_batch`
- `wait_for_download`
- `browse_user`

Die Suche gruppiert nach Benutzer und echtem Remote-Ordner. Disc-Unterordner
werden zusammengeführt. Ausführbare Dateien und Skripte werden nie in den
Download-Batch übernommen.
