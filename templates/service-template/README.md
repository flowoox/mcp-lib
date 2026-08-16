# MCP service template

Copy this directory when starting a new public MCP service.

## Rename

Replace:

- package name `example_mcp`
- project name `flowoox-mcp-example`
- console script `mcp-example`
- service title and contract ID in `contract.py`

## Run

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest
mcp-example
```

The template intentionally contains only one read-only example tool. Add new tools explicitly and keep upstream-specific behavior in handlers/clients instead of building generic shell, SQL or arbitrary HTTP proxy tools.

For Tekoda-private integrations, copy the same pattern into the private integration repository and call authoritative SSIO/Odoo/internal APIs through their normal authorization and audit paths.
