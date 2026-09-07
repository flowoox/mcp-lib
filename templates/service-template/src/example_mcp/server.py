from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp_common.mcp_security import build_mcp_server_security
from pydantic import BaseModel, Field

from .config import Settings
from .contract import capabilities


class EchoInput(BaseModel):
    message: str = Field(min_length=1, max_length=500)


def create_server(settings: Settings | None = None) -> FastMCP:
    settings = settings or Settings()
    security = build_mcp_server_security(settings, service_hosts=("mcp-example",))
    mcp = FastMCP(
        "Flowoox MCP Example",
        instructions="Typed example MCP service. Replace the example capability with explicit handlers.",
        host=settings.mcp_host,
        port=settings.mcp_port,
        stateless_http=True,
        json_response=True,
        transport_security=security.transport_security,
        auth=security.auth,
        token_verifier=security.token_verifier,
    )

    @mcp.tool()
    async def get_capabilities() -> dict[str, Any]:
        """Return the stable capability contract."""
        return capabilities()

    @mcp.tool()
    async def echo(message: str) -> dict[str, str]:
        """Return validated input. Read-only template capability."""
        payload = EchoInput(message=message)
        return {"message": payload.message}

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
