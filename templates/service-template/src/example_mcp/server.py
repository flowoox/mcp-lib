from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from .contract import capabilities


class EchoInput(BaseModel):
    message: str = Field(min_length=1, max_length=500)


def create_server() -> FastMCP:
    mcp = FastMCP(
        "Flowoox MCP Example",
        instructions="Typed example MCP service. Replace the example capability with explicit handlers.",
        host="127.0.0.1",
        port=8080,
        stateless_http=True,
        json_response=True,
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
