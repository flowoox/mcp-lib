from example_mcp.contract import capabilities


def test_contract_is_versioned_and_explicit() -> None:
    contract = capabilities()

    assert contract["contract"] == "flowoox.example"
    assert contract["version"] == "1.0.0"
    assert contract["capabilities"] == [
        {
            "id": "example.echo",
            "risk": "read",
            "description": "Return validated example input.",
        }
    ]
