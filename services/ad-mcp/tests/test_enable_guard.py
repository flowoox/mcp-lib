from ad_mcp.scripts import SCRIPTS, ScriptId


def test_enable_mutation_rechecks_credential_state_inside_static_script() -> None:
    source = SCRIPTS[ScriptId.SET_USER_ENABLED]
    assert "-Properties Enabled,PasswordLastSet" in source
    assert "$credentialEstablished = ($null -ne $user.PasswordLastSet)" in source
    assert "$requested -and -not $credentialEstablished" in source
    assert "cannot be enabled before credential state is established" in source
    assert source.index("$requested -and -not $credentialEstablished") < source.index(
        "Enable-ADAccount"
    )
