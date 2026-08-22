# Active Directory user provisioning boundary

The AD MCP deliberately separates **directory-object provisioning** from **credential bootstrap**.

## What this service can provision

The `ad.user.provision-disabled.*` lifecycle creates or verifies exactly one **disabled** user with a narrow, typed, non-secret attribute set:

- `name`
- `sam_account_name`
- `user_principal_name`
- `display_name`
- `ou_dn` (must identify an Organizational Unit)
- optional `given_name`, `surname`, `mail`, `employee_id`, and `description`

It does not accept arbitrary AD attributes, LDAP filters, PowerShell fragments, passwords, credential objects, or a caller-selected `enabled` flag.

The intended employee-entry sequence is:

```text
validate joiner data
      |
      v
plan_user_provision_disabled
      |
      +--> verify target OU
      +--> check sAMAccountName collision
      +--> check UPN collision
      +--> capture existing-object pre-state
      |
      v
trusted approval workflow signs approvalBinding
      |
      v
change_user_provision_disabled
      |
      +--> re-check collisions inside the static mutation script
      +--> create account with Enabled = false
      +--> never set a password
      |
      v
independent provisioning preflight/readback
      |
      v
verify_user_provision_disabled
```

## Idempotency and collision handling

A retry is accepted as already satisfied only when an existing user with the requested `sAMAccountName` matches the approved identity attributes, resides in the requested OU, and is still disabled.

The service refuses to modify an existing user merely to make a provisioning request fit. In particular it rejects:

- a `sAMAccountName` collision with different approved attributes;
- a UPN assigned to another user;
- an existing matching account that is already enabled;
- a target path that is not an Organizational Unit.

This keeps the provisioning tool an **ensure-this-disabled-identity-exists** primitive rather than a generic `Set-ADUser` endpoint.

## Approval

Provisioning is high risk and requires the same short-lived signed grant as the other AD mutation tools. The plan returns the exact `approvalBinding` that must be signed. It binds the approval to:

- `ad.user.provision-disabled.change`;
- `user:sam:<sam_account_name>`;
- the caller's idempotency key;
- the full non-secret desired attribute set;
- `enabled=false`.

Changing the OU, UPN, employee ID, display name, or any other bound field after approval invalidates the grant.

## Credential bootstrap is intentionally separate

The public model-facing MCP does **not** accept an initial password. Passing a joiner's password as ordinary MCP tool input risks exposing the secret to model context, tracing, logs, orchestration history, or audit payloads.

A later credential-bootstrap capability must therefore use an opaque secret reference or another non-model secret-delivery boundary. Until such a boundary is implemented and tested, accounts created here remain disabled and cannot be enabled by the joiner workflow without a separately established credential.

This is a deliberate security boundary, not a missing implicit password default.

## Least-privilege delegation

For provisioning deployments, delegate the Windows service identity only the rights required to create user objects and write the explicitly supported attributes in the approved target OUs. Do not run the MCP service as Domain Admin merely because user creation is enabled.

Keep organization-specific OU mappings, naming rules, HR identifiers, group policy, and entitlement logic outside this public repository. Those belong in the caller's orchestration/policy layer.
