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
      |
      v
trusted secret broker stages one target-bound, expiring secret envelope
      |
      v
plan/change/verify_user_credential_bootstrap
      |
      +--> consume the envelope exactly once
      +--> keep password material out of MCP input/output, receipts and argv
      +--> set the initial password while the user is still disabled
      +--> independently read back PasswordLastSet and Enabled=false
      |
      v
plan/change/verify_user_enabled
      |
      +--> refuse enable unless credential state is independently observed
      +--> re-check PasswordLastSet inside the static enable script
```

## Idempotency and collision handling

A provisioning retry is accepted as already satisfied only when an existing user with the requested `sAMAccountName` matches the complete approved attribute set, is a direct child of the requested OU, and is still disabled.

Optional fields are not wildcards. Omitting `mail`, `employee_id`, `description`, `given_name`, or `surname` means the corresponding existing AD attribute must also be unset before the request can be considered idempotently satisfied.

The preflight response is treated as security-sensitive evidence. Missing or malformed OU, sAMAccountName, UPN, or object-GUID data fails closed and prevents the mutation from running.

The service refuses to modify an existing user merely to make a provisioning request fit. In particular it rejects:

- a `sAMAccountName` collision with different approved attributes;
- a UPN assigned to another user;
- an existing matching account that is already enabled;
- an account in a child or different OU;
- a target path that is not an Organizational Unit;
- incomplete or malformed preflight evidence.

This keeps the provisioning tool an **ensure-this-disabled-identity-exists** primitive rather than a generic `Set-ADUser` endpoint.

## Approval

Provisioning is high risk and requires the same short-lived signed grant as the other AD mutation tools. The plan returns the exact `approvalBinding` that must be signed. It binds the approval to:

- `ad.user.provision-disabled.change`;
- `user:sam:<sam_account_name>`;
- the caller's idempotency key;
- the full non-secret desired attribute set;
- `enabled=false`.

Changing the OU, UPN, employee ID, display name, or any other bound field after approval invalidates the grant.

## Credential bootstrap

The model-facing MCP never accepts an initial password. The `ad.user.credential-bootstrap.*` lifecycle accepts only a versioned opaque reference in the form:

```text
mcpsecret:v1:<base64url-random-token>
```

A trusted non-model secret broker stages the corresponding one-time envelope through the reusable `mcp_common.secret_refs.stage_secret_reference` helper or an equivalent implementation of the same contract. The envelope binds the secret to:

- purpose `ad.password-bootstrap`;
- immutable target `user:guid:<object-guid>`;
- the exact idempotency key;
- a SHA-256 digest of the opaque reference;
- timezone-aware issue and expiry timestamps;
- a maximum lifetime of one hour.

Production credential bootstrap is separately fail-closed behind:

```text
AD_WRITES_ENABLED=true
AD_APPROVAL_SECRET=<at least 32 bytes>
AD_CREDENTIAL_BOOTSTRAP_ENABLED=true
AD_CREDENTIAL_SECRET_DIRECTORY=<runtime one-time envelope directory>
AD_CREDENTIAL_RECEIPT_STORE=<persistent non-secret receipt JSON path>
```

`AD_CREDENTIAL_SECRET_DIRECTORY` is runtime configuration, not MCP input. It must be an absolute, non-link directory. On POSIX it and every envelope must be private to the service identity; on Windows the deployment must enforce equivalent ACLs and must not expose a reparse point.

The MCP atomically renames an envelope before reading it and deletes the claimed file after the consume attempt, including on expiry, malformed data, binding mismatch, or mutation failure. A reference therefore cannot be replayed. The directory accepts only a direct regular `<token>.json` child, never a caller-selected path.

The password value is never included in:

- an MCP tool argument;
- approval bindings;
- audit metadata;
- persistent idempotency receipts;
- JSON payloads passed to PowerShell;
- PowerShell source;
- process command-line arguments;
- MCP tool output.

The Python runner delivers the consumed secret to exactly one allowlisted static PowerShell script through child-process stdin. For this secret-backed execution, child stderr is suppressed rather than reflected into MCP errors. The script converts the value to `SecureString`, calls `Set-ADAccountPassword`, clears its local plaintext/secure variables, and returns only non-secret state.

### GUID binding and initial-only semantics

Credential bootstrap is not a generic password-reset endpoint. The plan first resolves the AD identity and binds approval to its immutable object GUID, the SHA-256 digest of the opaque secret reference, the idempotency key, `credentialEstablished=true`, and `enabled=false`. The mutation re-checks the GUID and refuses to continue if the user is enabled.

A fresh bootstrap also requires `PasswordLastSet` to be unset. If AD already has password state and there is no matching verified local receipt, the service fails closed instead of silently resetting an existing credential.

The current bootstrap intentionally establishes the initial password **without** setting `ChangePasswordAtLogon`. This makes independent verification possible through `PasswordLastSet` while the user remains disabled. A separate, explicitly designed first-logon/password-rotation policy may be added later rather than weakening this bootstrap verification boundary.

### Non-secret idempotency receipts

Before consuming the one-time envelope and running the mutation, the service writes a non-secret `pending` receipt keyed by the caller's idempotency key. Receipt schema v2 binds:

- the AD object GUID;
- the SHA-256 digest of the opaque secret reference;
- the pre-change `PasswordLastSet` state.

It deliberately stores neither the secret nor a password-derived hash/HMAC verifier. After independent readback succeeds, the receipt is marked `verified` with the observed password timestamp.

A retry is a no-op only when a matching `verified` receipt and the current AD credential state agree. A `pending` receipt combined with newly established AD password state is considered ambiguous: the service does not claim that an external or interrupted password change was its own successful operation. Operator review and an explicitly chosen recovery action are required.

Legacy schema-v1 receipts are rejected instead of silently migrated because they contained a password-derived verifier and used weaker secret-reference semantics.

### Credential-before-enable gate

`plan_user_enabled(enabled=true)` requires independently observed `PasswordLastSet` evidence. The repository-owned `SET_USER_ENABLED` PowerShell script repeats the same check immediately before `Enable-ADAccount`, closing the plan/change race. Disabling a user remains possible without credential state.

## Least-privilege delegation

For provisioning deployments, delegate the Windows service identity only the rights required to create user objects, write the explicitly supported attributes in approved target OUs, reset passwords for the intended user scope, and enable/disable only the intended accounts. Do not run the MCP service as Domain Admin merely because user creation or credential bootstrap is enabled.

Keep organization-specific OU mappings, naming rules, HR identifiers, group policy, entitlement logic, secret names, secret mount locations, and approval policy outside this public repository. Those belong in the caller's deployment/orchestration/policy layer.
