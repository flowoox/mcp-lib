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
plan/change/verify_user_credential_bootstrap
      |
      +--> resolve an opaque secret reference locally
      +--> keep password material out of MCP input/output and argv
      +--> set the initial password while the user is still disabled
      +--> independently read back PasswordLastSet and Enabled=false
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

The model-facing MCP still does **not** accept an initial password. Instead the `ad.user.credential-bootstrap.*` lifecycle accepts only an opaque `secret_ref` such as `joiner-alice-20260822`.

Production credential bootstrap is separately fail-closed behind:

```text
AD_WRITES_ENABLED=true
AD_APPROVAL_SECRET=<at least 32 bytes>
AD_CREDENTIAL_BOOTSTRAP_ENABLED=true
AD_CREDENTIAL_SECRET_DIRECTORY=<runtime secret mount/directory>
AD_CREDENTIAL_RECEIPT_STORE=<persistent non-secret receipt JSON path>
```

`AD_CREDENTIAL_SECRET_DIRECTORY` is runtime configuration, not MCP input. A `secret_ref` may address only one direct, non-symlink child of that directory and cannot contain `/`, `\\`, or traversal segments. The file contents are read only inside the credential-change path. Protect the directory with the host/service-account ACL appropriate to the secret provider that populates it.

The password value is never included in:

- an MCP tool argument;
- approval bindings;
- audit metadata;
- JSON payloads passed to PowerShell;
- PowerShell source;
- process command-line arguments;
- MCP tool output.

The Python runner delivers the resolved secret to exactly one allowlisted static PowerShell script through child-process stdin. That script converts the value to `SecureString`, calls `Set-ADAccountPassword`, clears its local plaintext/secure variables, and returns only non-secret state.

### GUID binding and initial-only semantics

Credential bootstrap is not a generic password-reset endpoint. The plan first resolves the AD identity and binds approval to its immutable object GUID, the opaque secret reference, and the idempotency key. The mutation re-checks the GUID and refuses to continue if the user is enabled.

A fresh bootstrap also requires `PasswordLastSet` to be unset. If AD already has password state and there is no matching verified local receipt, the service fails closed instead of silently resetting an existing credential.

The current bootstrap intentionally establishes the initial password **without** setting `ChangePasswordAtLogon`. This makes independent verification possible through `PasswordLastSet` while the user remains disabled. A separate, explicitly designed first-logon/password-rotation policy may be added later rather than weakening this bootstrap verification boundary.

### Crash-safe idempotency receipts

Before mutation the service writes a non-secret `pending` receipt keyed by the caller's idempotency key. The receipt binds:

- the AD object GUID;
- a SHA-256 digest of the opaque secret reference;
- an HMAC-SHA256 fingerprint of the resolved secret keyed by `AD_APPROVAL_SECRET`;
- the pre-change `PasswordLastSet` state.

The secret itself and the clear-text secret reference are not stored. After independent readback succeeds, the receipt is marked `verified` with the observed password timestamp.

This allows safe retries to return a no-op when the exact approved bootstrap is already verified, and allows a pending operation to recover after a response/process interruption without accepting a different GUID, reference, or resolved secret under the same idempotency key.

## Least-privilege delegation

For provisioning deployments, delegate the Windows service identity only the rights required to create user objects, write the explicitly supported attributes in approved target OUs, and reset passwords for the intended user scope. Do not run the MCP service as Domain Admin merely because user creation or credential bootstrap is enabled.

Keep organization-specific OU mappings, naming rules, HR identifiers, group policy, entitlement logic, secret names, secret mount locations, and approval policy outside this public repository. Those belong in the caller's deployment/orchestration/policy layer.
