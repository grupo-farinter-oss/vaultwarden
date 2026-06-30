# SSO organization auto-provisioning

Vaultwarden can reconcile SSO users into one default organization during SSO login. The default organization can already exist, or Vaultwarden can bootstrap it automatically when `SSO_ORG_BOOTSTRAP=true`.

This feature is intentionally split into three steps:

- `SSO_ORG_AUTO_PROVISION=true` creates a membership in the default organization when the SSO user does not have one yet.
- `SSO_ORG_INVITE_AUTO_ACCEPT=true` moves an invited/autoprovisioned membership to `Accepted`.
- `SSO_ORG_AUTO_CONFIRM=true` runs the internal admin-bot crypto step and moves an accepted membership to `Confirmed`.

For a fully automatic SSO flow, enable all three flags.

`SSO_ORG_BOOTSTRAP=true` adds a fourth startup/login-time reconciliation step: Vaultwarden creates or adopts the default organization by `SSO_DEFAULT_ORG_ID` and ensures an internal owner bot membership exists. The bot is not a human admin and cannot log in through SSO; it exists so the server can safely own the SSO-managed organization without promoting the first SSO user to owner.

## Required configuration

```env
SSO_ENABLED=true
SSO_ONLY=true
SSO_DEFAULT_ORG_ID=<existing-organization-uuid>
SSO_ORG_AUTO_PROVISION=true
SSO_ORG_INVITE_AUTO_ACCEPT=true
SSO_ORG_AUTO_CONFIRM=true
SSO_ORG_AUTO_CONFIRM_KEY=<base64-organization-key>
```

`SSO_DEFAULT_ORG_ID` points to the organization to reconcile into. Without bootstrap, it must already exist. With bootstrap enabled, Vaultwarden creates the organization with this UUID if it is missing. Bootstrap requires this UUID so startup/login-time reconciliation is deterministic and does not rely on non-unique organization names.

`SSO_ORG_AUTO_CONFIRM_KEY` is the raw symmetric organization key encoded as Base64. It must decode to 32 or 64 bytes. Treat it as secret key material and inject it only from a secret store.

## Optional organization bootstrap

Enable bootstrap when the default SSO organization should be created or adopted automatically:

```env
SSO_DEFAULT_ORG_ID=<organization-uuid-to-create-or-adopt>
SSO_ORG_BOOTSTRAP=true
SSO_ORG_BOOTSTRAP_NAME="Default SSO Organization"
SSO_ORG_BOOTSTRAP_BILLING_EMAIL="admin@example.com"
SSO_ORG_BOOTSTRAP_COLLECTION_NAME="Default collection"
SSO_ORG_BOT_EMAIL="sso-org-bot@vaultwarden.local"
```

Bootstrap resolution works in this order:

1. If `SSO_DEFAULT_ORG_ID` is set and the organization exists, Vaultwarden uses it and ensures the bot is an owner.
2. If `SSO_DEFAULT_ORG_ID` is set but missing, Vaultwarden creates the organization with that UUID.
3. If `SSO_DEFAULT_ORG_ID` is not set, configuration validation fails.

When a new organization is created, Vaultwarden also creates the configured initial collection. Re-running bootstrap reuses an existing collection with the same name in the default organization. For existing organizations, it does not rename the organization or modify billing email.

The internal bot membership is confirmed as owner with access to all collections. It is an internal ownership record, not an interactive admin account. `SSO_ORG_BOT_EMAIL` is reserved: do not reuse a real user's email and do not assign it to any identity provider user.

## Behavior

For a new SSO user with no existing membership:

1. SSO login creates the user.
2. `SSO_ORG_AUTO_PROVISION` creates a default organization membership.
3. `SSO_ORG_INVITE_AUTO_ACCEPT` sets the membership to `Accepted`.
4. `SSO_ORG_AUTO_CONFIRM` encrypts the organization key for the user's public key and sets the membership to `Confirmed`.

For a user already invited to the default organization:

1. SSO login accepts the existing invite.
2. The auto-confirm bot confirms the membership.

For a user already accepted before enabling this feature:

1. The next SSO login confirms the existing accepted membership.

The non-SSO flow is not affected by these SSO flags.

## Getting the organization key for an existing org

The key must come from an unlocked owner/admin client session. The server database stores encrypted key material and cannot derive this value on its own.

One practical one-time extraction method is to use a trusted admin workstation:

1. Log in to Vaultwarden as an owner/admin who can access the target organization.
2. Unlock the vault in the web vault.
3. Open the browser developer console.
4. Set the target organization id and run this snippet:

```js
const targetOrgId = "<existing-organization-uuid>";

const isValidOrgKey = (value) => {
  if (typeof value !== "string") return false;
  try {
    const decoded = atob(value);
    return decoded.length === 32 || decoded.length === 64;
  } catch {
    return false;
  }
};

const keyFromValue = (value) => {
  if (isValidOrgKey(value)) return value;
  if (!value || typeof value !== "object") return null;
  if (isValidOrgKey(value.keyB64)) return value.keyB64;
  return null;
};

const findInTree = (value, seen = new Set()) => {
  if (!value || typeof value !== "object" || seen.has(value)) return null;
  seen.add(value);

  const direct = keyFromValue(value[targetOrgId]);
  if (direct) return direct;

  for (const child of Object.values(value)) {
    const nested = findInTree(child, seen);
    if (nested) return nested;
  }

  return null;
};

const parse = (value) => {
  try { return JSON.parse(value); } catch { return value; }
};

let orgKey = null;
for (let index = 0; index < localStorage.length && !orgKey; index++) {
  const storageKey = localStorage.key(index);
  orgKey = findInTree(parse(localStorage.getItem(storageKey) ?? ""));
}

console.log(orgKey ?? "Organization key not found in localStorage; check IndexedDB or use the Playwright helper.");
```

If the key is not in `localStorage`, use the Playwright E2E helper `getOrganizationKey` in `playwright/tests/setups/orgs.ts`; it also searches IndexedDB.

After extraction, store the value in your secret manager. Do not commit it.

## Kubernetes example

Store the key as a secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: vaultwarden-sso-org-auto-confirm
  namespace: vaultwarden
type: Opaque
stringData:
  SSO_ORG_AUTO_CONFIRM_KEY: "<base64-organization-key>"
```

Inject it together with the non-secret flags:

```yaml
env:
  - name: SSO_DEFAULT_ORG_ID
    value: "<existing-organization-uuid>"
  - name: SSO_ORG_BOOTSTRAP
    value: "true"
  - name: SSO_ORG_BOOTSTRAP_NAME
    value: "Default SSO Organization"
  - name: SSO_ORG_BOOTSTRAP_BILLING_EMAIL
    value: "admin@example.com"
  - name: SSO_ORG_BOT_EMAIL
    value: "sso-org-bot@vaultwarden.local"
  - name: SSO_ORG_AUTO_PROVISION
    value: "true"
  - name: SSO_ORG_INVITE_AUTO_ACCEPT
    value: "true"
  - name: SSO_ORG_AUTO_CONFIRM
    value: "true"
  - name: SSO_ORG_AUTO_CONFIRM_KEY
    valueFrom:
      secretKeyRef:
        name: vaultwarden-sso-org-auto-confirm
        key: SSO_ORG_AUTO_CONFIRM_KEY
```

## Security notes

`SSO_ORG_AUTO_CONFIRM_KEY` gives the Vaultwarden process enough material to encrypt the organization key for new SSO users. This preserves the normal per-user membership key model in the database, but the running server process now has access to sensitive organization key material.

Use this only when the deployment model accepts that tradeoff. Prefer secret injection from Vault/Kubernetes Secrets and restrict access to the runtime environment.

Do not enable auto-confirm without `SSO_ONLY=true` unless you explicitly want mixed SSO and password users to coexist. The reconciliation code only runs for SSO users, but operationally the default organization is intended to be governed by the identity provider.

`SSO_ORG_BOT_EMAIL` is blocked from SSO login while bootstrap is enabled. If an existing initialized or SSO-linked account already uses that email, bootstrap fails so the internal owner membership cannot be claimed by a real user.
