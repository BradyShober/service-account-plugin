# Service Accounts

This Jenkins plugin is being developed to provide independently managed machine identities and revocable credentials for automation. The intended initial model is API-only service accounts, with permissions granted through Jenkins' configured authorization strategy.


Service account management is available from **Manage Jenkins → Service Accounts** to users with the service-account view permission.
The list page contains account creation, navigation, and an audit log; open an account to manage its credentials. The audit log shows account and credential lifecycle events, actor, and readable timestamp. Events are retained for 90 days by default; configure the period in the service-account configuration, or set it to `0` to keep events indefinitely. Each account's API username is its authorization principal (`service-account-<id>`), shared by its independently revocable credentials; rotating credentials creates a new token secret without changing the username. New credential secrets are shown once on a separate confirmation page.

## Configuration as Code

Declare account metadata under `unclassified.serviceAccountConfiguration.serviceAccounts`. The principal is stable and derived from the account ID (`service-account-<id>`), so grant permissions in the active authorization strategy's normal configuration. Reserve that principal namespace in external security realms to avoid identity collisions. Configured accounts are upserted; accounts omitted from later reloads are retained. Configuration does not create, expose, or rotate credentials. Existing accounts keep their current principal names.

```yaml
unclassified:
  serviceAccountConfiguration:
    auditRetentionDays: 90
    serviceAccounts:
      - id: automation-deploy
        displayName: Deployment automation
        description: Deploys approved applications

jenkins:
  authorizationStrategy:
    globalMatrix:
      entries:
        - user:
            name: service-account-automation-deploy
            permissions:
              - Overall/Read
              - Job/Read
              - Job/Build
```

The account ID must contain 1–64 lowercase letters, digits, dots, underscores, or hyphens. Provision credentials separately through the account management UI or API.

## Managing accounts and credentials through the API

The management endpoints are relative to:

```text
$JENKINS_URL/manage/service-accounts
```

`JENKINS_URL` should include the controller's context path, if any. Requests require Jenkins authentication and the matching Service Account permission. Use HTTPS. POSTs authenticated with a valid service-account credential are exempt from Jenkins crumbs only on the service-account mutation endpoints listed below. Other POSTs remain protected by Jenkins CSRF handling; requests authenticated as regular Jenkins users should include a crumb.

| Method and path | Permission | Purpose and response |
|---|---|---|
| `GET /api/accounts` | View service accounts | JSON account and credential metadata; secrets are never included. |
| `GET /api/accounts/{id}` | View service accounts | JSON detail for one account. |
| `GET /api/accounts/{id}/credentials` | View service accounts | JSON credentials for one account. |
| `GET /api/audit` | View service accounts | JSON audit-event list. |
| `POST /api/accounts/create` | Create service accounts | JSON body: `id`, `displayName`, optional `description`. Returns HTTP 201 JSON. |
| `POST /api/accounts/{id}/update` | Manage service accounts | JSON body: `displayName`, optional `description`. |
| `POST /api/accounts/{id}/enable` or `/disable` | Manage service accounts | Enables or disables the account. |
| `POST /api/accounts/{id}/delete` | Delete service accounts | Permanently removes the account and stored credential data; its ID may be reused. Audit events remain until their configured retention period expires. |
| `POST /api/accounts/{id}/credentials/create` | Manage service-account credentials | JSON body: `label`, optional `description` and `lifetimeDays`. Returns HTTP 201 JSON with the new `secret` once. |
| `GET /api/accounts/{id}/credentials/{credentialId}` | View service accounts | JSON metadata for one credential; secrets are never included. |
| `POST /api/accounts/{id}/credentials/{credentialId}/revoke` | Manage service-account credentials | Revokes only that credential. |

The API credential used for administration must belong to a principal granted the required Service Account permission by the active authorization strategy. An administrator can use a Jenkins API token for these requests. A service-account token can also be used if its principal has been explicitly granted the required management permission.

Example setup for `curl` and `jq` using an administrator's Jenkins API token. Jenkins binds the default crumb to the authenticated user and HTTP session, so keep and reuse the cookie jar from the crumb request for subsequent calls. Fetch the crumb using the same credentials you will use for POST requests:

```sh
export JENKINS_URL="https://jenkins.example.com"
export JENKINS_USER="admin"
export JENKINS_API_TOKEN="..."
COOKIE_JAR=$(mktemp)
trap 'rm -f "$COOKIE_JAR"' EXIT

CRUMB_JSON=$(curl -fsS -u "$JENKINS_USER:$JENKINS_API_TOKEN" -c "$COOKIE_JAR" \
  "$JENKINS_URL/crumbIssuer/api/json")
CRUMB_FIELD=$(printf '%s' "$CRUMB_JSON" | jq -r .crumbRequestField)
CRUMB=$(printf '%s' "$CRUMB_JSON" | jq -r .crumb)
```

List accounts and inspect their credentials without revealing token secrets:

```sh
curl -fsS -u "$JENKINS_USER:$JENKINS_API_TOKEN" \
  -b "$COOKIE_JAR" \
  "$JENKINS_URL/manage/service-accounts/api/accounts" | jq
curl -fsS -u "$JENKINS_USER:$JENKINS_API_TOKEN" \
  -b "$COOKIE_JAR" \
  "$JENKINS_URL/manage/service-accounts/api/audit" | jq
```

Create an account and issue a credential:

```sh
curl -fsS -u "$JENKINS_USER:$JENKINS_API_TOKEN" \
  -b "$COOKIE_JAR" \
  -H "$CRUMB_FIELD: $CRUMB" \
  -H "Content-Type: application/json" \
  --data '{"id":"automation-deploy","displayName":"Deployment automation","description":"Deploys approved applications"}' \
  "$JENKINS_URL/manage/service-accounts/api/accounts/create"

curl -fsS -u "$JENKINS_USER:$JENKINS_API_TOKEN" \
  -b "$COOKIE_JAR" \
  -H "$CRUMB_FIELD: $CRUMB" \
  -H "Content-Type: application/json" \
  --data '{"label":"production-deploy","description":"Production deployment token","lifetimeDays":90}' \
  "$JENKINS_URL/manage/service-accounts/api/accounts/automation-deploy/credentials/create"
```

Account creation returns HTTP 201 with a JSON response:

```json
{
  "created": true,
  "id": "automation-deploy"
}
```

The credential-creation API response is JSON with this shape:

```json
{
  "credentialId": "credential UUID",
  "username": "service-account-automation-deploy",
  "secret": "one-time token value"
}
```

Capture the secret from this one-time response and store it in a secrets manager; it cannot be retrieved later. The response and secret must not be written to shared logs or build output. The new credential's Basic-auth username is the account principal, `service-account-automation-deploy`; use the returned secret as its password. The browser UI submits the same operation in UI mode and displays the secret on its one-time confirmation page.

Update, disable, enable, revoke, or delete an account using the resource routes. JSON bodies are required for updates:

```sh
curl -fsS -u "$JENKINS_USER:$JENKINS_API_TOKEN" \
  -b "$COOKIE_JAR" \
  -H "$CRUMB_FIELD: $CRUMB" \
  -H "Content-Type: application/json" \
  --data '{"displayName":"Deployment automation","description":"Deploys approved applications"}' \
  "$JENKINS_URL/manage/service-accounts/api/accounts/automation-deploy/update"

curl -fsS -u "$JENKINS_USER:$JENKINS_API_TOKEN" \
  -b "$COOKIE_JAR" \
  -H "$CRUMB_FIELD: $CRUMB" \
  "$JENKINS_URL/manage/service-accounts/api/accounts/automation-deploy/disable"

curl -fsS -u "$JENKINS_USER:$JENKINS_API_TOKEN" \
  -b "$COOKIE_JAR" \
  -H "$CRUMB_FIELD: $CRUMB" \
  "$JENKINS_URL/manage/service-accounts/api/accounts/automation-deploy/credentials/<credential-id-from-listing>/revoke"
```

Successful API mutations return JSON. Validation errors are returned as JSON with an `error` field. Mutations require POST. Valid service-account credentials do not need a crumb for the API mutation routes listed above; all other authentication methods remain subject to Jenkins CSRF handling.

```shell
mvn test
```
