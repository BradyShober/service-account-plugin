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

`JENKINS_URL` should include the controller's context path, if any. Requests require Jenkins authentication and the matching Service Account permission. Use HTTPS. For POST requests, provide a Jenkins crumb unless the authentication mechanism and controller configuration explicitly exempt the request from CSRF crumbs. The examples below fetch the crumb and send it as a header.

| Method and path | Permission | Purpose and response |
|---|---|---|
| `GET /api` | View service accounts | JSON account and credential metadata; secrets are never included. |
| `GET /audit` | View service accounts | JSON audit-event list. |
| `POST /createAccount` | Create service accounts | Parameters: `id`, `displayName`, optional `description`. Redirects to the account list on success. |
| `POST /updateAccount` | Manage service accounts | Parameters: `accountId`, `displayName`, optional `description`. Returns `{"updated":true}`. |
| `POST /enableAccount` or `/disableAccount` | Manage service accounts | Parameter: `accountId`. Redirects to the account detail page. |
| `POST /deleteAccount` | Delete service accounts | Parameter: `accountId`. Deletes the account and invalidates its credentials, then redirects to the list. |
| `POST /createCredential` | Manage service-account credentials | Parameters: `accountId`, `label`, optional `description`, optional `lifetimeDays`. Returns HTTP 201 JSON containing `credentialId`, `username`, and the new `secret` once. |
| `POST /revokeCredential` | Manage service-account credentials | Parameters: `accountId`, `credentialId`. Revokes only that credential, then redirects to the account detail page. |

The API credential used for administration must belong to a principal granted the required Service Account permission by the active authorization strategy. An administrator can use a Jenkins API token for these requests. A service-account token can also be used if its principal has been explicitly granted the required management permission.

Example setup for `curl` and `jq`:

```sh
export JENKINS_URL="https://jenkins.example.com"
export JENKINS_USER="admin"
export JENKINS_API_TOKEN="..."

CRUMB_JSON=$(curl -fsS -u "$JENKINS_USER:$JENKINS_API_TOKEN" \
  "$JENKINS_URL/crumbIssuer/api/json")
CRUMB_FIELD=$(printf '%s' "$CRUMB_JSON" | jq -r .crumbRequestField)
CRUMB=$(printf '%s' "$CRUMB_JSON" | jq -r .crumb)
```

List accounts and inspect their credentials without revealing token secrets:

```sh
curl -fsS -u "$JENKINS_USER:$JENKINS_API_TOKEN" \
  "$JENKINS_URL/manage/service-accounts/api" | jq
curl -fsS -u "$JENKINS_USER:$JENKINS_API_TOKEN" \
  "$JENKINS_URL/manage/service-accounts/audit" | jq
```

Create an account and issue a credential:

```sh
curl -fsS -u "$JENKINS_USER:$JENKINS_API_TOKEN" \
  -H "$CRUMB_FIELD: $CRUMB" \
  --data-urlencode "id=automation-deploy" \
  --data-urlencode "displayName=Deployment automation" \
  --data-urlencode "description=Deploys approved applications" \
  "$JENKINS_URL/manage/service-accounts/createAccount"

curl -fsS -u "$JENKINS_USER:$JENKINS_API_TOKEN" \
  -H "$CRUMB_FIELD: $CRUMB" \
  --data-urlencode "accountId=automation-deploy" \
  --data-urlencode "label=production-deploy" \
  --data-urlencode "description=Production deployment token" \
  --data-urlencode "lifetimeDays=90" \
  "$JENKINS_URL/manage/service-accounts/createCredential"
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

Update, disable, enable, revoke, or delete an account using POST form parameters. For example:

```sh
curl -fsS -u "$JENKINS_USER:$JENKINS_API_TOKEN" \
  -H "$CRUMB_FIELD: $CRUMB" \
  --data-urlencode "accountId=automation-deploy" \
  "$JENKINS_URL/manage/service-accounts/disableAccount"

curl -fsS -u "$JENKINS_USER:$JENKINS_API_TOKEN" \
  -H "$CRUMB_FIELD: $CRUMB" \
  --data-urlencode "accountId=automation-deploy" \
  --data-urlencode "credentialId=<credential-id-from-listing>" \
  "$JENKINS_URL/manage/service-accounts/revokeCredential"
```

Successful state-changing endpoints may redirect or return JSON as noted above; clients should handle redirects where applicable. Validation errors are returned as JSON with an `error` field. Mutations require POST and are protected by Jenkins CSRF handling.

```shell
mvn test
```
