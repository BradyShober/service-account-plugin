# Service Accounts

This Jenkins plugin is being developed to provide independently managed machine identities and revocable credentials for automation. The intended initial model is API-only service accounts, with permissions granted through Jenkins' configured authorization strategy.

The implementation is in progress. Do not use this plugin for production authentication until the authentication and authorization integration tests and security review are complete.

Service account management is available from **Manage Jenkins → Service Accounts** to users with the service-account view permission.
The list page contains account creation and navigation; open an account to manage its credentials. Each account's API username is its authorization principal (`service-account-<id>`), shared by its independently revocable credentials; rotating credentials creates a new token secret without changing the username. New credential secrets are shown once on a separate confirmation page.

## Configuration as Code

Declare account metadata under `unclassified.serviceAccountConfiguration.serviceAccounts`. The principal is stable and derived from the account ID (`service-account-<id>`), so grant permissions in the active authorization strategy's normal configuration. Reserve that principal namespace in external security realms to avoid identity collisions. Configured accounts are upserted; accounts omitted from later reloads are retained. Configuration does not create, expose, or rotate credentials. Existing accounts keep their current principal names.

```yaml
unclassified:
  serviceAccountConfiguration:
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

## Development

The plugin is built against Jenkins 2.580.1 and Java 21 or newer.

```shell
mvn test
```
