package io.jenkins.plugins.serviceaccount;

import hudson.Extension;
import hudson.model.ManagementLink;
import hudson.security.Permission;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.kohsuke.stapler.json.JsonHttpResponse;

@Extension
public class ServiceAccountManagement extends ManagementLink {
    @Override
    public String getIconFileName() {
        return Jenkins.get().hasPermission(ServiceAccountPermissions.VIEW) ? "symbol-key" : null;
    }

    @Override
    public String getDisplayName() {
        return "Service Accounts";
    }

    @Override
    public String getUrlName() {
        return "service-accounts";
    }

    @Override
    public String getDescription() {
        return "Manage service accounts and their API credentials";
    }

    @Override
    public Permission getRequiredPermission() {
        return ServiceAccountPermissions.VIEW;
    }

    @Override
    protected String getCategoryName() {
        return "SECURITY";
    }

    public List<Map<String, Object>> getAccounts() throws IOException {
        Jenkins.get().checkPermission(ServiceAccountPermissions.VIEW);
        return store().listAccounts().stream()
                .map(ServiceAccountManagement::accountMap)
                .toList();
    }

    public boolean isCanCreateAccounts() {
        return Jenkins.get().hasPermission(ServiceAccountPermissions.CREATE);
    }

    public boolean isCanManageAccounts() {
        return Jenkins.get().hasPermission(ServiceAccountPermissions.MANAGE);
    }

    public boolean isCanDeleteAccounts() {
        return Jenkins.get().hasPermission(ServiceAccountPermissions.DELETE);
    }

    public boolean isCanManageCredentials() {
        return Jenkins.get().hasPermission(ServiceAccountPermissions.MANAGE_CREDENTIALS);
    }

    public int getDefaultCredentialLifetimeDays() {
        return ServiceAccountConfiguration.get().getDefaultCredentialLifetimeDays();
    }

    public HttpResponse doAccount(@QueryParameter String id) throws IOException {
        Jenkins.get().checkPermission(ServiceAccountPermissions.VIEW);
        ServiceAccountStore.AccountSummary account = store().listAccounts().stream()
                .filter(candidate -> candidate.id().equals(id))
                .findFirst()
                .orElse(null);
        if (account == null) {
            throw HttpResponses.notFound();
        }
        return HttpResponses.forwardToView(new AccountPage(account), "index");
    }

    public JSONObject doApi() throws IOException {
        Jenkins.get().checkPermission(ServiceAccountPermissions.VIEW);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put(
                "accounts",
                store().listAccounts().stream()
                        .map(ServiceAccountManagement::accountMap)
                        .toList());
        return JSONObject.fromObject(response);
    }

    public JSONObject doAudit() throws IOException {
        Jenkins.get().checkPermission(ServiceAccountPermissions.VIEW);
        List<Map<String, Object>> events = new ArrayList<>();
        for (ServiceAccountStore.AuditEvent event : store().listAuditEvents()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("type", event.type());
            item.put("accountId", event.accountId());
            item.put("principalName", event.principalName());
            item.put("credentialId", event.credentialId());
            item.put("credentialLabel", event.credentialLabel());
            item.put("actor", event.actor());
            item.put("timestamp", event.timestamp());
            events.add(item);
        }
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("events", events);
        return JSONObject.fromObject(response);
    }

    @RequirePOST
    public HttpResponse doCreateAccount(
            @QueryParameter String id,
            @QueryParameter String displayName,
            @QueryParameter String description,
            @QueryParameter String fromUi)
            throws IOException {
        Jenkins.get().checkPermission(ServiceAccountPermissions.CREATE);
        try {
            store().createAccount(id, displayName, description, actor());
            return HttpResponses.redirectTo("./");
        } catch (IllegalArgumentException e) {
            if ("true".equals(fromUi)) {
                return createAccountErrorRedirect(id, displayName, description, e.getMessage());
            }
            return jsonError(400, e.getMessage());
        }
    }

    @RequirePOST
    public HttpResponse doUpdateAccount(
            @QueryParameter String accountId, @QueryParameter String displayName, @QueryParameter String description)
            throws IOException {
        Jenkins.get().checkPermission(ServiceAccountPermissions.MANAGE);
        try {
            store().updateAccount(accountId, displayName, description, actor());
            return jsonResponse(Map.of("updated", true), 200);
        } catch (IllegalArgumentException e) {
            return jsonError(400, e.getMessage());
        }
    }

    @RequirePOST
    public HttpResponse doCreateCredential(
            @QueryParameter String accountId,
            @QueryParameter String label,
            @QueryParameter String description,
            @QueryParameter String lifetimeDays)
            throws IOException {
        Jenkins.get().checkPermission(ServiceAccountPermissions.MANAGE_CREDENTIALS);
        Integer days;
        try {
            days = lifetimeDays == null || lifetimeDays.isBlank() ? null : Integer.valueOf(lifetimeDays);
        } catch (NumberFormatException e) {
            return jsonError(400, "Credential lifetime must be a whole number of days");
        }
        try {
            ServiceAccountStore.CreatedCredential credential =
                    store().createCredential(accountId, label, description, days, actor());
            return HttpResponses.forwardToView(
                    new CredentialCreatedPage(accountId, credential.username(), credential.secret()), "index");
        } catch (IllegalArgumentException e) {
            return jsonError(400, e.getMessage());
        }
    }

    @RequirePOST
    public HttpResponse doEnableAccount(@QueryParameter String accountId) throws IOException {
        return setAccountEnabled(accountId, true);
    }

    @RequirePOST
    public HttpResponse doDisableAccount(@QueryParameter String accountId) throws IOException {
        return setAccountEnabled(accountId, false);
    }

    @RequirePOST
    public HttpResponse doRevokeCredential(@QueryParameter String accountId, @QueryParameter String credentialId)
            throws IOException {
        Jenkins.get().checkPermission(ServiceAccountPermissions.MANAGE_CREDENTIALS);
        try {
            store().revokeCredential(accountId, credentialId, actor());
            return accountRedirect(accountId);
        } catch (IllegalArgumentException e) {
            return jsonError(400, e.getMessage());
        }
    }

    @RequirePOST
    public HttpResponse doDeleteAccount(@QueryParameter String accountId) throws IOException {
        Jenkins.get().checkPermission(ServiceAccountPermissions.DELETE);
        try {
            store().deleteAccount(accountId, actor());
            return HttpResponses.redirectTo("./");
        } catch (IllegalArgumentException e) {
            return jsonError(400, e.getMessage());
        }
    }

    private HttpResponse setAccountEnabled(String accountId, boolean enabled) throws IOException {
        Jenkins.get().checkPermission(ServiceAccountPermissions.MANAGE);
        try {
            store().setAccountEnabled(accountId, enabled, actor());
            return accountRedirect(accountId);
        } catch (IllegalArgumentException e) {
            return jsonError(400, e.getMessage());
        }
    }

    private static ServiceAccountStore store() {
        return ServiceAccountStore.get();
    }

    private static String actor() {
        return Jenkins.getAuthentication2().getName();
    }

    private static Map<String, Object> accountMap(ServiceAccountStore.AccountSummary account) {
        return accountMap(account, false);
    }

    private static Map<String, Object> accountMap(ServiceAccountStore.AccountSummary account, boolean forPage) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("id", account.id());
        result.put("principalName", account.principalName());
        result.put("displayName", account.displayName());
        result.put("description", account.description());
        result.put("enabled", account.enabled());
        result.put("createdAt", account.createdAt());
        result.put("createdBy", account.createdBy());
        if (forPage) {
            result.put("createdAtDisplay", formatTimestamp(account.createdAt()));
        }
        List<Map<String, Object>> credentials = new ArrayList<>();
        for (ServiceAccountStore.CredentialSummary credential : account.credentials()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("id", credential.id());
            item.put("username", credential.username());
            item.put("label", credential.label());
            item.put("description", credential.description());
            item.put("status", credential.status());
            item.put("createdAt", credential.createdAt());
            item.put("createdBy", credential.createdBy());
            item.put("lastUsedAt", credential.lastUsedAt());
            item.put("expiresAt", credential.expiresAt());
            item.put("revokedAt", credential.revokedAt());
            item.put("revokedBy", credential.revokedBy());
            if (forPage) {
                item.put("createdAtDisplay", formatTimestamp(credential.createdAt()));
                item.put("expiresAtDisplay", formatTimestamp(credential.expiresAt()));
                item.put(
                        "lastUsedAtDisplay",
                        credential.lastUsedAt() == 0 ? "Never" : formatTimestamp(credential.lastUsedAt()));
            }
            credentials.add(item);
        }
        result.put("credentials", credentials);
        return result;
    }

    private static HttpResponse jsonResponse(Map<String, Object> values, int status) {
        return new JsonHttpResponse(JSONObject.fromObject(values), status);
    }

    private static HttpResponse jsonError(int status, String message) {
        return jsonResponse(Map.of("error", message), status);
    }

    private static HttpResponse accountRedirect(String accountId) {
        return HttpResponses.redirectTo("account?id=" + accountId);
    }

    private static HttpResponse createAccountErrorRedirect(
            String id, String displayName, String description, String error) {
        return HttpResponses.redirectTo("./?error="
                + encode(error)
                + "&id="
                + encode(id)
                + "&displayName="
                + encode(displayName)
                + "&description="
                + encode(description));
    }

    private static String encode(String value) {
        return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
    }

    private static String requestParameter(String name) {
        var request = Stapler.getCurrentRequest2();
        return request == null ? null : request.getParameter(name);
    }

    public String getCreationError() {
        return requestParameter("error");
    }

    public String getCreationId() {
        return requestParameter("id");
    }

    public String getCreationDisplayName() {
        return requestParameter("displayName");
    }

    public String getCreationDescription() {
        return requestParameter("description");
    }

    private static Map<String, Object> accountPageMap(ServiceAccountStore.AccountSummary account) {
        return accountMap(account, true);
    }

    private static String formatTimestamp(Long timestamp) {
        if (timestamp == null) {
            return "Never";
        }
        var request = Stapler.getCurrentRequest2();
        Locale locale = request == null ? Locale.getDefault() : request.getLocale();
        return DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, locale)
                .format(new Date(timestamp));
    }

    public static class AccountPage {
        private final Map<String, Object> account;

        AccountPage(ServiceAccountStore.AccountSummary account) {
            this.account = accountPageMap(account);
        }

        public Map<String, Object> getAccount() {
            return account;
        }

        public boolean isCanManageAccounts() {
            return Jenkins.get().hasPermission(ServiceAccountPermissions.MANAGE);
        }

        public boolean isCanDeleteAccounts() {
            return Jenkins.get().hasPermission(ServiceAccountPermissions.DELETE);
        }

        public boolean isCanManageCredentials() {
            return Jenkins.get().hasPermission(ServiceAccountPermissions.MANAGE_CREDENTIALS);
        }

        public int getDefaultCredentialLifetimeDays() {
            return ServiceAccountConfiguration.get().getDefaultCredentialLifetimeDays();
        }
    }

    public static class CredentialCreatedPage {
        private final String accountId;
        private final String username;
        private final String secret;

        CredentialCreatedPage(String accountId, String username, String secret) {
            this.accountId = accountId;
            this.username = username;
            this.secret = secret;
        }

        public String getAccountId() {
            return accountId;
        }

        public String getUsername() {
            return username;
        }

        public String getSecret() {
            return secret;
        }
    }
}
