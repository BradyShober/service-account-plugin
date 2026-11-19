package io.jenkins.plugins.serviceaccount;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import jenkins.model.Jenkins;
import net.sf.json.JSONException;
import net.sf.json.JSONNull;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.kohsuke.stapler.json.JsonHttpResponse;
import org.kohsuke.stapler.verb.GET;

public class ServiceAccountApi {
    @GET
    public JSONObject doIndex() throws IOException {
        return accountsJson();
    }

    @GET
    public JSONObject doAudit() throws IOException {
        Jenkins.get().checkPermission(ServiceAccountPermissions.VIEW);
        List<Map<String, Object>> events = new ArrayList<>();
        for (ServiceAccountStore.AuditEvent event : ServiceAccountStore.get().listAuditEvents()) {
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
        return JSONObject.fromObject(Map.of("events", events));
    }

    public AccountsResource getAccounts() {
        return new AccountsResource();
    }

    private static JSONObject accountsJson() throws IOException {
        Jenkins.get().checkPermission(ServiceAccountPermissions.VIEW);
        return JSONObject.fromObject(Map.of(
                "accounts",
                ServiceAccountStore.get().listAccounts().stream()
                        .map(ServiceAccountManagement::accountMap)
                        .toList()));
    }

    private static ServiceAccountStore.AccountSummary findAccount(String accountId) throws IOException {
        return ServiceAccountStore.get().listAccounts().stream()
                .filter(account -> account.id().equals(accountId))
                .findFirst()
                .orElseThrow(HttpResponses::notFound);
    }

    private static ServiceAccountStore.CredentialSummary findCredential(String accountId, String credentialId)
            throws IOException {
        return findAccount(accountId).credentials().stream()
                .filter(credential -> credential.id().equals(credentialId))
                .findFirst()
                .orElseThrow(HttpResponses::notFound);
    }

    private static JSONObject requireJsonBody() throws IOException {
        var request = Stapler.getCurrentRequest2();
        String contentType = request == null ? null : request.getContentType();
        if (contentType == null || !"application/json".equalsIgnoreCase(contentType.split(";", 2)[0].trim())) {
            throw new ApiRequestException(415, "Content-Type must be application/json");
        }
        StringBuilder json = new StringBuilder();
        char[] buffer = new char[1024];
        int charactersRead;
        try (var reader = request.getReader()) {
            while ((charactersRead = reader.read(buffer)) != -1) {
                json.append(buffer, 0, charactersRead);
            }
        }
        try {
            return JSONObject.fromObject(json.toString());
        } catch (JSONException e) {
            throw new ApiRequestException(400, "Request body must contain valid JSON");
        }
    }

    private static String jsonString(JSONObject body, String name) {
        if (body == null || !body.containsKey(name)) {
            return null;
        }
        Object value = body.get(name);
        if (value == null || value instanceof JSONNull) {
            return null;
        }
        return value instanceof String string ? string : null;
    }

    private static Integer jsonInteger(JSONObject body, String name) {
        if (body == null || !body.containsKey(name)) {
            return null;
        }
        Object value = body.get(name);
        if (value == null || value instanceof JSONNull) {
            return null;
        }
        try {
            return new BigDecimal(value.toString()).intValueExact();
        } catch (NumberFormatException | ArithmeticException e) {
            throw new IllegalArgumentException(name + " must be a whole number");
        }
    }

    private static HttpResponse jsonResponse(Map<String, Object> values, int status) {
        return new JsonHttpResponse(JSONObject.fromObject(values), status);
    }

    private static HttpResponse jsonError(int status, String message) {
        return jsonResponse(Map.of("error", message), status);
    }

    private static String actor() {
        return Jenkins.getAuthentication2().getName();
    }

    private static class ApiRequestException extends RuntimeException {
        private final int status;

        ApiRequestException(int status, String message) {
            super(message);
            this.status = status;
        }
    }

    public static class AccountsResource {
        @GET
        public JSONObject doIndex() throws IOException {
            return accountsJson();
        }

        @RequirePOST
        public HttpResponse doCreate() throws IOException {
            Jenkins.get().checkPermission(ServiceAccountPermissions.CREATE);
            JSONObject body;
            try {
                body = requireJsonBody();
            } catch (ApiRequestException e) {
                return jsonError(e.status, e.getMessage());
            }
            String id = jsonString(body, "id");
            try {
                ServiceAccountStore.get()
                        .createAccount(id, jsonString(body, "displayName"), jsonString(body, "description"), actor());
                return jsonResponse(Map.of("created", true, "id", id), 201);
            } catch (IllegalArgumentException e) {
                return jsonError(400, e.getMessage());
            }
        }

        public AccountResource getDynamic(String id) {
            return new AccountResource(id);
        }
    }

    public static class AccountResource {
        private final String id;

        AccountResource(String id) {
            this.id = id;
        }

        @GET
        public JSONObject doIndex() throws IOException {
            Jenkins.get().checkPermission(ServiceAccountPermissions.VIEW);
            return JSONObject.fromObject(ServiceAccountManagement.accountMap(findAccount(id)));
        }

        @RequirePOST
        public HttpResponse doUpdate() throws IOException {
            Jenkins.get().checkPermission(ServiceAccountPermissions.MANAGE);
            JSONObject body;
            try {
                body = requireJsonBody();
            } catch (ApiRequestException e) {
                return jsonError(e.status, e.getMessage());
            }
            try {
                ServiceAccountStore.get()
                        .updateAccount(id, jsonString(body, "displayName"), jsonString(body, "description"), actor());
                return jsonResponse(Map.of("updated", true, "id", id), 200);
            } catch (IllegalArgumentException e) {
                return jsonError(400, e.getMessage());
            }
        }

        @RequirePOST
        public HttpResponse doEnable() throws IOException {
            return setEnabled(true);
        }

        @RequirePOST
        public HttpResponse doDisable() throws IOException {
            return setEnabled(false);
        }

        @RequirePOST
        public HttpResponse doDelete() throws IOException {
            Jenkins.get().checkPermission(ServiceAccountPermissions.DELETE);
            try {
                ServiceAccountStore.get().deleteAccount(id, actor());
                return jsonResponse(Map.of("deleted", true, "id", id), 200);
            } catch (IllegalArgumentException e) {
                return jsonError(400, e.getMessage());
            }
        }

        public CredentialsResource getCredentials() {
            return new CredentialsResource(id);
        }

        private HttpResponse setEnabled(boolean enabled) throws IOException {
            Jenkins.get().checkPermission(ServiceAccountPermissions.MANAGE);
            try {
                ServiceAccountStore.get().setAccountEnabled(id, enabled, actor());
                return jsonResponse(Map.of("enabled", enabled, "id", id), 200);
            } catch (IllegalArgumentException e) {
                return jsonError(400, e.getMessage());
            }
        }
    }

    public static class CredentialsResource {
        private final String accountId;

        CredentialsResource(String accountId) {
            this.accountId = accountId;
        }

        @GET
        public JSONObject doIndex() throws IOException {
            Jenkins.get().checkPermission(ServiceAccountPermissions.VIEW);
            ServiceAccountStore.AccountSummary account = findAccount(accountId);
            return JSONObject.fromObject(
                    Map.of("credentials", ServiceAccountManagement.credentialMaps(account, false)));
        }

        @RequirePOST
        public HttpResponse doCreate() throws IOException {
            Jenkins.get().checkPermission(ServiceAccountPermissions.MANAGE_CREDENTIALS);
            JSONObject body;
            try {
                body = requireJsonBody();
            } catch (ApiRequestException e) {
                return jsonError(e.status, e.getMessage());
            }
            Integer lifetimeDays;
            try {
                lifetimeDays = jsonInteger(body, "lifetimeDays");
            } catch (IllegalArgumentException e) {
                return jsonError(400, e.getMessage());
            }
            try {
                ServiceAccountStore.CreatedCredential credential = ServiceAccountStore.get()
                        .createCredential(
                                accountId,
                                jsonString(body, "label"),
                                jsonString(body, "description"),
                                lifetimeDays,
                                actor());
                return jsonResponse(
                        Map.of(
                                "credentialId", credential.id(),
                                "username", credential.username(),
                                "secret", credential.secret()),
                        201);
            } catch (IllegalArgumentException e) {
                return jsonError(400, e.getMessage());
            }
        }

        public CredentialResource getDynamic(String credentialId) {
            return new CredentialResource(accountId, credentialId);
        }
    }

    public static class CredentialResource {
        private final String accountId;
        private final String credentialId;

        CredentialResource(String accountId, String credentialId) {
            this.accountId = accountId;
            this.credentialId = credentialId;
        }

        @GET
        public JSONObject doIndex() throws IOException {
            Jenkins.get().checkPermission(ServiceAccountPermissions.VIEW);
            return JSONObject.fromObject(
                    ServiceAccountManagement.credentialMap(findCredential(accountId, credentialId), false));
        }

        @RequirePOST
        public HttpResponse doRevoke() throws IOException {
            Jenkins.get().checkPermission(ServiceAccountPermissions.MANAGE_CREDENTIALS);
            try {
                ServiceAccountStore.get().revokeCredential(accountId, credentialId, actor());
                return jsonResponse(Map.of("revoked", true, "credentialId", credentialId), 200);
            } catch (IllegalArgumentException e) {
                return jsonError(400, e.getMessage());
            }
        }
    }
}
