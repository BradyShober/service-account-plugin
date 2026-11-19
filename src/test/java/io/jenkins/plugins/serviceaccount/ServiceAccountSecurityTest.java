package io.jenkins.plugins.serviceaccount;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.csrf.DefaultCrumbIssuer;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.htmlunit.HttpMethod;
import org.htmlunit.WebRequest;
import org.htmlunit.util.NameValuePair;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

@WithJenkins
class ServiceAccountSecurityTest {
    @Test
    void credentialCreationApiReturnsOneTimeSecretAsJson(JenkinsRule rule) throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false);
        realm.createAccount("operator", "password");
        rule.jenkins.setSecurityRealm(realm);
        GlobalMatrixAuthorizationStrategy strategy = new GlobalMatrixAuthorizationStrategy();
        strategy.add(Jenkins.ADMINISTER, "operator");
        rule.jenkins.setAuthorizationStrategy(strategy);
        ServiceAccountStore store =
                Jenkins.get().getExtensionList(ServiceAccountStore.class).get(0);
        store.createAccount("api-created", "API created", null, "admin");

        var webClient = rule.createWebClient().login("operator", "password");
        try {
            WebRequest crumbRequest = new WebRequest(
                    rule.getURL().toURI().resolve("crumbIssuer/api/json").toURL());
            JSONObject crumbResponse = JSONObject.fromObject(
                    webClient.loadWebResponse(crumbRequest).getContentAsString());
            WebRequest request = createCredentialRequest(rule, "api-created");
            var headers = new HashMap<String, String>();
            headers.put(crumbResponse.getString("crumbRequestField"), crumbResponse.getString("crumb"));
            headers.put("Content-Type", "application/json");
            request.setAdditionalHeaders(headers);

            var response = webClient.loadWebResponse(request);
            assertEquals(201, response.getStatusCode());
            assertTrue(response.getContentType().contains("application/json"), response.getContentType());
            JSONObject credential = JSONObject.fromObject(response.getContentAsString());
            assertTrue(credential.getString("credentialId").length() > 0);
            assertEquals("service-account-api-created", credential.getString("username"));
            String secret = credential.getString("secret");
            assertFalse(secret.isBlank());

            ServiceAccountAuthenticator authenticator = new ServiceAccountAuthenticator();
            assertNotNull(authenticator.authenticate2(
                    (jakarta.servlet.http.HttpServletRequest) null,
                    (jakarta.servlet.http.HttpServletResponse) null,
                    credential.getString("username"),
                    secret));
        } finally {
            webClient.close();
        }
    }

    @Test
    void managementOperationsRequireTheirSpecificPermissions(JenkinsRule rule) throws Exception {
        ServiceAccountStore store =
                Jenkins.get().getExtensionList(ServiceAccountStore.class).get(0);
        store.createAccount("protected", "Protected account", null, "admin");
        store.createCredential("protected", "existing", null, null, "admin");
        rule.jenkins.setAuthorizationStrategy(new GlobalMatrixAuthorizationStrategy());
        ServiceAccountManagement management =
                Jenkins.get().getExtensionList(ServiceAccountManagement.class).get(0);
        var limitedUser = new UsernamePasswordAuthenticationToken("limited", "", List.of());

        try (ACLContext ignored = ACL.as2(limitedUser)) {
            assertThrows(AccessDeniedException.class, () -> management.getApi().doIndex());
            assertThrows(AccessDeniedException.class, () -> management.getApi().doAudit());
            assertThrows(
                    AccessDeniedException.class, () -> management.doCreateAccount("new", "New account", null, null));
            assertThrows(
                    AccessDeniedException.class,
                    () -> management
                            .getApi()
                            .getAccounts()
                            .getDynamic("protected")
                            .doUpdate());
            assertThrows(
                    AccessDeniedException.class,
                    () -> management.doCreateCredential("protected", "new", null, null, null));
            assertThrows(AccessDeniedException.class, () -> management.doDisableAccount("protected"));
            assertThrows(AccessDeniedException.class, () -> management.doRevokeCredential("protected", "missing"));
            assertThrows(AccessDeniedException.class, () -> management.doDeleteAccount("protected"));
        }
    }

    @Test
    void mutatingHttpEndpointRequiresCrumb(JenkinsRule rule) throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false);
        realm.createAccount("operator", "password");
        rule.jenkins.setSecurityRealm(realm);
        GlobalMatrixAuthorizationStrategy strategy = new GlobalMatrixAuthorizationStrategy();
        strategy.add(Jenkins.ADMINISTER, "operator");
        rule.jenkins.setAuthorizationStrategy(strategy);
        rule.jenkins.setCrumbIssuer(new DefaultCrumbIssuer(false));

        var webClient = rule.createWebClient().login("operator", "password");
        try {
            WebRequest withoutCrumb = createAccountRequest(rule, "csrf-rejected");
            assertEquals(403, webClient.loadWebResponse(withoutCrumb).getStatusCode());

            WebRequest crumbRequest = new WebRequest(
                    rule.getURL().toURI().resolve("crumbIssuer/api/json").toURL());
            JSONObject crumbResponse = JSONObject.fromObject(
                    webClient.loadWebResponse(crumbRequest).getContentAsString());
            WebRequest withCrumb = createAccountRequest(rule, "csrf-accepted");
            var headers = new HashMap<String, String>();
            headers.put(crumbResponse.getString("crumbRequestField"), crumbResponse.getString("crumb"));
            withCrumb.setAdditionalHeaders(headers);
            assertEquals(200, webClient.loadWebResponse(withCrumb).getStatusCode());
            assertEquals(
                    "csrf-accepted",
                    Jenkins.get().getExtensionList(ServiceAccountStore.class).get(0).listAccounts().stream()
                            .filter(account -> account.id().equals("csrf-accepted"))
                            .findFirst()
                            .orElseThrow()
                            .id());
        } finally {
            webClient.close();
        }
    }

    @Test
    void serviceAccountCanCallPluginMutationApiWithoutCrumbButNoOtherEndpoint(JenkinsRule rule) throws Exception {
        rule.jenkins.setSecurityRealm(new HudsonPrivateSecurityRealm(false));
        rule.jenkins.setCrumbIssuer(new DefaultCrumbIssuer());
        ServiceAccountStore store =
                Jenkins.get().getExtensionList(ServiceAccountStore.class).get(0);
        store.createAccount("api-operator", "API operator", null, "admin");
        ServiceAccountStore.CreatedCredential credential =
                store.createCredential("api-operator", "automation", null, null, "admin");

        GlobalMatrixAuthorizationStrategy strategy = new GlobalMatrixAuthorizationStrategy();
        strategy.add(Jenkins.READ, credential.username());
        strategy.add(ServiceAccountPermissions.CREATE, credential.username());
        rule.jenkins.setAuthorizationStrategy(strategy);

        HttpURLConnection allowedRequest =
                postJsonAsServiceAccount(rule, credential, "manage/service-accounts/api/accounts/create", """
                {"id":"created-without-crumb","displayName":"Created without crumb"}
                """);
        try {
            int status = allowedRequest.getResponseCode();
            assertEquals(201, status);
        } finally {
            allowedRequest.disconnect();
        }
        assertTrue(
                store.listAccounts().stream().anyMatch(account -> account.id().equals("created-without-crumb")));

        HttpURLConnection invalidCredentialRequest = postJsonAsServiceAccount(
                rule,
                credential.username(),
                credential.secret() + "-invalid",
                "manage/service-accounts/api/accounts/create",
                """
                {"id":"invalid-credential","displayName":"Invalid credential"}
                """);
        try {
            assertEquals(401, invalidCredentialRequest.getResponseCode());
        } finally {
            invalidCredentialRequest.disconnect();
        }

        HttpURLConnection outOfScopeRequest =
                postAsServiceAccount(rule, credential, "manage/service-accounts/api/notAnApiMutation", "");
        try {
            assertEquals(403, outOfScopeRequest.getResponseCode());
        } finally {
            outOfScopeRequest.disconnect();
        }
    }

    @Test
    void createAccountApiAcceptsJsonBody(JenkinsRule rule) throws Exception {
        rule.jenkins.setSecurityRealm(new HudsonPrivateSecurityRealm(false));
        ServiceAccountStore store =
                Jenkins.get().getExtensionList(ServiceAccountStore.class).get(0);
        store.createAccount("json-operator", "JSON operator", null, "admin");
        ServiceAccountStore.CreatedCredential credential =
                store.createCredential("json-operator", "automation", null, null, "admin");
        GlobalMatrixAuthorizationStrategy strategy = new GlobalMatrixAuthorizationStrategy();
        strategy.add(Jenkins.READ, credential.username());
        strategy.add(ServiceAccountPermissions.VIEW, credential.username());
        strategy.add(ServiceAccountPermissions.CREATE, credential.username());
        rule.jenkins.setAuthorizationStrategy(strategy);

        HttpURLConnection request =
                postJsonAsServiceAccount(rule, credential, "manage/service-accounts/api/accounts/create", """
                {
                    "id": "apitest",
                    "displayName": "API Test",
                    "description": "Created via API"
                }
                """);
        try {
            assertEquals(201, request.getResponseCode());
            assertTrue(request.getContentType().contains("application/json"));
            JSONObject response =
                    JSONObject.fromObject(new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
            assertTrue(response.getBoolean("created"));
            assertEquals("apitest", response.getString("id"));
        } finally {
            request.disconnect();
        }

        ServiceAccountStore.AccountSummary createdAccount = store.listAccounts().stream()
                .filter(account -> account.id().equals("apitest"))
                .findFirst()
                .orElseThrow();
        assertEquals("API Test", createdAccount.displayName());
        assertEquals("Created via API", createdAccount.description());

        HttpURLConnection accountRequest =
                getAsServiceAccount(rule, credential, "manage/service-accounts/api/accounts/apitest");
        try {
            assertEquals(200, accountRequest.getResponseCode());
            JSONObject accountResponse = JSONObject.fromObject(
                    new String(accountRequest.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
            assertEquals("API Test", accountResponse.getString("displayName"));
        } finally {
            accountRequest.disconnect();
        }

        HttpURLConnection credentialsRequest =
                getAsServiceAccount(rule, credential, "manage/service-accounts/api/accounts/apitest/credentials");
        try {
            assertEquals(200, credentialsRequest.getResponseCode());
            JSONObject credentialsResponse = JSONObject.fromObject(
                    new String(credentialsRequest.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
            assertEquals(0, credentialsResponse.getJSONArray("credentials").size());
        } finally {
            credentialsRequest.disconnect();
        }

        HttpURLConnection formApiRequest = postAsServiceAccount(
                rule, credential, "manage/service-accounts/api/accounts/create", "id=form-api&displayName=Form+API");
        try {
            assertEquals(415, formApiRequest.getResponseCode());
        } finally {
            formApiRequest.disconnect();
        }
    }

    private static HttpURLConnection postAsServiceAccount(
            JenkinsRule rule, ServiceAccountStore.CreatedCredential credential, String path, String body)
            throws Exception {
        return postAsServiceAccount(rule, credential.username(), credential.secret(), path, body);
    }

    private static HttpURLConnection postAsServiceAccount(
            JenkinsRule rule, String username, String secret, String path, String body) throws Exception {
        URLConnection connection = rule.getURL().toURI().resolve(path).toURL().openConnection();
        HttpURLConnection http = (HttpURLConnection) connection;
        http.setInstanceFollowRedirects(false);
        http.setRequestMethod("POST");
        http.setDoOutput(true);
        String basic = username + ":" + secret;
        http.setRequestProperty(
                "Authorization", "Basic " + Base64.getEncoder().encodeToString(basic.getBytes(StandardCharsets.UTF_8)));
        http.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        try (OutputStream output = http.getOutputStream()) {
            output.write(body.getBytes(StandardCharsets.UTF_8));
        }
        return http;
    }

    private static HttpURLConnection getAsServiceAccount(
            JenkinsRule rule, ServiceAccountStore.CreatedCredential credential, String path) throws Exception {
        URLConnection connection = rule.getURL().toURI().resolve(path).toURL().openConnection();
        HttpURLConnection http = (HttpURLConnection) connection;
        String basic = credential.username() + ":" + credential.secret();
        http.setRequestProperty(
                "Authorization", "Basic " + Base64.getEncoder().encodeToString(basic.getBytes(StandardCharsets.UTF_8)));
        return http;
    }

    private static HttpURLConnection postJsonAsServiceAccount(
            JenkinsRule rule, ServiceAccountStore.CreatedCredential credential, String path, String body)
            throws Exception {
        return postJsonAsServiceAccount(rule, credential.username(), credential.secret(), path, body);
    }

    private static HttpURLConnection postJsonAsServiceAccount(
            JenkinsRule rule, String username, String secret, String path, String body) throws Exception {
        URLConnection connection = rule.getURL().toURI().resolve(path).toURL().openConnection();
        HttpURLConnection http = (HttpURLConnection) connection;
        http.setInstanceFollowRedirects(false);
        http.setRequestMethod("POST");
        http.setDoOutput(true);
        String basic = username + ":" + secret;
        http.setRequestProperty(
                "Authorization", "Basic " + Base64.getEncoder().encodeToString(basic.getBytes(StandardCharsets.UTF_8)));
        http.setRequestProperty("Content-Type", "application/json");
        try (OutputStream output = http.getOutputStream()) {
            output.write(body.getBytes(StandardCharsets.UTF_8));
        }
        return http;
    }

    private static WebRequest createAccountRequest(JenkinsRule rule, String id) throws Exception {
        WebRequest request = new WebRequest(rule.getURL()
                .toURI()
                .resolve("manage/service-accounts/createAccount")
                .toURL());
        request.setHttpMethod(HttpMethod.POST);
        request.setRequestParameters(List.of(
                new NameValuePair("id", id),
                new NameValuePair("displayName", id),
                new NameValuePair("fromUi", "true")));
        return request;
    }

    private static WebRequest createCredentialRequest(JenkinsRule rule, String accountId) throws Exception {
        WebRequest request = new WebRequest(rule.getURL()
                .toURI()
                .resolve("manage/service-accounts/api/accounts/" + accountId + "/credentials/create")
                .toURL());
        request.setHttpMethod(HttpMethod.POST);
        request.setRequestBody("{\"label\":\"from-api\"}");
        request.setAdditionalHeader("Content-Type", "application/json");
        return request;
    }
}
