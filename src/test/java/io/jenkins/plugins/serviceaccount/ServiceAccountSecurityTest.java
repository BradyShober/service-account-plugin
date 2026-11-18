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
            assertThrows(AccessDeniedException.class, management::doApi);
            assertThrows(AccessDeniedException.class, management::doAudit);
            assertThrows(
                    AccessDeniedException.class, () -> management.doCreateAccount("new", "New account", null, null));
            assertThrows(AccessDeniedException.class, () -> management.doUpdateAccount("protected", "Updated", null));
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
                .resolve("manage/service-accounts/createCredential")
                .toURL());
        request.setHttpMethod(HttpMethod.POST);
        request.setRequestParameters(
                List.of(new NameValuePair("accountId", accountId), new NameValuePair("label", "from-api")));
        return request;
    }
}
