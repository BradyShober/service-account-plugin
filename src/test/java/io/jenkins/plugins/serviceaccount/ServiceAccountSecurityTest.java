package io.jenkins.plugins.serviceaccount;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
                    AccessDeniedException.class, () -> management.doCreateCredential("protected", "new", null, null));
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
}
