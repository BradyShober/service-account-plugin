package io.jenkins.plugins.serviceaccount;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.security.AuthorizationStrategy;
import hudson.security.HudsonPrivateSecurityRealm;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import jenkins.model.Jenkins;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class ServiceAccountAuthenticatorTest {
    @Test
    void authenticatesOverHttpWithoutAnExternalRealmUser(JenkinsRule rule) throws Exception {
        rule.jenkins.setSecurityRealm(new HudsonPrivateSecurityRealm(false));
        rule.jenkins.setAuthorizationStrategy(AuthorizationStrategy.UNSECURED);

        ServiceAccountStore store =
                Jenkins.get().getExtensionList(ServiceAccountStore.class).get(0);
        store.createAccount("automation-deploy", "Automation deploy", "Deployment automation", "admin");
        ServiceAccountStore.CreatedCredential credential =
                store.createCredential("automation-deploy", "deploy", null, null, "admin");

        HttpURLConnection connection = (HttpURLConnection)
                rule.getURL().toURI().resolve("whoAmI/api/json").toURL().openConnection();
        connection.setInstanceFollowRedirects(false);
        String basic = credential.username() + ":" + credential.secret();
        connection.setRequestProperty(
                "Authorization", "Basic " + Base64.getEncoder().encodeToString(basic.getBytes(StandardCharsets.UTF_8)));

        int status = connection.getResponseCode();
        String body = new String(connection.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        connection.disconnect();

        assertEquals(200, status);
        assertTrue(body.contains("service-account-"), body);
    }

    @Test
    void authenticatesOverHttpWithAnExternalRealm(JenkinsRule rule) throws Exception {
        rule.jenkins.setSecurityRealm(rule.createDummySecurityRealm());
        rule.jenkins.setAuthorizationStrategy(AuthorizationStrategy.UNSECURED);

        ServiceAccountStore store =
                Jenkins.get().getExtensionList(ServiceAccountStore.class).get(0);
        store.createAccount("external-realm", "External realm", null, "admin");
        ServiceAccountStore.CreatedCredential credential =
                store.createCredential("external-realm", "api", null, null, "admin");

        HttpURLConnection connection = (HttpURLConnection)
                rule.getURL().toURI().resolve("whoAmI/api/json").toURL().openConnection();
        connection.setInstanceFollowRedirects(false);
        String basic = credential.username() + ":" + credential.secret();
        connection.setRequestProperty(
                "Authorization", "Basic " + Base64.getEncoder().encodeToString(basic.getBytes(StandardCharsets.UTF_8)));

        int status = connection.getResponseCode();
        String body = new String(connection.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        connection.disconnect();

        assertEquals(200, status);
        assertTrue(body.contains("service-account-"), body);
    }

    @Test
    void serviceAccountCredentialsContinueWorkingAfterRealmChanges(JenkinsRule rule) throws Exception {
        rule.jenkins.setSecurityRealm(new HudsonPrivateSecurityRealm(false));
        rule.jenkins.setAuthorizationStrategy(AuthorizationStrategy.UNSECURED);
        ServiceAccountStore store =
                Jenkins.get().getExtensionList(ServiceAccountStore.class).get(0);
        store.createAccount("realm-switch", "Realm switch", null, "admin");
        ServiceAccountStore.CreatedCredential credential =
                store.createCredential("realm-switch", "api", null, null, "admin");

        assertEquals(200, whoAmIStatus(rule, credential));
        rule.jenkins.setSecurityRealm(rule.createDummySecurityRealm());
        assertEquals(200, whoAmIStatus(rule, credential));
        rule.jenkins.setSecurityRealm(new HudsonPrivateSecurityRealm(false));
        assertEquals(200, whoAmIStatus(rule, credential));
    }

    @Test
    void invalidTokenDoesNotAuthenticateAsServiceAccount(JenkinsRule rule) throws Exception {
        rule.jenkins.setSecurityRealm(new HudsonPrivateSecurityRealm(false));
        ServiceAccountStore store =
                Jenkins.get().getExtensionList(ServiceAccountStore.class).get(0);
        store.createAccount("automation-monitoring", "Monitoring", null, "admin");
        ServiceAccountStore.CreatedCredential credential =
                store.createCredential("automation-monitoring", "monitoring", null, null, "admin");

        assertNull(new ServiceAccountAuthenticator()
                .authenticate2(
                        (jakarta.servlet.http.HttpServletRequest) null,
                        (jakarta.servlet.http.HttpServletResponse) null,
                        credential.username(),
                        "invalid-token"));
    }

    @Test
    void invalidTokenIsRejectedOverHttp(JenkinsRule rule) throws Exception {
        rule.jenkins.setSecurityRealm(new HudsonPrivateSecurityRealm(false));
        rule.jenkins.setAuthorizationStrategy(AuthorizationStrategy.UNSECURED);
        ServiceAccountStore store =
                Jenkins.get().getExtensionList(ServiceAccountStore.class).get(0);
        store.createAccount("automation-rejected", "Rejected", null, "admin");
        ServiceAccountStore.CreatedCredential credential =
                store.createCredential("automation-rejected", "active", null, null, "admin");

        HttpURLConnection connection = (HttpURLConnection)
                rule.getURL().toURI().resolve("whoAmI/api/json").toURL().openConnection();
        connection.setInstanceFollowRedirects(false);
        String basic = credential.username() + ":invalid-token";
        connection.setRequestProperty(
                "Authorization", "Basic " + Base64.getEncoder().encodeToString(basic.getBytes(StandardCharsets.UTF_8)));

        int status = connection.getResponseCode();
        connection.disconnect();

        assertEquals(401, status);
    }

    @Test
    void storesOnlyVerifierAndSurvivesStoreReload(JenkinsRule rule) throws Exception {
        ServiceAccountStore store =
                Jenkins.get().getExtensionList(ServiceAccountStore.class).get(0);
        store.createAccount("automation-jcasc", "JCasC automation", null, "admin");
        ServiceAccountStore.CreatedCredential credential =
                store.createCredential("automation-jcasc", "config", null, null, "admin");

        String persisted = Files.readString(rule.jenkins.getRootDir().toPath().resolve("service-accounts.xml"));
        assertFalse(persisted.contains(credential.secret()));

        ServiceAccountStore reloaded = new ServiceAccountStore();
        ServiceAccountStore.AuthenticatedAccount result =
                reloaded.authenticate("automation-jcasc", credential.id(), credential.secret());
        assertNotNull(result);
        assertTrue(result.principalName().startsWith("service-account-"));
    }

    @Test
    void deletingAccountRemovesAccountAndCredentialDataButKeepsAuditHistory(JenkinsRule rule) throws Exception {
        ServiceAccountStore store =
                Jenkins.get().getExtensionList(ServiceAccountStore.class).get(0);
        store.createAccount("delete-me", "Delete me", null, "admin");
        ServiceAccountStore.CreatedCredential credential =
                store.createCredential("delete-me", "automation", null, null, "admin");

        store.deleteAccount("delete-me", "admin");

        ServiceAccountStore reloaded = new ServiceAccountStore();
        assertTrue(reloaded.listAccounts().isEmpty());
        assertNull(reloaded.authenticate("delete-me", credential.id(), credential.secret()));
        assertTrue(reloaded.listAuditEvents().stream()
                .anyMatch(event -> event.type().equals("ACCOUNT_DELETED") && event.accountId().equals("delete-me")));
        String persisted = Files.readString(rule.jenkins.getRootDir().toPath().resolve("service-accounts.xml"));
        assertFalse(persisted.contains("<verifier>"));
        store.createAccount("delete-me", "Recreated", null, "admin");
        assertTrue(store.listAccounts().stream()
                .filter(account -> account.id().equals("delete-me"))
                .findFirst()
                .orElseThrow()
                .credentials()
                .isEmpty());
        assertNull(store.authenticate("delete-me", credential.id(), credential.secret()));
    }

    @Test
    void revocationDisablementAndExpirationAreEnforced(JenkinsRule rule) throws Exception {
        ServiceAccountStore store =
                Jenkins.get().getExtensionList(ServiceAccountStore.class).get(0);
        store.createAccount("lifecycle", "Lifecycle", null, "admin");
        ServiceAccountStore.CreatedCredential first = store.createCredential("lifecycle", "first", null, null, "admin");
        ServiceAccountStore.CreatedCredential second =
                store.createCredential("lifecycle", "second", null, null, "admin");

        assertNotNull(store.authenticate("lifecycle", first.id(), first.secret()));
        assertNotNull(store.authenticate("lifecycle", second.id(), second.secret()));

        store.revokeCredential("lifecycle", first.id(), "admin");
        assertNull(store.authenticate("lifecycle", first.id(), first.secret()));
        assertNotNull(store.authenticate("lifecycle", second.id(), second.secret()));

        store.setAccountEnabled("lifecycle", false, "admin");
        assertNull(store.authenticate("lifecycle", second.id(), second.secret()));
        store.setAccountEnabled("lifecycle", true, "admin");
        assertNotNull(store.authenticate("lifecycle", second.id(), second.secret()));

        long expiresAt = store.listAccounts().get(0).credentials().stream()
                .filter(credential -> credential.id().equals(second.id()))
                .findFirst()
                .orElseThrow()
                .expiresAt();
        assertNotNull(store.authenticate("lifecycle", second.id(), second.secret(), expiresAt - 1));
        assertNull(store.authenticate("lifecycle", second.id(), second.secret(), expiresAt));
    }

    @Test
    void credentialUsernameIsStableAcrossIndependentTokens(JenkinsRule rule) throws Exception {
        ServiceAccountStore store =
                Jenkins.get().getExtensionList(ServiceAccountStore.class).get(0);
        store.createAccount("rotation", "Rotation", null, "admin");
        ServiceAccountStore.CreatedCredential first = store.createCredential("rotation", "first", null, null, "admin");
        ServiceAccountStore.CreatedCredential second =
                store.createCredential("rotation", "second", null, null, "admin");

        assertEquals(first.username(), second.username());
        assertEquals("service-account-rotation", first.username());
        assertNotNull(authenticate(first));
        assertNotNull(authenticate(second));
        ServiceAccountAuthenticator authenticator = new ServiceAccountAuthenticator();
        assertNotNull(authenticator.authenticate2(
                (jakarta.servlet.http.HttpServletRequest) null,
                (jakarta.servlet.http.HttpServletResponse) null,
                first.username(),
                first.secret()));
        assertNotNull(authenticator.authenticate2(
                (jakarta.servlet.http.HttpServletRequest) null,
                (jakarta.servlet.http.HttpServletResponse) null,
                second.username(),
                second.secret()));
        store.revokeCredential("rotation", first.id(), "admin");
        assertNull(authenticate(first));
        assertNotNull(authenticate(second));
        assertNull(authenticator.authenticate2(
                (jakarta.servlet.http.HttpServletRequest) null,
                (jakarta.servlet.http.HttpServletResponse) null,
                first.username(),
                first.secret()));
        assertNotNull(authenticator.authenticate2(
                (jakarta.servlet.http.HttpServletRequest) null,
                (jakarta.servlet.http.HttpServletResponse) null,
                second.username(),
                second.secret()));
    }

    @Test
    void credentialLifetimePolicyRejectsInvalidValues(JenkinsRule rule) throws Exception {
        ServiceAccountStore store =
                Jenkins.get().getExtensionList(ServiceAccountStore.class).get(0);
        store.createAccount("policy", "Policy", null, "admin");

        assertThrows(
                IllegalArgumentException.class,
                () -> store.createCredential("policy", "non-expiring", null, 0, "admin"));
        assertThrows(
                IllegalArgumentException.class, () -> store.createCredential("policy", "too-long", null, 366, "admin"));
    }

    @Test
    void concurrentCredentialCreationPersistsUsableIndependentCredentials(JenkinsRule rule) throws Exception {
        ServiceAccountStore store =
                Jenkins.get().getExtensionList(ServiceAccountStore.class).get(0);
        store.createAccount("concurrent", "Concurrent", null, "admin");

        int credentialCount = 12;
        ExecutorService executor = Executors.newFixedThreadPool(6);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<ServiceAccountStore.CreatedCredential>> futures = new ArrayList<>();
            for (int i = 0; i < credentialCount; i++) {
                int credentialNumber = i;
                futures.add(executor.submit(() -> {
                    start.await();
                    return store.createCredential("concurrent", "credential-" + credentialNumber, null, null, "admin");
                }));
            }
            start.countDown();
            List<ServiceAccountStore.CreatedCredential> credentials = new ArrayList<>();
            for (Future<ServiceAccountStore.CreatedCredential> future : futures) {
                credentials.add(future.get());
            }

            assertEquals(
                    credentialCount,
                    credentials.stream()
                            .map(ServiceAccountStore.CreatedCredential::id)
                            .distinct()
                            .count());
            for (ServiceAccountStore.CreatedCredential credential : credentials) {
                assertNotNull(store.authenticate(credential.username(), credential.secret()));
            }
            assertEquals(
                    credentialCount,
                    store.listAccounts().stream()
                            .filter(account -> account.id().equals("concurrent"))
                            .findFirst()
                            .orElseThrow()
                            .credentials()
                            .size());
        } finally {
            executor.shutdownNow();
        }
    }

    private static int whoAmIStatus(JenkinsRule rule, ServiceAccountStore.CreatedCredential credential)
            throws Exception {
        HttpURLConnection connection = (HttpURLConnection)
                rule.getURL().toURI().resolve("whoAmI/api/json").toURL().openConnection();
        String basic = credential.username() + ":" + credential.secret();
        connection.setRequestProperty(
                "Authorization", "Basic " + Base64.getEncoder().encodeToString(basic.getBytes(StandardCharsets.UTF_8)));
        int status = connection.getResponseCode();
        connection.disconnect();
        return status;
    }

    private static ServiceAccountStore.AuthenticatedAccount authenticate(
            ServiceAccountStore.CreatedCredential credential) throws Exception {
        return Jenkins.get()
                .getExtensionList(ServiceAccountStore.class)
                .get(0)
                .authenticate(credential.username(), credential.secret());
    }
}
