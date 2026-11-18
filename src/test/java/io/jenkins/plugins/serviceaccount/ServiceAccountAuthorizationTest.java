package io.jenkins.plugins.serviceaccount;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.FreeStyleProject;
import hudson.model.Item;
import hudson.model.ManagementLink;
import hudson.model.ManagementLink.Category;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.HudsonPrivateSecurityRealm;
import io.jenkins.plugins.casc.ConfigurationAsCode;
import java.nio.file.Files;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import org.htmlunit.html.HtmlElement;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlInput;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;

@WithJenkins
class ServiceAccountAuthorizationTest {
    @Test
    void serviceAccountsPageIsLinkedFromManageJenkins(JenkinsRule rule) throws Exception {
        ServiceAccountManagement serviceAccountLink = ManagementLink.all().stream()
                .filter(ServiceAccountManagement.class::isInstance)
                .map(ServiceAccountManagement.class::cast)
                .findFirst()
                .orElseThrow();
        assertTrue(serviceAccountLink.getCategory() == Category.SECURITY);
        assertEquals("symbol-key", serviceAccountLink.getIconFileName());
        assertTrue(rule.jenkins.hasPermission(ServiceAccountPermissions.VIEW));
        ServiceAccountStore store =
                Jenkins.get().getExtensionList(ServiceAccountStore.class).get(0);
        store.createAccount("ui-test", "UI test account", null, "admin");
        ServiceAccountStore.CreatedCredential credential =
                store.createCredential("ui-test", "test credential", null, null, "admin");

        var webClient = rule.createWebClient();
        HtmlPage managePage = webClient.goTo("manage");
        var link = managePage.getAnchors().stream()
                .filter(anchor -> anchor.getHrefAttribute().contains("service-accounts"))
                .findFirst()
                .orElse(null);
        assertNotNull(
                link,
                managePage.getAnchors().stream()
                        .map(anchor -> anchor.getHrefAttribute() + " " + anchor.asNormalizedText())
                        .toList()
                        .toString());
        HtmlPage accountsPage = link.click();
        HtmlForm createAccountForm = accountsPage.getFirstByXPath("//form[@action='createAccount']");
        assertTrue(createAccountForm.getAttribute("class").contains("jenkins-form-item"));
        createAccountForm.getInputByName("id").setValueAttribute("browser-created");
        createAccountForm.getInputByName("displayName").setValueAttribute("Created in browser");
        HtmlPage afterCreate = (HtmlPage) ((HtmlElement) createAccountForm.getFirstByXPath(".//button")).click();
        assertTrue(
                afterCreate.getUrl().getPath().endsWith("/manage/service-accounts/"),
                afterCreate.getUrl().toString());
        assertTrue(afterCreate.asNormalizedText().contains("Created in browser"), afterCreate.asNormalizedText());

        HtmlForm duplicateAccountForm = afterCreate.getFirstByXPath("//form[@action='createAccount']");
        duplicateAccountForm.getInputByName("id").setValueAttribute("browser-created");
        duplicateAccountForm.getInputByName("displayName").setValueAttribute("Duplicate browser account");
        HtmlPage duplicateResponse =
                (HtmlPage) ((HtmlElement) duplicateAccountForm.getFirstByXPath(".//button")).click();
        assertEquals("text/html", duplicateResponse.getWebResponse().getContentType());
        assertTrue(
                duplicateResponse.asNormalizedText().contains("A service account with this identifier already exists"),
                duplicateResponse.asNormalizedText());
        assertEquals(
                "browser-created",
                ((HtmlInput) duplicateResponse.getFirstByXPath("//input[@name='id']")).getValueAttribute());
        assertEquals(
                "Duplicate browser account",
                ((HtmlInput) duplicateResponse.getFirstByXPath("//input[@name='displayName']")).getValueAttribute());

        var accountLink = afterCreate.getAnchors().stream()
                .filter(anchor -> anchor.getHrefAttribute().contains("account?id=browser-created"))
                .findFirst()
                .orElseThrow();
        HtmlPage accountPage = accountLink.click();
        assertTrue(accountPage.asNormalizedText().contains("Credentials"), accountPage.asNormalizedText());
        assertTrue(accountPage.asNormalizedText().contains("Create a credential"), accountPage.asNormalizedText());
        assertTrue(accountPage.asNormalizedText().contains("Created:"), accountPage.asNormalizedText());
        String accountPageMarkup = accountPage.asXml();
        assertFalse(accountPageMarkup.contains("onclick="), accountPageMarkup);
        assertTrue(accountPageMarkup.contains("service-account-delete-form"), accountPageMarkup);
        assertTrue(accountPageMarkup.contains("AccountPage.js"), accountPageMarkup);

        HtmlForm createCredentialForm = accountPage.getFirstByXPath("//form[contains(@action, 'createCredential')]");
        assertTrue(createCredentialForm.getAttribute("class").contains("jenkins-form-item"));
        assertTrue(accountPage
                        .getByXPath("//p[contains(@class, 'jenkins-form-item')]")
                        .size()
                >= 3);
        createCredentialForm.getInputByName("label").setValueAttribute("browser-token");
        StringBuilder storeLog = new StringBuilder();
        Logger storeLogger = Logger.getLogger(ServiceAccountStore.class.getName());
        Handler secretCapture = new Handler() {
            @Override
            public void publish(LogRecord record) {
                storeLog.append(record.getMessage());
                if (record.getThrown() != null) {
                    storeLog.append(record.getThrown());
                }
            }

            @Override
            public void flush() {}

            @Override
            public void close() {}
        };
        storeLogger.addHandler(secretCapture);
        HtmlPage credentialCreatedPage;
        try {
            credentialCreatedPage =
                    (HtmlPage) ((HtmlElement) createCredentialForm.getFirstByXPath(".//button")).click();
        } finally {
            storeLogger.removeHandler(secretCapture);
        }
        assertEquals("text/html", credentialCreatedPage.getWebResponse().getContentType());
        assertTrue(credentialCreatedPage.asNormalizedText().contains("Copy and store this secret now"));
        assertTrue(
                credentialCreatedPage.getTitleText().startsWith("Credential created"),
                credentialCreatedPage.getTitleText());
        var secretElement = credentialCreatedPage.getElementById("service-account-secret");
        assertNotNull(secretElement);
        assertFalse(secretElement.asNormalizedText().isBlank());
        String createdSecret = secretElement.asNormalizedText();
        assertFalse(storeLog.toString().contains(createdSecret));
        var returnLink = credentialCreatedPage.getAnchors().stream()
                .filter(anchor -> anchor.getHrefAttribute().contains("account?id=browser-created"))
                .findFirst()
                .orElseThrow();
        long credentialCreatedAt = store.listAccounts().stream()
                .filter(account -> account.id().equals("browser-created"))
                .findFirst()
                .orElseThrow()
                .credentials()
                .stream()
                .filter(item -> item.label().equals("browser-token"))
                .findFirst()
                .orElseThrow()
                .createdAt();
        HtmlPage updatedAccountPage = returnLink.click();
        assertTrue(updatedAccountPage.asNormalizedText().contains("browser-token"));
        assertTrue(updatedAccountPage.asNormalizedText().contains("Never"));
        assertFalse(updatedAccountPage.asNormalizedText().contains(createdSecret));
        assertFalse(updatedAccountPage.asNormalizedText().contains(Long.toString(credentialCreatedAt)));
        ServiceAccountManagement management =
                Jenkins.get().getExtensionList(ServiceAccountManagement.class).get(0);
        assertFalse(management.doApi().toString().contains(createdSecret));
        assertFalse(management.doAudit().toString().contains(createdSecret));
        assertFalse(Files.readString(rule.jenkins.getRootDir().toPath().resolve("service-accounts.xml"))
                .contains(createdSecret));
        HtmlForm revokeForm = updatedAccountPage.getFirstByXPath("//form[contains(@action, 'revokeCredential')]");
        HtmlPage revokedAccountPage = (HtmlPage) ((HtmlElement) revokeForm.getFirstByXPath(".//button")).click();
        assertTrue(revokedAccountPage.asNormalizedText().contains("revoked"));

        String pageText = accountsPage.asNormalizedText();
        assertEquals("text/html", accountsPage.getWebResponse().getContentType());
        assertTrue(accountsPage.getTitleText().startsWith("Service Accounts"), accountsPage.getTitleText());
        assertTrue(pageText.contains("Service accounts"), pageText);
        assertTrue(pageText.contains("UI test account"), pageText);
        assertFalse(pageText.contains(credential.secret()), pageText);
        assertTrue(accountPage.getByXPath("//form").size() > 0, accountPage.asXml());
        assertTrue(accountPage
                        .getByXPath("//input[@type='text' and contains(@class, 'jenkins-input')]")
                        .size()
                >= 2);
        assertTrue(accountPage
                        .getByXPath("//input[@type='number' and contains(@class, 'jenkins-input')]")
                        .size()
                >= 1);
        assertFalse(pageText.contains("<j:jelly"), pageText);
        webClient.close();
    }

    @Test
    void matrixAuthorizationTreatsEachServiceAccountAsAnIndependentPrincipal(JenkinsRule rule) throws Exception {
        rule.jenkins.setSecurityRealm(new HudsonPrivateSecurityRealm(false));
        ServiceAccountStore store =
                Jenkins.get().getExtensionList(ServiceAccountStore.class).get(0);
        store.createAccount("monitoring", "Monitoring", null, "admin");
        store.createAccount("deployment", "Deployment", null, "admin");
        ServiceAccountStore.CreatedCredential monitoringCredential =
                store.createCredential("monitoring", "read-only", null, null, "admin");
        ServiceAccountStore.CreatedCredential deploymentCredential =
                store.createCredential("deployment", "deploy", null, null, "admin");
        String monitoringPrincipal = store.listAccounts().stream()
                .filter(account -> account.id().equals("monitoring"))
                .findFirst()
                .orElseThrow()
                .principalName();
        String deploymentPrincipal = store.listAccounts().stream()
                .filter(account -> account.id().equals("deployment"))
                .findFirst()
                .orElseThrow()
                .principalName();

        GlobalMatrixAuthorizationStrategy strategy = new GlobalMatrixAuthorizationStrategy();
        strategy.add(Jenkins.READ, monitoringPrincipal);
        strategy.add(ServiceAccountPermissions.VIEW, monitoringPrincipal);
        rule.jenkins.setAuthorizationStrategy(strategy);
        FreeStyleProject project = rule.createFreeStyleProject();
        strategy.add(Item.BUILD, deploymentPrincipal);

        Authentication monitoring = authenticate(monitoringCredential);
        Authentication deployment = authenticate(deploymentCredential);
        ServiceAccountManagement management =
                Jenkins.get().getExtensionList(ServiceAccountManagement.class).get(0);

        try (ACLContext ignored = ACL.as2(monitoring)) {
            assertTrue(rule.jenkins.hasPermission(Jenkins.READ));
            assertFalse(project.hasPermission(Item.BUILD));
            String accountList = management.doApi().toString();
            assertTrue(accountList.contains("monitoring"), accountList);
            assertFalse(accountList.contains(monitoringCredential.secret()), accountList);
        }
        try (ACLContext ignored = ACL.as2(deployment)) {
            assertFalse(rule.jenkins.hasPermission(Jenkins.READ));
            assertTrue(project.hasPermission(Item.BUILD));
            assertThrows(AccessDeniedException.class, management::doApi);
        }
    }

    @Test
    void configurationAsCodeCreatesStablePrincipalsForMatrixPermissions(JenkinsRule rule) throws Exception {
        rule.jenkins.setSecurityRealm(new HudsonPrivateSecurityRealm(false));
        ServiceAccountStore store =
                Jenkins.get().getExtensionList(ServiceAccountStore.class).get(0);
        store.createAccount("retained-manual", "Retained manual account", null, "admin");
        ServiceAccountStore.CreatedCredential credential =
                store.createCredential("retained-manual", "do-not-rotate", null, null, "admin");

        String yaml = """
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
                """;
        var configFile = Files.createTempFile("service-account-jcasc", ".yaml");
        ServiceAccountStore.CreatedCredential configuredCredential;
        long configuredAt;
        int auditEventCount;
        try {
            Files.writeString(configFile, yaml);
            ConfigurationAsCode.get().configure(configFile.toString());
            configuredAt = store.listAccounts().stream()
                    .filter(account -> account.id().equals("automation-deploy"))
                    .findFirst()
                    .orElseThrow()
                    .createdAt();
            auditEventCount = store.listAuditEvents().size();
            configuredCredential = store.createCredential("automation-deploy", "deploy", null, null, "admin");
            ConfigurationAsCode.get().configure(configFile.toString());
            assertEquals(
                    configuredCredential.id(),
                    store.listAccounts().stream()
                            .filter(account -> account.id().equals("automation-deploy"))
                            .findFirst()
                            .orElseThrow()
                            .credentials()
                            .get(0)
                            .id());
            Files.writeString(configFile, yaml.replace("Deploys approved applications", "Deploys approved workloads"));
            ConfigurationAsCode.get().configure(configFile.toString());
        } finally {
            Files.deleteIfExists(configFile);
        }

        var configuredAccount = store.listAccounts().stream()
                .filter(account -> account.id().equals("automation-deploy"))
                .findFirst()
                .orElseThrow();
        assertEquals("service-account-automation-deploy", configuredAccount.principalName());
        assertEquals(configuredAt, configuredAccount.createdAt());
        assertEquals("Deploys approved workloads", configuredAccount.description());
        assertEquals(auditEventCount + 2, store.listAuditEvents().size());
        assertEquals(
                credential.id(),
                store.listAccounts().stream()
                        .filter(account -> account.id().equals("retained-manual"))
                        .findFirst()
                        .orElseThrow()
                        .credentials()
                        .get(0)
                        .id());
        Authentication authentication = authenticate(configuredCredential);
        try (ACLContext ignored = ACL.as2(authentication)) {
            assertTrue(rule.jenkins.hasPermission(Jenkins.READ));
            assertFalse(rule.jenkins.hasPermission(Jenkins.ADMINISTER));
        }
    }

    @Test
    void accountCreationRejectsPrincipalCollisionsWithRealmUsers(JenkinsRule rule) throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false);
        realm.createAccount("service-account-reserved", "password");
        rule.jenkins.setSecurityRealm(realm);
        ServiceAccountStore store =
                Jenkins.get().getExtensionList(ServiceAccountStore.class).get(0);

        assertThrows(IllegalArgumentException.class, () -> store.createAccount("reserved", "Reserved", null, "admin"));
    }

    private static Authentication authenticate(ServiceAccountStore.CreatedCredential credential) throws Exception {
        Authentication authentication = new ServiceAccountAuthenticator()
                .authenticate2(
                        (jakarta.servlet.http.HttpServletRequest) null,
                        (jakarta.servlet.http.HttpServletResponse) null,
                        credential.username(),
                        credential.secret());
        assertNotNull(authentication);
        return authentication;
    }
}
