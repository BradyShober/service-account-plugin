package io.jenkins.plugins.serviceaccount;

import hudson.Extension;
import hudson.XmlFile;
import hudson.model.User;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.util.XStream2;
import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@Extension
public class ServiceAccountStore {
    static final String PRINCIPAL_PREFIX = "service-account-";
    private static final String STORE_FILENAME = "service-accounts.xml";
    private static final long LAST_USED_SAVE_INTERVAL_MILLIS = 60_000L;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final XStream2 XSTREAM = new XStream2();
    private static final Logger LOGGER = Logger.getLogger(ServiceAccountStore.class.getName());

    private Map<String, AccountRecord> accounts = new LinkedHashMap<>();
    private List<AuditEventRecord> auditEvents = new ArrayList<>();
    private transient boolean loaded;

    static ServiceAccountStore get() {
        return Jenkins.get().getExtensionList(ServiceAccountStore.class).get(0);
    }

    synchronized void createAccount(String id, String displayName, String description, String creator)
            throws IOException {
        ensureLoaded();
        validateId(id);
        validateText(displayName, "Display name", 128, false);
        validateText(description, "Description", 1024, true);
        if (accounts.containsKey(id)) {
            throw new IllegalArgumentException("A service account with this identifier already exists");
        }

        String principalName = principalName(id);
        validatePrincipalAvailable(id, principalName);

        AccountRecord account = new AccountRecord();
        account.id = id;
        account.principalName = principalName;
        account.displayName = displayName;
        account.description = description;
        account.createdAt = System.currentTimeMillis();
        account.createdBy = creator;
        account.credentials = new LinkedHashMap<>();
        accounts.put(id, account);
        addEvent("ACCOUNT_CREATED", account, null, creator);
        try {
            save();
        } catch (IOException e) {
            accounts.remove(id);
            auditEvents.remove(auditEvents.size() - 1);
            throw e;
        }
    }

    synchronized void upsertConfiguredAccounts(List<ServiceAccountDefinition> definitions) throws IOException {
        ensureLoaded();
        Map<String, ServiceAccountDefinition> uniqueDefinitions = new LinkedHashMap<>();
        for (ServiceAccountDefinition definition : definitions) {
            validateId(definition.getId());
            validateText(definition.getDisplayName(), "Display name", 128, false);
            validateText(definition.getDescription(), "Description", 1024, true);
            if (uniqueDefinitions.putIfAbsent(definition.getId(), definition) != null) {
                throw new IllegalArgumentException("Duplicate service-account identifier: " + definition.getId());
            }

            AccountRecord existing = accounts.get(definition.getId());
            if (existing == null) {
                validatePrincipalAvailable(definition.getId(), principalName(definition.getId()));
            }
        }

        List<AccountRecord> added = new ArrayList<>();
        Map<AccountRecord, AccountMetadata> changed = new LinkedHashMap<>();
        int previousEventCount = auditEvents.size();
        for (ServiceAccountDefinition definition : uniqueDefinitions.values()) {
            AccountRecord account = accounts.get(definition.getId());
            if (account == null) {
                account = new AccountRecord();
                account.id = definition.getId();
                account.principalName = principalName(definition.getId());
                account.displayName = definition.getDisplayName();
                account.description = definition.getDescription();
                account.createdAt = System.currentTimeMillis();
                account.createdBy = "JCasC";
                account.credentials = new LinkedHashMap<>();
                accounts.put(account.id, account);
                added.add(account);
                addEvent("ACCOUNT_CREATED", account, null, "JCasC");
            } else if (!java.util.Objects.equals(account.displayName, definition.getDisplayName())
                    || !java.util.Objects.equals(account.description, definition.getDescription())) {
                changed.put(account, new AccountMetadata(account.displayName, account.description));
                account.displayName = definition.getDisplayName();
                account.description = definition.getDescription();
                addEvent("ACCOUNT_UPDATED", account, null, "JCasC");
            }
        }
        if (added.isEmpty() && changed.isEmpty()) {
            return;
        }
        try {
            save();
        } catch (IOException e) {
            rollbackConfiguredAccounts(added, changed, previousEventCount);
            throw e;
        }
    }

    private synchronized void rollbackConfiguredAccounts(
            List<AccountRecord> added, Map<AccountRecord, AccountMetadata> changed, int previousEventCount) {
        for (AccountRecord account : added) {
            accounts.remove(account.id);
        }
        for (Map.Entry<AccountRecord, AccountMetadata> entry : changed.entrySet()) {
            AccountRecord account = entry.getKey();
            AccountMetadata metadata = entry.getValue();
            account.displayName = metadata.displayName();
            account.description = metadata.description();
        }
        auditEvents.subList(previousEventCount, auditEvents.size()).clear();
    }

    synchronized CreatedCredential createCredential(
            String accountId, String label, String description, Integer lifetimeDays, String creator)
            throws IOException {
        ensureLoaded();
        AccountRecord account = accounts.get(accountId);
        if (account == null) {
            throw new IllegalArgumentException("Service account does not exist");
        }
        if (!account.enabled) {
            throw new IllegalArgumentException("Cannot create credentials for a disabled service account");
        }
        validateText(label, "Credential label", 128, false);
        validateText(description, "Description", 1024, true);

        byte[] random = new byte[32];
        RANDOM.nextBytes(random);
        String secret = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        Arrays.fill(random, (byte) 0);

        long now = System.currentTimeMillis();
        CredentialRecord credential = new CredentialRecord();
        credential.id = UUID.randomUUID().toString();
        credential.label = label;
        credential.description = description;
        credential.verifier = verifier(secret);
        credential.createdAt = now;
        credential.createdBy = creator;
        credential.expiresAt = ServiceAccountConfiguration.get().getExpirationTime(lifetimeDays, now);
        account.credentials.put(credential.id, credential);
        addEvent("CREDENTIAL_CREATED", account, credential, creator);
        try {
            save();
        } catch (IOException e) {
            account.credentials.remove(credential.id);
            auditEvents.remove(auditEvents.size() - 1);
            throw e;
        }
        return new CreatedCredential(credential.id, credentialUsername(account.id), secret);
    }

    synchronized void updateAccount(String accountId, String displayName, String description, String actor)
            throws IOException {
        ensureLoaded();
        AccountRecord account = requireActiveAccount(accountId);
        validateText(displayName, "Display name", 128, false);
        validateText(description, "Description", 1024, true);
        String oldDisplayName = account.displayName;
        String oldDescription = account.description;
        account.displayName = displayName;
        account.description = description;
        addEvent("ACCOUNT_UPDATED", account, null, actor);
        try {
            save();
        } catch (IOException e) {
            account.displayName = oldDisplayName;
            account.description = oldDescription;
            auditEvents.remove(auditEvents.size() - 1);
            throw e;
        }
    }

    synchronized void setAccountEnabled(String accountId, boolean enabled, String actor) throws IOException {
        ensureLoaded();
        AccountRecord account = requireActiveAccount(accountId);
        if (account.enabled == enabled) {
            return;
        }
        account.enabled = enabled;
        addEvent(enabled ? "ACCOUNT_ENABLED" : "ACCOUNT_DISABLED", account, null, actor);
        try {
            save();
        } catch (IOException e) {
            account.enabled = !enabled;
            auditEvents.remove(auditEvents.size() - 1);
            throw e;
        }
    }

    synchronized void revokeCredential(String accountId, String credentialId, String actor) throws IOException {
        ensureLoaded();
        AccountRecord account = requireActiveAccount(accountId);
        CredentialRecord credential = account.credentials.get(credentialId);
        if (credential == null) {
            throw new IllegalArgumentException("Credential does not exist");
        }
        if (credential.revokedAt != null) {
            throw new IllegalArgumentException("Credential has already been revoked");
        }

        credential.revokedAt = System.currentTimeMillis();
        credential.revokedBy = actor;
        String verifier = credential.verifier;
        credential.verifier = null;
        addEvent("CREDENTIAL_REVOKED", account, credential, actor);
        try {
            save();
        } catch (IOException e) {
            credential.revokedAt = null;
            credential.revokedBy = null;
            credential.verifier = verifier;
            auditEvents.remove(auditEvents.size() - 1);
            throw e;
        }
    }

    synchronized void deleteAccount(String accountId, String actor) throws IOException {
        ensureLoaded();
        AccountRecord account = requireActiveAccount(accountId);
        Map<String, AccountRecord> previousAccounts = accounts;
        accounts = new LinkedHashMap<>(accounts);
        accounts.remove(accountId);
        addEvent("ACCOUNT_DELETED", account, null, actor);
        try {
            save();
        } catch (IOException e) {
            accounts = previousAccounts;
            auditEvents.remove(auditEvents.size() - 1);
            throw e;
        }
    }

    synchronized AuthenticatedAccount authenticate(String accountId, String credentialId, String secret)
            throws IOException {
        return authenticate(accountId, credentialId, secret, System.currentTimeMillis());
    }

    synchronized AuthenticatedAccount authenticate(String accountId, String credentialId, String secret, long now)
            throws IOException {
        ensureLoaded();
        AccountRecord account = accounts.get(accountId);
        if (account == null || !account.enabled || secret == null) {
            return null;
        }

        CredentialRecord credential = account.credentials.get(credentialId);
        return authenticateCredential(account, credential, secret, now);
    }

    synchronized AuthenticatedAccount authenticate(String username, String secret) throws IOException {
        ensureLoaded();
        if (username == null || secret == null) {
            return null;
        }

        long now = System.currentTimeMillis();
        for (AccountRecord account : accounts.values()) {
            if (!account.enabled) {
                continue;
            }
            if (credentialUsername(account.id).equals(username)) {
                for (CredentialRecord credential : account.credentials.values()) {
                    AuthenticatedAccount authenticated = authenticateCredential(account, credential, secret, now);
                    if (authenticated != null) {
                        return authenticated;
                    }
                }
                return null;
            }
        }
        return null;
    }

    private AuthenticatedAccount authenticateCredential(
            AccountRecord account, CredentialRecord credential, String secret, long now) throws IOException {
        if (credential == null
                || credential.revokedAt != null
                || credential.verifier == null
                || (credential.expiresAt != null && now >= credential.expiresAt)) {
            return null;
        }

        byte[] presentedVerifier = digest(secret);
        byte[] storedVerifier = HexFormat.of().parseHex(credential.verifier);
        if (!MessageDigest.isEqual(storedVerifier, presentedVerifier)) {
            return null;
        }
        if (now - credential.lastUsedAt >= LAST_USED_SAVE_INTERVAL_MILLIS) {
            long previousLastUsed = credential.lastUsedAt;
            credential.lastUsedAt = now;
            try {
                save();
            } catch (IOException e) {
                credential.lastUsedAt = previousLastUsed;
                LOGGER.log(Level.WARNING, "Unable to persist last-used time for a service-account credential", e);
            }
        }
        return new AuthenticatedAccount(account.principalName);
    }

    static String credentialUsername(String accountId) {
        return principalName(accountId);
    }

    synchronized List<AccountSummary> listAccounts() throws IOException {
        ensureLoaded();
        return accounts.values().stream()
                .map(this::toSummary)
                .sorted(Comparator.comparing(AccountSummary::id))
                .toList();
    }

    synchronized List<AuditEvent> listAuditEvents() throws IOException {
        ensureLoaded();
        if (hasExpiredAuditEvents(System.currentTimeMillis())) {
            save();
        }
        return auditEvents.stream()
                .map(AuditEventRecord::toAuditEvent)
                .sorted(Comparator.comparingLong(AuditEvent::timestamp).reversed())
                .toList();
    }

    synchronized void pruneAuditEvents() throws IOException {
        ensureLoaded();
        if (hasExpiredAuditEvents(System.currentTimeMillis())) {
            save();
        }
    }

    synchronized void pruneAuditEvents(long now) throws IOException {
        ensureLoaded();
        if (hasExpiredAuditEvents(now)) {
            save(now);
        }
    }

    private AccountRecord requireActiveAccount(String id) {
        AccountRecord account = accounts.get(id);
        if (account == null) {
            throw new IllegalArgumentException("Service account does not exist");
        }
        return account;
    }

    private void validatePrincipalAvailable(String accountId, String principalName) {
        boolean usedByAnotherAccount = accounts.values().stream()
                .anyMatch(account -> !account.id.equals(accountId) && principalName.equals(account.principalName));
        if (usedByAnotherAccount
                || User.getById(principalName, false) != null
                || existsInSecurityRealm(principalName)) {
            throw new IllegalArgumentException("The service-account principal is already in use: " + principalName);
        }
    }

    private boolean existsInSecurityRealm(String principalName) {
        if (!(Jenkins.get().getSecurityRealm() instanceof HudsonPrivateSecurityRealm)) {
            return false;
        }
        try {
            Jenkins.get().getSecurityRealm().loadUserByUsername2(principalName);
            return true;
        } catch (UsernameNotFoundException e) {
            return false;
        }
    }

    static String principalName(String id) {
        return PRINCIPAL_PREFIX + id;
    }

    private AccountSummary toSummary(AccountRecord account) {
        long now = System.currentTimeMillis();
        List<CredentialSummary> credentials = account.credentials.values().stream()
                .map(credential -> {
                    String status;
                    if (credential.revokedAt != null) {
                        status = "revoked";
                    } else if (!account.enabled) {
                        status = "account-disabled";
                    } else if (credential.expiresAt != null && now >= credential.expiresAt) {
                        status = "expired";
                    } else {
                        status = "active";
                    }
                    return new CredentialSummary(
                            credential.id,
                            credentialUsername(account.id),
                            credential.label,
                            credential.description,
                            status,
                            credential.createdAt,
                            credential.createdBy,
                            credential.lastUsedAt,
                            credential.expiresAt,
                            credential.revokedAt,
                            credential.revokedBy);
                })
                .sorted(Comparator.comparingLong(CredentialSummary::createdAt).reversed())
                .toList();
        return new AccountSummary(
                account.id,
                account.principalName,
                account.displayName,
                account.description,
                account.enabled,
                account.createdAt,
                account.createdBy,
                credentials);
    }

    private void addEvent(String type, AccountRecord account, CredentialRecord credential, String actor) {
        auditEvents.add(new AuditEventRecord(
                type,
                account.id,
                account.principalName,
                credential == null ? null : credential.id,
                credential == null ? null : credential.label,
                actor,
                System.currentTimeMillis()));
    }

    private void ensureLoaded() throws IOException {
        if (loaded) {
            return;
        }
        File path = new File(Jenkins.get().getRootDir(), STORE_FILENAME);
        XmlFile xml = new XmlFile(XSTREAM, path);
        if (xml.exists()) {
            Object stored = xml.read();
            if (!(stored instanceof StoreData data) || data.accounts == null) {
                throw new IOException("Service-account data has an unsupported or invalid format");
            }
            accounts = data.accounts;
            auditEvents = data.auditEvents == null ? new ArrayList<>() : data.auditEvents;
        }
        loaded = true;
    }

    private void save() throws IOException {
        save(System.currentTimeMillis());
    }

    private void save(long now) throws IOException {
        ensureLoaded();
        File path = new File(Jenkins.get().getRootDir(), STORE_FILENAME);
        XmlFile xml = new XmlFile(XSTREAM, path);
        List<AuditEventRecord> previousAuditEvents = auditEvents;
        auditEvents = new ArrayList<>(auditEvents);
        pruneExpiredAuditEvents(now);
        StoreData data = new StoreData();
        data.accounts = accounts;
        data.auditEvents = auditEvents;
        try {
            xml.write(data);
        } catch (IOException e) {
            auditEvents = previousAuditEvents;
            throw e;
        }
    }

    private boolean hasExpiredAuditEvents(long now) {
        int retentionDays = ServiceAccountConfiguration.get().getAuditRetentionDays();
        if (retentionDays == 0) {
            return false;
        }
        long cutoff = now - retentionDays * 86_400_000L;
        return auditEvents.stream().anyMatch(event -> event.timestamp < cutoff);
    }

    private void pruneExpiredAuditEvents(long now) {
        int retentionDays = ServiceAccountConfiguration.get().getAuditRetentionDays();
        if (retentionDays == 0) {
            return;
        }
        long cutoff = now - retentionDays * 86_400_000L;
        auditEvents.removeIf(event -> event.timestamp < cutoff);
    }

    private static void validateId(String id) {
        if (id == null || !id.matches("[a-z0-9][a-z0-9._-]{0,63}")) {
            throw new IllegalArgumentException(
                    "Service-account identifiers must use 1-64 lowercase letters, digits, dots, underscores, or hyphens");
        }
    }

    private static void validateText(String value, String field, int maximumLength, boolean optional) {
        if (value == null || value.isBlank()) {
            if (optional) {
                return;
            }
            throw new IllegalArgumentException(field + " is required");
        }
        if (value.length() > maximumLength) {
            throw new IllegalArgumentException(field + " must not exceed " + maximumLength + " characters");
        }
    }

    private static String verifier(String secret) {
        return HexFormat.of().formatHex(digest(secret));
    }

    private static byte[] digest(String secret) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update("service-account-plugin-v1\u0000".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return digest.digest(secret.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    private static class StoreData {
        private Map<String, AccountRecord> accounts = new LinkedHashMap<>();
        private List<AuditEventRecord> auditEvents = new ArrayList<>();
    }

    private static class AccountRecord {
        private String id;
        private String principalName;
        private String displayName;
        private String description;
        private boolean enabled = true;
        private long createdAt;
        private String createdBy;
        private Map<String, CredentialRecord> credentials = new LinkedHashMap<>();
    }

    private static class CredentialRecord {
        private String id;
        private String label;
        private String description;
        private String verifier;
        private long createdAt;
        private String createdBy;
        private long lastUsedAt;
        private Long expiresAt;
        private Long revokedAt;
        private String revokedBy;
    }

    private record AccountMetadata(String displayName, String description) {}

    private static class AuditEventRecord {
        private String type;
        private String accountId;
        private String principalName;
        private String credentialId;
        private String credentialLabel;
        private String actor;
        private long timestamp;

        private AuditEventRecord() {}

        private AuditEventRecord(
                String type,
                String accountId,
                String principalName,
                String credentialId,
                String credentialLabel,
                String actor,
                long timestamp) {
            this.type = type;
            this.accountId = accountId;
            this.principalName = principalName;
            this.credentialId = credentialId;
            this.credentialLabel = credentialLabel;
            this.actor = actor;
            this.timestamp = timestamp;
        }

        private AuditEvent toAuditEvent() {
            return new AuditEvent(type, accountId, principalName, credentialId, credentialLabel, actor, timestamp);
        }
    }

    record CreatedCredential(String id, String username, String secret) {}

    record AuthenticatedAccount(String principalName) {}

    record AccountSummary(
            String id,
            String principalName,
            String displayName,
            String description,
            boolean enabled,
            long createdAt,
            String createdBy,
            List<CredentialSummary> credentials) {}

    record CredentialSummary(
            String id,
            String username,
            String label,
            String description,
            String status,
            long createdAt,
            String createdBy,
            long lastUsedAt,
            Long expiresAt,
            Long revokedAt,
            String revokedBy) {}

    record AuditEvent(
            String type,
            String accountId,
            String principalName,
            String credentialId,
            String credentialLabel,
            String actor,
            long timestamp) {}
}
