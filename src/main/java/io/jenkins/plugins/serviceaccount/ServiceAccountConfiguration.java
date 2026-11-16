package io.jenkins.plugins.serviceaccount;

import hudson.Extension;
import java.io.IOException;
import java.util.List;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundSetter;

@Extension
@Symbol("serviceAccountConfiguration")
public class ServiceAccountConfiguration extends GlobalConfiguration {
    private static final long MILLIS_PER_DAY = 86_400_000L;

    private int defaultCredentialLifetimeDays = 90;
    private int maximumCredentialLifetimeDays = 365;
    private boolean allowNonExpiringCredentials;
    private transient List<ServiceAccountDefinition> serviceAccounts = List.of();

    public ServiceAccountConfiguration() {
        load();
    }

    static ServiceAccountConfiguration get() {
        return Jenkins.get().getExtensionList(ServiceAccountConfiguration.class).get(0);
    }

    public int getDefaultCredentialLifetimeDays() {
        return defaultCredentialLifetimeDays;
    }

    @DataBoundSetter
    public void setDefaultCredentialLifetimeDays(int days) {
        validateDays(days);
        defaultCredentialLifetimeDays = days;
        saveConfiguration();
    }

    public int getMaximumCredentialLifetimeDays() {
        return maximumCredentialLifetimeDays;
    }

    @DataBoundSetter
    public void setMaximumCredentialLifetimeDays(int days) {
        validateDays(days);
        maximumCredentialLifetimeDays = days;
        saveConfiguration();
    }

    public boolean isAllowNonExpiringCredentials() {
        return allowNonExpiringCredentials;
    }

    @DataBoundSetter
    public void setAllowNonExpiringCredentials(boolean allow) {
        allowNonExpiringCredentials = allow;
        saveConfiguration();
    }

    public List<ServiceAccountDefinition> getServiceAccounts() {
        return serviceAccounts;
    }

    @DataBoundSetter
    public void setServiceAccounts(List<ServiceAccountDefinition> serviceAccounts) {
        if (serviceAccounts == null) {
            return;
        }
        try {
            ServiceAccountStore.get().upsertConfiguredAccounts(serviceAccounts);
            this.serviceAccounts = List.copyOf(serviceAccounts);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to persist JCasC service-account definitions", e);
        }
    }

    Long getExpirationTime(Integer requestedLifetimeDays, long now) {
        int lifetimeDays = requestedLifetimeDays == null ? defaultCredentialLifetimeDays : requestedLifetimeDays;
        if (lifetimeDays == 0) {
            if (!allowNonExpiringCredentials) {
                throw new IllegalArgumentException("Non-expiring credentials are disabled by policy");
            }
            return null;
        }
        if (lifetimeDays < 1 || lifetimeDays > maximumCredentialLifetimeDays) {
            throw new IllegalArgumentException("Credential lifetime must be between 1 and the configured maximum");
        }
        if (defaultCredentialLifetimeDays > maximumCredentialLifetimeDays) {
            throw new IllegalStateException("The configured default credential lifetime exceeds the maximum");
        }
        return Math.addExact(now, Math.multiplyExact((long) lifetimeDays, MILLIS_PER_DAY));
    }

    private void saveConfiguration() {
        save();
    }

    private static void validateDays(int days) {
        if (days < 1 || days > 3650) {
            throw new IllegalArgumentException("Credential lifetime must be between 1 and 3650 days");
        }
    }
}
