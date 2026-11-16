package io.jenkins.plugins.serviceaccount;

import org.kohsuke.stapler.DataBoundConstructor;

public class ServiceAccountDefinition {
    private final String id;
    private final String displayName;
    private final String description;

    @DataBoundConstructor
    public ServiceAccountDefinition(String id, String displayName, String description) {
        this.id = id;
        this.displayName = displayName;
        this.description = description;
    }

    public String getId() {
        return id;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }
}
