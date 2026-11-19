package io.jenkins.plugins.serviceaccount;

import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.security.Permission;
import hudson.security.PermissionGroup;
import hudson.security.PermissionScope;
import jenkins.model.Jenkins;

public final class ServiceAccountPermissions {
    private static final PermissionGroup PERMISSIONS =
            new PermissionGroup(ServiceAccountPermissions.class, Messages._ServiceAccountPermissions_Title());

    public static final Permission VIEW = new Permission(
            PERMISSIONS,
            "ViewServiceAccounts",
            Messages._ServiceAccountPermissions_ViewServiceAccounts(),
            Jenkins.ADMINISTER,
            PermissionScope.JENKINS);
    public static final Permission CREATE = new Permission(
            PERMISSIONS,
            "CreateServiceAccounts",
            Messages._ServiceAccountPermissions_CreateServiceAccounts(),
            Jenkins.ADMINISTER,
            PermissionScope.JENKINS);
    public static final Permission MANAGE = new Permission(
            PERMISSIONS,
            "ManageServiceAccounts",
            Messages._ServiceAccountPermissions_ManageServiceAccounts(),
            Jenkins.ADMINISTER,
            PermissionScope.JENKINS);
    public static final Permission DELETE = new Permission(
            PERMISSIONS,
            "DeleteServiceAccounts",
            Messages._ServiceAccountPermissions_DeleteServiceAccounts(),
            Jenkins.ADMINISTER,
            PermissionScope.JENKINS);
    public static final Permission MANAGE_CREDENTIALS = new Permission(
            PERMISSIONS,
            "ManageServiceAccountCredentials",
            Messages._ServiceAccountPermissions_ManageServiceAccountCredentials(),
            Jenkins.ADMINISTER,
            PermissionScope.JENKINS);

    @Initializer(after = InitMilestone.PLUGINS_STARTED)
    public static void registerPermissions() {
        VIEW.getId();
        CREATE.getId();
        MANAGE.getId();
        DELETE.getId();
        MANAGE_CREDENTIALS.getId();
    }

    private ServiceAccountPermissions() {}
}
