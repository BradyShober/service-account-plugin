package io.jenkins.plugins.serviceaccount;

import hudson.Extension;
import hudson.security.SecurityRealm;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import jenkins.model.Jenkins;
import jenkins.security.BasicHeaderAuthenticator;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;

@Extension
public class ServiceAccountAuthenticator extends BasicHeaderAuthenticator {
    @Override
    public Authentication authenticate2(
            HttpServletRequest request, HttpServletResponse response, String username, String password)
            throws IOException, ServletException {
        if (username == null
                || (!username.startsWith(ServiceAccountStore.PRINCIPAL_PREFIX)
                        && !username.startsWith(ServiceAccountStore.CREDENTIAL_USERNAME_PREFIX))) {
            return null;
        }

        ServiceAccountStore.AuthenticatedAccount account =
                Jenkins.get().getExtensionList(ServiceAccountStore.class).get(0).authenticate(username, password);
        if (account == null) {
            return null;
        }

        User principal = new User(
                account.principalName(), "", true, true, true, true, List.of(SecurityRealm.AUTHENTICATED_AUTHORITY2));
        return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    }
}
