package io.jenkins.plugins.serviceaccount;

import hudson.Extension;
import hudson.security.csrf.CrumbExclusion;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;

@Extension
public class ServiceAccountCrumbExclusion extends CrumbExclusion {
    private static final String SERVICE_ACCOUNT_API_PATH = "/manage/service-accounts/api/";
    private static final String ACCOUNT_ID_PATTERN = "[a-z0-9][a-z0-9._-]{0,63}";
    private static final String CREDENTIAL_ID_PATTERN = "[a-zA-Z0-9-]+";

    @Override
    public boolean process(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!"POST".equals(request.getMethod())
                || !isServiceAccountMutation(request)
                || !hasValidServiceAccountCredentials(request)) {
            return false;
        }
        chain.doFilter(request, response);
        return true;
    }

    private static boolean hasValidServiceAccountCredentials(HttpServletRequest request) throws ServletException {
        String authorization = request.getHeader("Authorization");
        if (authorization == null || !authorization.regionMatches(true, 0, "Basic ", 0, 6)) {
            return false;
        }
        String usernameAndPassword;
        try {
            usernameAndPassword =
                    new String(Base64.getDecoder().decode(authorization.substring(6)), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return false;
        }
        int separator = usernameAndPassword.indexOf(':');
        if (separator <= 0) {
            return false;
        }
        String username = usernameAndPassword.substring(0, separator);
        String secret = usernameAndPassword.substring(separator + 1);
        if (!username.startsWith(ServiceAccountStore.PRINCIPAL_PREFIX)
                && !username.startsWith(ServiceAccountStore.CREDENTIAL_USERNAME_PREFIX)) {
            return false;
        }
        try {
            return ServiceAccountStore.get().authenticate(username, secret) != null;
        } catch (IOException e) {
            throw new ServletException("Unable to validate service-account credentials for CSRF exemption", e);
        }
    }

    private static boolean isServiceAccountMutation(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        String requestUri = request.getRequestURI();
        if (!requestUri.startsWith(contextPath)) {
            return false;
        }
        String path = requestUri.substring(contextPath.length());
        if (!path.startsWith(SERVICE_ACCOUNT_API_PATH)) {
            return false;
        }
        String[] segments = path.substring(SERVICE_ACCOUNT_API_PATH.length()).split("/", -1);
        if (segments.length == 2) {
            return "accounts".equals(segments[0]) && "create".equals(segments[1]);
        }
        if (segments.length == 3 && "accounts".equals(segments[0]) && segments[1].matches(ACCOUNT_ID_PATTERN)) {
            return Set.of("update", "enable", "disable", "delete").contains(segments[2]);
        }
        if (segments.length == 4 && "accounts".equals(segments[0]) && segments[1].matches(ACCOUNT_ID_PATTERN)) {
            return "credentials".equals(segments[2]) && "create".equals(segments[3]);
        }
        return segments.length == 5
                && "accounts".equals(segments[0])
                && segments[1].matches(ACCOUNT_ID_PATTERN)
                && "credentials".equals(segments[2])
                && segments[3].matches(CREDENTIAL_ID_PATTERN)
                && "revoke".equals(segments[4]);
    }
}
