package enterprises.neuland.keycloak;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.RoleUtils;

import javax.ws.rs.core.Response;
import java.util.Set;

public class RequireRoleAuthenticator implements Authenticator {
    public static final String REQUIRED_ROLE = "user";
    @Override
    public void authenticate(AuthenticationFlowContext authenticationFlowContext) {
        ClientModel client = authenticationFlowContext.getAuthenticationSession().getClient();
        UserModel user = authenticationFlowContext.getUser();

        RoleModel requiredRole = client.getRole(REQUIRED_ROLE);
        if (requiredRole == null) {
            authenticationFlowContext.success();
            return;
        }

        if (isUserInRole(user, requiredRole)) {
            authenticationFlowContext.success();
            return;
        }

        authenticationFlowContext.getEvent().user(user);
        authenticationFlowContext.getEvent().error(Errors.NOT_ALLOWED);

        LoginFormsProvider loginFormsProvider = authenticationFlowContext.form();

        Response errorForm = loginFormsProvider
                .setError("Access Denied: " + client.getClientId())
                .createErrorPage(Response.Status.FORBIDDEN);

        authenticationFlowContext.forceChallenge(errorForm);

    }

    protected boolean isUserInRole(UserModel user, RoleModel role) {
        if (role == null) {
            return true;
        }

        if (RoleUtils.hasRole(user.getRoleMappingsStream(), role)) {
            return true;
        }

        Set<RoleModel> nestedAssignedRoles = RoleUtils.getDeepUserRoleMappings(user);
        return RoleUtils.hasRole(nestedAssignedRoles, role);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(org.keycloak.models.KeycloakSession keycloakSession, org.keycloak.models.RealmModel realmModel, org.keycloak.models.UserModel userModel) {
        return true;
    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {
        // NOOP
    }

    @Override
    public void setRequiredActions(org.keycloak.models.KeycloakSession keycloakSession, org.keycloak.models.RealmModel realmModel, org.keycloak.models.UserModel userModel) {
        // NOOP
    }

    @Override
    public void close() {
        // NOOP
    }
}
