package enterprises.neuland.keycloak;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

public class RequireRoleDirectGrantAuthenticator extends RequireRoleAuthenticator {
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

        String responsePhrase = "Access denied because of missing role.";

        Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "missing_role", responsePhrase);
        authenticationFlowContext.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
    }

    private Response errorResponse(int status, String error, String errorDescription) {
        OAuth2ErrorRepresentation errorRep = new OAuth2ErrorRepresentation(error, errorDescription);
        return Response.status(status).entity(errorRep).type(MediaType.APPLICATION_JSON_TYPE).build();
    }
}
