package demo.config;

import lombok.RequiredArgsConstructor;
import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.rotation.AdapterTokenVerifier;
import org.keycloak.adapters.springsecurity.facade.SimpleHttpFacade;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.NotAuthorizedException;
import java.util.List;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
class KeycloakAdminClientDirectAccessGrantAuthenticationProvider implements AuthenticationProvider {


    private final AdapterDeploymentContext adapterDeploymentContext;
    private final HttpServletRequest currentHttpRequest;
    private final HttpServletResponse currentHttpResponse;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        try {

            KeycloakDeployment deployment = adapterDeploymentContext.resolveDeployment(new SimpleHttpFacade(currentHttpRequest, currentHttpResponse));

            Keycloak keycloak = KeycloakBuilder.builder() //
                    .serverUrl(deployment.getAuthServerBaseUrl()) //
                    .realm(deployment.getRealm()) //
                    .grantType(OAuth2Constants.PASSWORD) //
                    .clientId(deployment.getResourceName()) //
                    .clientSecret((String) deployment.getResourceCredentials().get("secret")) //
                    .username(authentication.getName()) //
                    .password((String) authentication.getCredentials()) //
                    .build();

            AccessTokenResponse accessTokenResponse = keycloak.tokenManager().getAccessToken();

            String accessTokenString = accessTokenResponse.getToken();

            AccessToken accessToken = AdapterTokenVerifier.verifyToken(accessTokenString, deployment);

            System.out.println("login successful");
            List<SimpleGrantedAuthority> realmRoles = accessToken.getRealmAccess().getRoles().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

            return new UsernamePasswordAuthenticationToken(authentication.getName(), authentication.getCredentials(), realmRoles);

        } catch (VerificationException vex) {
            throw new AuthenticationServiceException("keycloak direct access grant auth failed: bad token", vex);
        } catch (NotAuthorizedException naex) {
            throw new AuthenticationServiceException("keycloak direct access grant auth failed: bad credentials", naex);
        }

    }

    @Override
    public boolean supports(Class<?> type) {
        return UsernamePasswordAuthenticationToken.class.equals(type);
    }
}

