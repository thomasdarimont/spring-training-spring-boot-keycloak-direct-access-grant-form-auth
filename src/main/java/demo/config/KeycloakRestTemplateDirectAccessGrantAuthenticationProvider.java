package demo.config;

import lombok.RequiredArgsConstructor;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.rotation.AdapterTokenVerifier;
import org.keycloak.adapters.springsecurity.facade.SimpleHttpFacade;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
class KeycloakRestTemplateDirectAccessGrantAuthenticationProvider implements AuthenticationProvider {


    private final AdapterDeploymentContext adapterDeploymentContext;
    private final HttpServletRequest currentHttpRequest;
    private final HttpServletResponse currentHttpResponse;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        try {

            KeycloakDeployment deployment = adapterDeploymentContext.resolveDeployment(new SimpleHttpFacade(currentHttpRequest, currentHttpResponse));

            RestTemplate rt = new RestTemplate();

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> map = new LinkedMultiValueMap<String, String>();
            map.add("username", authentication.getName());
            map.add("password", (String) authentication.getCredentials());
            map.add("grant_type", "password");
            map.add("client_id", deployment.getResourceName());
            map.add("client_secret", (String) deployment.getResourceCredentials().get("secret"));

            ResponseEntity<Map> response = rt.exchange(deployment.getTokenUrl(), HttpMethod.POST, new HttpEntity<>(map, headers), Map.class);

            String accessTokenString = (String) response.getBody().get("access_token");

            AccessToken accessToken = AdapterTokenVerifier.verifyToken(accessTokenString, deployment);

            System.out.println("login successful");
            List<SimpleGrantedAuthority> realmRoles = accessToken.getRealmAccess().getRoles().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

            return new UsernamePasswordAuthenticationToken(authentication.getName(), authentication.getCredentials(), realmRoles);

        } catch (VerificationException vex) {
            throw new AuthenticationServiceException("keycloak direct access grant auth failed: bad token", vex);
        } catch (HttpClientErrorException.Unauthorized hceex) {
            throw new AuthenticationServiceException("keycloak direct access grant auth failed: bad credentials", hceex);
        }

    }

    @Override
    public boolean supports(Class<?> type) {
        return UsernamePasswordAuthenticationToken.class.equals(type);
    }
}

