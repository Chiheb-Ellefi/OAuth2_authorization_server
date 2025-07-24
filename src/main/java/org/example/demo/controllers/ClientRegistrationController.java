package org.example.demo.controllers;

import org.example.demo.models.ClientRegistrationRequest;
import org.example.demo.models.ClientRegistrationResponse;
import org.example.demo.utils.ClientCredentialsGenerator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;


@RestController
public class ClientRegistrationController {
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationConsentService authorizationConsentService;

    @Value("${application.jwt.access_token.ttl}")
    private int accessTokenTtl;
    @Value("${application.jwt.refresh_token.ttl}")
    private int refreshTokenTtl;
    @Value("${application.jwt.refresh_token.reuse_token}")
    private boolean reuseRefreshToken ;
    @Value("${application.jwt.authorization_code.ttl}")
    private int authorizationCodeTtl;
    private static final Map<String, AuthorizationGrantType> GRANT_TYPE_MAP = Map.of(
            "authorization_code", AuthorizationGrantType.AUTHORIZATION_CODE,
            "refresh_token", AuthorizationGrantType.REFRESH_TOKEN,
            "client_credentials", AuthorizationGrantType.CLIENT_CREDENTIALS
    );

    // Allowed scopes
    private static final Set<String> ALLOWED_SCOPES = Set.of(
            "openid", "profile", "email", "read", "write", "admin"
    );
    private final PasswordEncoder passwordEncoder;

    public ClientRegistrationController(RegisteredClientRepository registeredClientRepository,
                                        PasswordEncoder passwordEncoder, OAuth2AuthorizationConsentService authorizationConsentService) {
        this.registeredClientRepository = registeredClientRepository;
        this.passwordEncoder = passwordEncoder;
        this.authorizationConsentService = authorizationConsentService;

    }
    @PostMapping("/client")
    public ResponseEntity<ClientRegistrationResponse> registerClient( @RequestBody ClientRegistrationRequest request) {

        String clientSecret=ClientCredentialsGenerator.generateClientSecret();
        String clientId=ClientCredentialsGenerator.generateClientId(request.getAppName());
        HashSet<AuthorizationGrantType> authorizationGrantTypes =new HashSet<>();
        request.getGrantTypes().forEach(grantType -> {
            AuthorizationGrantType mappedGrantType = GRANT_TYPE_MAP.get(grantType.toLowerCase());
            if (mappedGrantType != null) {
                authorizationGrantTypes.add(mappedGrantType);
            }
        });;
        Set<String> scopes=new HashSet<>();
        request.getScopes().forEach(scope -> {
            if (ALLOWED_SCOPES.contains(scope.toLowerCase())) {
                scopes.add(scope.toLowerCase());
            }
        });
      RegisteredClient client=  RegisteredClient.withId(UUID.randomUUID().toString())
                .clientName(request.getAppName())
                .redirectUri(request.getRedirectUri())
                .postLogoutRedirectUri(request.getPostLogoutRedirectUri())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientId(clientId)
                .clientSecret(passwordEncoder.encode(clientSecret))
                .authorizationGrantTypes(grantTypes->grantTypes.addAll(authorizationGrantTypes))
                .scopes(s->s.addAll(scopes))
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(request.isRequireAuthorizationConsent())
                        .requireProofKey(request.isRequirePkce())
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(accessTokenTtl))
                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        .refreshTokenTimeToLive(Duration.ofMinutes(refreshTokenTtl))
                        .reuseRefreshTokens(reuseRefreshToken)
                        .authorizationCodeTimeToLive(Duration.ofMinutes(authorizationCodeTtl))
                        .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                        .build())
                .build();
        registeredClientRepository.save(client);
        ClientRegistrationResponse response=ClientRegistrationResponse.builder()
                .clientId(client.getClientId())
                .clientSecret(clientSecret)
                .build();
        Set<GrantedAuthority> grantedAuthorities=scopes.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
        OAuth2AuthorizationConsent consent=OAuth2AuthorizationConsent.withId(clientId,request.getAppName())
                .authorities(authorities->authorities.addAll(grantedAuthorities))
                .build();
        authorizationConsentService.save(consent);
        return ResponseEntity.accepted().body(response);
    }
    @GetMapping("/callback")
    public  String callback(){
        return "callback";
    }
    @GetMapping("logout/success")
    public String logoutSuccess(){
        return "logout success";
    }
}
