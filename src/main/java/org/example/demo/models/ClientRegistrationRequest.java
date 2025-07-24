package org.example.demo.models;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.validator.constraints.URL;

import java.io.Serializable;
import java.util.List;

@Getter
@Setter
@Builder
public class ClientRegistrationRequest implements Serializable {
    @NotBlank
    private String appName;
    @URL(message = "Redirect URI must be a valid URL")
    private String redirectUri;
    @URL(message = "Post logout redirect URI must be a valid URL")
    private String postLogoutRedirectUri;
    @NotEmpty
    private List<String> scopes;
    @NotEmpty
    private List<String> grantTypes;
    @Builder.Default
    private boolean requirePkce = false;
    @Builder.Default
    private boolean requireAuthorizationConsent = true;
}
