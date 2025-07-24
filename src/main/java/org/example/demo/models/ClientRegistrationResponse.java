package org.example.demo.models;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
@Builder
public class ClientRegistrationResponse {
  private String clientId;
  private String clientSecret;
}
