CREATE TABLE oauth2_registered_client (
                                          id VARCHAR(100) PRIMARY KEY,
                                          client_id VARCHAR(100) NOT NULL,
                                          client_id_issued_at TIMESTAMP NOT NULL,
                                          client_secret VARCHAR(200),
                                          client_secret_expires_at TIMESTAMP,
                                          client_name VARCHAR(200) NOT NULL,
                                          client_authentication_methods VARCHAR(1000) NOT NULL,
                                          authorization_grant_types VARCHAR(1000) NOT NULL,
                                          redirect_uris VARCHAR(1000),
                                          scopes VARCHAR(1000) NOT NULL,
                                          client_settings VARCHAR(2000) NOT NULL,
                                          token_settings VARCHAR(2000) NOT NULL
);
CREATE TABLE oauth2_authorization (
                                      id VARCHAR(100) PRIMARY KEY,
                                      registered_client_id VARCHAR(100) NOT NULL,
                                      principal_name VARCHAR(200) NOT NULL,
                                      authorization_grant_type VARCHAR(100) NOT NULL,
                                      attributes BYTEA,
                                      state VARCHAR(500),
                                      authorization_code_value BYTEA,
                                      authorization_code_issued_at TIMESTAMP,
                                      authorization_code_expires_at TIMESTAMP,
                                      authorization_code_metadata BYTEA,
                                      access_token_value BYTEA,
                                      access_token_issued_at TIMESTAMP,
                                      access_token_expires_at TIMESTAMP,
                                      access_token_metadata BYTEA,
                                      access_token_type VARCHAR(100),
                                      access_token_scopes VARCHAR(1000),
                                      refresh_token_value BYTEA,
                                      refresh_token_issued_at TIMESTAMP,
                                      refresh_token_expires_at TIMESTAMP,
                                      refresh_token_metadata BYTEA,
                                      oidc_id_token_value BYTEA,
                                      oidc_id_token_issued_at TIMESTAMP,
                                      oidc_id_token_expires_at TIMESTAMP,
                                      oidc_id_token_metadata BYTEA
);
CREATE TABLE oauth2_authorization_consent (
                                              registered_client_id VARCHAR(100) NOT NULL,
                                              principal_name VARCHAR(200) NOT NULL,
                                              authorities VARCHAR(1000) NOT NULL,
                                              PRIMARY KEY (registered_client_id, principal_name)
);
