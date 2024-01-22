package com.novi.oauthexample.config;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

public class JwtAudienceValidator implements OAuth2TokenValidator<Jwt> {
    private final String audience;

    public JwtAudienceValidator(String audience) {
        this.audience = audience;
    }


    @Override
    public OAuth2TokenValidatorResult validate(final Jwt jwt) {
        /*
        In deze methode definieren we een hele simpele methode om de JWT te valideren.
        We kijken of de JWT de opgegeven audience bevat (het "aud" attribuut van de JWT).
        Zo ja, dan is het valide. Zo nee, dan is het niet valide.
        */
        OAuth2Error error = new OAuth2Error("invalid_token", "The required audience is missing!", null);
        if (jwt.getAudience().contains(audience)) {
            return OAuth2TokenValidatorResult.success();
        }
        return OAuth2TokenValidatorResult.failure(error);
    }
}