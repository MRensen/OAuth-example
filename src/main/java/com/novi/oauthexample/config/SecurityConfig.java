package com.novi.oauthexample.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;

import static org.springframework.security.config.Customizer.withDefaults;


@Configuration
public class SecurityConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuer;
    @Value("${spring.security.oauth2.resourceserver.jwt.audiences}")
    private String audience;
    @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-id}")
    private String clientId;

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
       return http
               .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
               .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/").permitAll()
                        .requestMatchers("/resource/{name}").access(new WebExpressionAuthorizationManager("#name == authentication.name"))
                        .anyRequest().authenticated()
                )
               .sessionManagement(session-> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
               .build();

    }


    @Bean
    public JwtDecoder jwtDecoder(){
        /*
        In deze methode valideren we de JWT op echtheid.
        Daarvoor kijken we of de audience en de issuer uit de JWT overeenkomen met de audience en issuer uit de application.properties.
        In de issuer validator wordt ook meteen gekeken of de JWT nog niet verlopen is, dus of de timestamp valide is.
        */

        OAuth2TokenValidator<Jwt> audienceValidator = new JwtAudienceValidator(audience);
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuer);
        OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(withIssuer, audienceValidator);

        NimbusJwtDecoder jwtDecoder = JwtDecoders.fromOidcIssuerLocation(issuer);
        jwtDecoder.setJwtValidator(validator);

        return jwtDecoder;
    }

}
