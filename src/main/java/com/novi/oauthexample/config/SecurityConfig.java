package com.novi.oauthexample.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;



@Configuration
public class SecurityConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuer;
    @Value("${spring.security.oauth2.resourceserver.jwt.audiences}")
    private String audience;

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        return http
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                                .decoder(jwtDecoder())
                        ))
                .securityMatcher("/**")
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/","/authenticate").permitAll()
                        .requestMatchers("/api/public").permitAll()
                        .requestMatchers("/api/private").authenticated()
                        .requestMatchers("/api/private-scoped").hasAuthority("read:messages")
                        .requestMatchers("/resource/{name}").access(new WebExpressionAuthorizationManager("#name == authentication.name"))
                        .anyRequest().authenticated()
                )
                .sessionManagement(session-> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .build();

    }


    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        /*
        In deze methode overschrijven we de standaard JwtAuthenticationConverter met een nieuwe jwtAuthenticationConverter.
        Dit is nodig om aan te geven dat we het "permissions" attribuut in de JWT willen gebruiken om de authorities uit te extraheren.
        Daarnaast kunnen we ook meteen de prefix op een lege string zetten, zodat we niet "SCOPE_" voor onze authorities hoeven zetten.
        Uiteindelijk kunnen we hiermee in de HttpSecurity aangeven dat alleen gebruikers met een bepaalde "permission"
        een endpoint mogen aanspreken, zoals:

                .requestMatchers("/api/private-scoped").hasAuthority("read:messages")

         Je ziet dat hier de "hasAuthority" methode gebruikt wordt, terwijl we het over "permissions" hebben.
         Dat kan, omdat we in deze methode instellen dat "permissions" als "authorities" gelezen worden.
         */
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthoritiesClaimName("permissions");
        grantedAuthoritiesConverter.setAuthorityPrefix("");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);

        return jwtAuthenticationConverter;
    }



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