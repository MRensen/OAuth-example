package com.novi.oauthexample.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class Controller {
    @GetMapping("/home")
    public String getMappingHome(){
        return "Hallo wereld";
    }

    @GetMapping("/header")
     /*
      Dit endpoint vraagt om een "input" header en geeft een "ouput" header terug.
       */
    public ResponseEntity<String> getHeader(@RequestHeader("input") String input){
        return ResponseEntity.status(HttpStatus.OK).header("output", input).build();
    }

    @GetMapping("/user")
    /*
    Deze methode geeft gebruikersinformatie uit de JWT terug.
    Client Credentials Flow heeft geen gebruiker, dus er is ook geen gebruikers informatie.
    Wat wordt er dan wel terug gegeven?
     */
    public Map<String, Object> getUser(JwtAuthenticationToken principal){
        Collection<String> authorities = principal.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        Map<String,Object> info = new HashMap<>();
        info.put("name", principal.getName());
        info.put("authorities", authorities);
        info.put("tokenAttributes", principal.getTokenAttributes());

        return info;
    }

    @GetMapping("/resource/{name}")
    /*
    Dit endpoint mag je alleen aanspreken als je de juiste naam mee geeft.
    Zie de "SecurityConfig" klasse.
     */
    public String getName(@PathVariable String name){
        return name;
    }
}
