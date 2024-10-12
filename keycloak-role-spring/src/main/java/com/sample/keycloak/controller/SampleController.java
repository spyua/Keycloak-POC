package com.sample.keycloak.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;
import java.util.stream.Collectors;

@RestController
public class SampleController {

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<String> admin(Authentication authentication) {
        return ResponseEntity.ok("This is Admin");
    }

    @GetMapping("/viewer")
    @PreAuthorize("hasRole('ROLE_VIEWER')")
    public ResponseEntity<String> viewer(Authentication authentication) {
        return ResponseEntity.ok("You can view this system");
    }


    @GetMapping("/editor")
    @PreAuthorize("hasRole('ROLE_EDITOR')")
    public ResponseEntity<String> editor(Authentication authentication) {
        return ResponseEntity.ok("You can editor");
    }


    @GetMapping("/")
    public ResponseEntity<String> pub(Authentication authentication) {
        return ResponseEntity.ok("This is public page");
    }

    @GetMapping("/role")
    public List<String> role(Authentication authentication) {
         return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
    }


}
