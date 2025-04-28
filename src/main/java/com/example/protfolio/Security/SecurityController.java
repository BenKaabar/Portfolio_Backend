package com.example.protfolio.Security;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.protfolio.Entites.Home;
import com.example.protfolio.Services.Home.HomeService;

import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping(path = "/auth")
@Slf4j
public class SecurityController {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtEncoder jwtEncoder;
    @Autowired
    private HomeService homeService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping(path = "/profile")
    public Authentication authentication(Authentication authentication) {
        return authentication;
    }

    @PostMapping(path = "/login")
    public Map<String, String> login(@RequestParam String username, @RequestParam String password) {
        Home home = homeService.AllHome().get(0);
        log.info(username + " " + password);
        if (home.getGmail().equals(username) && passwordEncoder.matches(password, home.getPassword())) {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));
            Instant instant = Instant.now();
            String scope = authentication.getAuthorities().stream()
                    .map(a -> a.getAuthority())
                    .collect(Collectors.joining(" "));

            JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                    .issuedAt(instant)
                    .expiresAt(instant.plus(10, ChronoUnit.MINUTES))
                    .subject(username)
                    .claim("scope", scope)
                    .build();
            JwtEncoderParameters jwtEncoderParameters = JwtEncoderParameters.from(
                    JwsHeader.with(MacAlgorithm.HS512).build(),
                    jwtClaimsSet);
            String jwt = jwtEncoder.encode(jwtEncoderParameters).getTokenValue();
            return Map.of("access-token", jwt);
        } else {
            return Map.of("access-token", "no key");
        }
    }
}