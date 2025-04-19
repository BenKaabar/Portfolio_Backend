package com.example.protfolio.Security;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import com.example.protfolio.Services.HomeUserDetailsService.HomeUserDetailsService;
import com.nimbusds.jose.jwk.source.ImmutableSecret;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Configuration
@Slf4j
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.setAllowedOrigins(List.of(
                "http://localhost:4200",
                "https://portfolio-benkaabar.netlify.app",
                "https://680402dbe0146e0008c98986--portfolio-benkaabar.netlify.app"));
        config.setAllowedHeaders(Arrays.asList(
                HttpHeaders.ORIGIN,
                HttpHeaders.CONTENT_TYPE,
                HttpHeaders.ACCEPT,
                HttpHeaders.AUTHORIZATION));
        config.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "DELETE", "PATCH"));
        config.setExposedHeaders(List.of("x-auth-token"));
        source.registerCorsConfiguration("/**", config);
        log.info("Allowed origins: {}", config.getAllowedOrigins());
        return new CorsFilter(source) {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                    FilterChain filterChain)
                    throws ServletException, IOException {
                String origin = request.getHeader("Origin");
                log.info("Incoming request from Origin: {}", origin);
                log.info("Method: {}, Origin: {}, URL: {}",
                        request.getMethod(),
                        request.getHeader("Origin"),
                        request.getRequestURL());

                super.doFilterInternal(request, response, filterChain);
            }
        };
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new HomeUserDetailsService();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .cors(Customizer.withDefaults())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(ar -> ar
                        .requestMatchers("/auth/login").permitAll()
                        .requestMatchers("/Contact/CreateContact/**").permitAll()
                        .requestMatchers("/Home/AllHome/**").permitAll()
                        .requestMatchers("/ResumeEducation/AllResumeEducation/**").permitAll()
                        .requestMatchers("/ResumeExperience/AllResumeExperience/**").permitAll()
                        .requestMatchers("/ResumeSkills/AllResumeSkills/**").permitAll()
                        .requestMatchers("/Service/AllServices/**").permitAll()
                        .requestMatchers("/Work/AllWork/**").permitAll()
                        .requestMatchers("/Home/UpdatedHome/**").permitAll())
                .authorizeHttpRequests(ar -> ar.anyRequest().authenticated())
                .oauth2ResourceServer(oa -> oa.jwt(Customizer.withDefaults()))
                .build();
    }

    @Bean
    JwtEncoder jwtEncoder() {
        String secretKey = "bgjdfghdf6sh5sd4h5dsh65stdh65stfh654SF6hsfsh15+sf1th56gfhs4785lg";
        return new NimbusJwtEncoder(new ImmutableSecret<>(secretKey.getBytes()));
    }

    @Bean
    JwtDecoder jwtDecoder() {
        String secretKey = "bgjdfghdf6sh5sd4h5dsh65stdh65stfh654SF6hsfsh15+sf1th56gfhs4785lg";
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "RSA");
        return NimbusJwtDecoder.withSecretKey(secretKeySpec).macAlgorithm(MacAlgorithm.HS512).build();
    }

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService) {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        return new ProviderManager(daoAuthenticationProvider);
    }

}