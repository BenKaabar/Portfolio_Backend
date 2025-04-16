package com.example.protfolio.Services.HomeUserDetailsService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.protfolio.Entites.Home;
import com.example.protfolio.Repository.HomeRepository;

@Service
public class HomeUserDetailsService implements UserDetailsService {

    @Autowired
    private HomeRepository homeRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Home home = homeRepository.findByGmail(username);
        if (home == null) {
            throw new UsernameNotFoundException("User not found");
        }
        return User.withUsername(home.getGmail())
                .password(home.getPassword()) 
                .authorities("ADMIN") 
                .build();
    }
}
