package com.finance.Auth.services;

import org.bouncycastle.crypto.generators.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {

        User user = userRepository.findByUsername(username)
                .orElseThrow(() ->
                    new UsernameNotFoundException("Username not found")
                );
        /*
        List<GrantedAuthority> grantedAuthorities = admin.getRoles()
                .stream().map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        */
        //return new User(username, password, true, true, true,
        //      true, grantedAuthorities);

        //Optional<User> user = userRepository.findByUserName(username);
        //return new CustomUserDetails(user);
    }
}
