package com.finance.Auth.Model;


import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class User implements UserDetails {
    private Long userId;
    private String name;
    private String username;
    private String email;
    private String password;

    private Collection<? extends GrantedAuthority> authorities;

    public User(Long userId, String username, String name, String email, String password, Collection<? extends GrantedAuthority> authorities) {
        this.userId = userId;
        this.username = username;
        this.email = email;
        this.password = password;
        this.authorities = authorities;
    }

    public static User createUser(User user) {
        List<GrantedAuthority> authorities = user.getRoles().stream().map(role ->
                new SimpleGrantedAuthority(role.getName().name())
        ).collect(Collectors.toList());

        return new User(
                user.getId(),
                user.getName(),
                user.getUsername(),
                user.getEmail(),
                user.getPassword(),
                authorities
        );

        
    }
}
