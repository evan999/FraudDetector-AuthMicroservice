package com.finance.Auth.services;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class CustomUserDetails {
    CustomUserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
