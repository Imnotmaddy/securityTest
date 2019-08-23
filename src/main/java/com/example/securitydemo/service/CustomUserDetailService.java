package com.example.securitydemo.service;

import com.example.securitydemo.config.UserPrinciple;
import com.example.securitydemo.model.User;
import com.example.securitydemo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        final User user = userRepository.findByUsername(username);
        if (user == null)
            throw new UsernameNotFoundException("User was not found");
        return new UserPrinciple(user);
    }

    public void save(User user) {
        this.userRepository.save(user);
    }
}
