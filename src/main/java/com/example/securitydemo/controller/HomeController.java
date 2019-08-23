package com.example.securitydemo.controller;

import com.example.securitydemo.dto.UserDto;
import com.example.securitydemo.model.Role;
import com.example.securitydemo.model.User;
import com.example.securitydemo.service.CustomUserDetailService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import javax.annotation.security.RolesAllowed;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.Collections;

@Controller
@RequiredArgsConstructor
public class HomeController {

    private final CustomUserDetailService userService;
    private final PasswordEncoder passwordEncoder;

    @GetMapping("/")
    public String home() {
        return "home";
    }

    @GetMapping("/user")
    public String toCreateUser() {
        return "registration";
    }

    @PostMapping("/user")
    public String createUser(UserDto dto) {
        User user = new User(dto.getUsername(), passwordEncoder.encode(dto.getPassword()));
        user.setRoles(Collections.singleton(Role.USER));
        userService.save(user);
        return "redirect:/userPage";
    }

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/logout-success")
    public String logoutPage() {
        return "login";
    }

    @GetMapping("/adminPage")
    @PreAuthorize("hasAnyAuthority('ADMIN')")
    public String adminPage() {
        final Collection<? extends GrantedAuthority> authorities = SecurityContextHolder.getContext().getAuthentication().getAuthorities();
        return "adminPage";
    }

    @GetMapping("/userPage")
    public String userPage() {
        return "userPage";
    }

}
