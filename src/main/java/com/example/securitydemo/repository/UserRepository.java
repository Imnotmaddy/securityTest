package com.example.securitydemo.repository;

import com.example.securitydemo.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Integer> {
    User findByUsername(String name);
}
