package org.example.demo.repositories;

import org.example.demo.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;


@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    void deleteUserByUsername(String username);

    Optional<User> findByUsername(String username);
}