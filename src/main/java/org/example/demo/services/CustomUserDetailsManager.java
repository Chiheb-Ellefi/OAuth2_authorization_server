package org.example.demo.services;

import org.example.demo.entities.User;
import org.example.demo.repositories.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

import java.util.function.Supplier;

@Service
public class CustomUserDetailsManager implements UserDetailsManager {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    CustomUserDetailsManager(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }
    @Override
    public void createUser(UserDetails user) {
        User newUser=(User) user;
        userRepository.save(User.builder()
                .username(user.getUsername())
                .password(passwordEncoder.encode(user.getPassword()))
                .role(newUser.getRole())
                .build());
    }

    @Override
    public void updateUser(UserDetails user) {
        Supplier<UsernameNotFoundException> notFoundExceptionSupplier = () -> new UsernameNotFoundException(user.getUsername());
        if(!userExists(user.getUsername())){
            throw notFoundExceptionSupplier.get();
        }
        userRepository.save((User)user);
    }

    @Override
    public void deleteUser(String username) {
        userRepository.deleteUserByUsername(username);
    }

    @Override
    public void changePassword(String username, String newPassword) {
        Supplier<UsernameNotFoundException> exceptionSupplier = () -> new UsernameNotFoundException(username + " not found");
        User oldUser= userRepository.findByUsername(username).orElseThrow(exceptionSupplier);
        oldUser.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(oldUser);
    }

    @Override
    public boolean userExists(String username) {
        return userRepository.findByUsername(username).isPresent();
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Supplier<UsernameNotFoundException> exceptionSupplier = () -> new UsernameNotFoundException(username + " not found");
        return userRepository.findByUsername(username).orElseThrow(exceptionSupplier);
    }
}
