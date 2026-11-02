package com.villanidarius.medicascheduler.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


public interface UsersRepository extends JpaRepository<User, Integer> {
    //these will be used later on in the project
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    Optional<User> findByPhoneNumber(String phoneNumber);
    Optional<User> findByEmailOrUsernameOrPhone(String email, String username, String phone);
}
