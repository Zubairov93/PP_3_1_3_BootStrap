package ru.kata.spring.boot_security.demo.services;

import org.springframework.security.core.userdetails.UserDetailsService;
import ru.kata.spring.boot_security.demo.models.Role;
import ru.kata.spring.boot_security.demo.models.User;

import java.util.List;

public interface UserService {


    void initUser ();

    User getUser(long id);

    boolean save(User user);

    void update(User user);

    void delete(long id);

    List<User> getListOfUsers();

    void save(Role role);

    void save(User user, Role role);

    boolean contains(String username);

    List<Role> getAllRoles();


}