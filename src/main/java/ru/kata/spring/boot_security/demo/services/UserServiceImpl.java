package ru.kata.spring.boot_security.demo.services;

import org.hibernate.Hibernate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import ru.kata.spring.boot_security.demo.repositories.RoleRepository;
import ru.kata.spring.boot_security.demo.repositories.UserRepository;
import ru.kata.spring.boot_security.demo.models.Role;
import ru.kata.spring.boot_security.demo.models.User;

import java.util.*;

@Service
public class UserServiceImpl implements UserService, UserDetailsService {


    private final UserRepository userRepository;

    private final RoleRepository roleRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;


    @Autowired
    public UserServiceImpl(BCryptPasswordEncoder bCryptPasswordEncoder, UserRepository userRepository, RoleRepository roleRepository) {

        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    @Transactional(readOnly = true)
    @Override
    public User getUser(long id) {
        return userRepository.findById(id).get();
    }

    @Transactional
    @Override
    public boolean save(User user) {
        if (!userRepository.findByUsername(user.getUsername()).isEmpty()) {
            return false;
        }
        Role role = roleRepository.findByName("ROLE_USER").get();
        user.setRoles(Collections.singleton(role));
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return true;
    }

    @Transactional
    @Override
    public void update(User user) {
        user.setRoles(userRepository.findById(user.getId()).get().getRoles());
        userRepository.save(user);
        String pass = user.getPassword();
        if (pass.isEmpty()){
            user.setPassword(userRepository.findById(user.getId()).get().getPassword());
        }
        else{
            user.setPassword(bCryptPasswordEncoder.encode(pass));
        }
        userRepository.save(user);
    }

    @Transactional()
    @Override
    public void delete(long id) {
        userRepository.deleteById(id);
    }

    @Transactional(readOnly = true)
    @Override
    public List<User> getListOfUsers() {
        return userRepository.findAll();
    }

    @Transactional
    @Override
    public void save(Role role) {
        if (roleRepository.findByName(role.getName()).isEmpty()) {
            roleRepository.save(role);
        } else {
            role = roleRepository.findByName(role.getName()).get();
        }
    }

    @Transactional
    @Override
    public void save(User user, Role role) {
        Role role1 = roleRepository.findByName(role.getName()).get();
        user.setRoles(Collections.singleton(role1));
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        userRepository.save(user);
    }

    @Override
    public boolean contains(String username) {
        return !userRepository.findByUsername(username).isEmpty();
    }

    @Override
    public List<Role> getAllRoles() {
        return roleRepository.findAll();
    }


    @Transactional(propagation = Propagation.REQUIRED, readOnly = true, noRollbackFor = Exception.class)
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> userOptional = userRepository.findByUsername(username);

        if (userOptional.isEmpty()) {
            throw new UsernameNotFoundException(username);
        }

        User user = userOptional.get();
        Hibernate.initialize(user.getRoles()); // Инициализация ролей

        Set<Role> roles = user.getRoles();

        if (roles == null) {
            throw new UsernameNotFoundException("User has no roles: " + username);
        }

        for (Role role : roles) {
            System.out.println(role.getName());
        }

        return user;
    }

    @Transactional
    public void initUser() {

        Role adminRole = new Role("ROLE_ADMIN");
        Role userRole = new Role("ROLE_USER");
        save(adminRole);
        save(userRole);

        // Создайте пользователя с ролями
        User user = new User();
        user.setUsername("admin");
        user.setPassword(bCryptPasswordEncoder.encode("admin"));
        user.setRoles(Set.of(adminRole));
        User user1 = new User();
        user1.setUsername("user");
        user1.setPassword(bCryptPasswordEncoder.encode("user"));
        user1.setRoles(Set.of(userRole));
        Set<Role> roles = new HashSet<>();
        roles.add(adminRole);
        roles.add(userRole);
        user.setRoles(roles);
        userRepository.save(user);
        userRepository.save(user1);
    }

}
