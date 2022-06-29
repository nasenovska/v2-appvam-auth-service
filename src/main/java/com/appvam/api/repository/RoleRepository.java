package com.appvam.api.repository;

import com.appvam.api.models.Role;
import com.appvam.api.models.Roles;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(Roles name);

    Optional<Role> findByName(String name);
}
