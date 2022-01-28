package com.communication.securedWebsockets.repositories;

import com.communication.securedWebsockets.model.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(String username);
}
