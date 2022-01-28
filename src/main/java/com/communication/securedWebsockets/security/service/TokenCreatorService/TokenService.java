package com.communication.securedWebsockets.security.service.TokenCreatorService;

import java.util.Map;

public interface TokenService {
    Map<String, String> createTokens(String username, String url);
}