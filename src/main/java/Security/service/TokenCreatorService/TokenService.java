package Security.service.TokenCreatorService;

import java.util.Map;

public interface TokenService {
    Map<String, String> createTokens(String username, String url);
}