package Security.service.TokenCreatorService;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Servicio encargado de crear tokens JWT
 */
@RequiredArgsConstructor
@Service
public class TokenServiceImpl implements TokenService {
    private Algorithm algorithm;

    @Value("${spring.security.algorithm.seceretword}")
    public String securityWord;

    public Map<String, String> createTokens(String username, String url) {
        algorithm = Algorithm.HMAC256(securityWord.getBytes());
        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", createTokenMap(username, url, 60000));
        tokens.put("refresh_token", createTokenMap(username, url, 100000));
        return tokens;
    }

    /**
     * @param expiration in milis
     * @return Map<String, Object> with the token
     */
    private String createTokenMap(String username, String url, Integer expiration) {
        return JWT.create()
                .withSubject(username)
                .withExpiresAt(new Date(System.currentTimeMillis() + expiration))
                .withIssuer(url)
                .sign(algorithm);
    }
}
