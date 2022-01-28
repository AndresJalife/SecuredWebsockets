package Security.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import static org.springframework.http.HttpStatus.FORBIDDEN;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    private static final String APPLICATION_JSON_VALUE = "application/json";
    private final String secretWord;

    public CustomAuthorizationFilter(String secretWord){
        this.secretWord = secretWord;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException {
        String servletPath = request.getServletPath();
        if (servletPath.contains("/ws/")){
            authorizeWebSocketRequest(request, response, filterChain);
        }
    }

    public void authorizeWebSocketRequest(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException {
        try {
            String token = request.getParameter("token");
            authenticate(request, response, filterChain, token);
        } catch (Exception exception){
            authenticationExceptionCatched(exception, response);
        }
    }

    public void authenticate(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, String token) throws ServletException, IOException {
        Algorithm algorithm = Algorithm.HMAC256(secretWord.getBytes(StandardCharsets.UTF_8));
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = verifier.verify(token);
        String username = decodedJWT.getSubject();
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        filterChain.doFilter(request, response);
    }

    public void authenticationExceptionCatched(Exception exception, HttpServletResponse response) throws IOException {
        log.error("Error logging in: {}", exception.getMessage());
        Map<String, String> errors = new HashMap<>();
        errors.put("error", exception.getMessage());

        response.setContentType(APPLICATION_JSON_VALUE);
        response.setHeader("error", exception.getMessage());
        response.setStatus(FORBIDDEN.value());

        new ObjectMapper().writeValue(response.getOutputStream(), errors);
    }
}
