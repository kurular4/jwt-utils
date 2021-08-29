import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.security.Key;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class JwtUtil {
    private static final String TOKEN_PREFIX = "Bearer ";

    public static boolean validateToken(String token, String secretKey) {
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    public static Optional<String> extractToken(String authorizationHeader) {
        return Optional
                .ofNullable(authorizationHeader)
                .filter(header -> authorizationHeader.startsWith(TOKEN_PREFIX))
                .map(header -> header.substring(TOKEN_PREFIX.length()));
    }

    public static String createToken(String subject, long duration, TimeUnit timeUnit, String secretKey) {
        return createToken(subject, Collections.emptyMap(), timeUnit.toMillis(duration), secretKey, SignatureAlgorithm.HS256);
    }

    public static String createToken(String subject, Map<String, Object> claimMap, long duration, TimeUnit timeUnit, String secretKey) {
        return createToken(subject, claimMap, timeUnit.toMillis(duration), secretKey, SignatureAlgorithm.HS256);
    }

    public static String createToken(String subject, Map<String, Object> claimMap, long validityInMillis, String secretKey, SignatureAlgorithm signatureAlgorithm) {
        Claims claims = Jwts.claims().setSubject(subject);
        claimMap.forEach(claims::put);
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMillis);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(signatureAlgorithm, secretKey)
                .compact();
    }

    public static String getSubject(String token, String secretKey) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }

    public static Object getClaim(String token, String secretKey, String key) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().get(key);
    }
}
