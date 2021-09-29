package com.omer.jwtutils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * jjwt wrapper that contains methods to have better use of functions
 */
public class JwtUtil {
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String AUTHORIZATION_HEADER = "authorization";

    /**
     * Tests token for validity
     *
     * @param token     to be validated
     * @param secretKey key that is used to sign the token
     * @return true if it is a valid token, false otherwise
     */
    public static boolean validateToken(String token, String secretKey) {
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    /**
     * Extracts token from given authorization header
     *
     * @param authorizationHeader header to extract token from
     * @return Optional object which may contain token
     */
    public static Optional<String> extractToken(String authorizationHeader) {
        return Optional
                .ofNullable(authorizationHeader)
                .filter(header -> authorizationHeader.startsWith(TOKEN_PREFIX))
                .map(header -> header.substring(TOKEN_PREFIX.length()));
    }

    /**
     * Creates token from given parameters with default signature algorithm HS256
     *
     * @param subject   subject of the jwt
     * @param duration  how long it will take until expiration
     * @param timeUnit  unit of time
     * @param secretKey secret to sign token
     * @return created token
     */
    public static String createToken(String subject, long duration, TimeUnit timeUnit, String secretKey) {
        return createToken(subject, Collections.emptyMap(), timeUnit.toMillis(duration), secretKey, SignatureAlgorithm.HS256);
    }

    /**
     * Creates token from given parameters with default signature algorithm HS256
     *
     * @param subject   subject of the jwt
     * @param claimMap  map containing claims to put in the token payload
     * @param duration  how long it will take until expiration
     * @param timeUnit  unit of time
     * @param secretKey secret to sign token
     * @return created token
     */
    public static String createToken(String subject, Map<String, Object> claimMap, long duration, TimeUnit timeUnit, String secretKey) {
        return createToken(subject, claimMap, timeUnit.toMillis(duration), secretKey, SignatureAlgorithm.HS256);
    }

    /**
     * Creates token from given parameters with default signature algorithm HS256
     *
     * @param subject   subject of the jwt
     * @param duration  how long it will take until expiration
     * @param secretKey secret to sign token
     * @return created token
     */
    public static String createToken(String subject, Duration duration, String secretKey) {
        return createToken(subject, Collections.emptyMap(), duration.toMillis(), secretKey, SignatureAlgorithm.HS256);
    }

    /**
     * Creates token from given parameters with default signature algorithm HS256
     *
     * @param subject   subject of the jwt
     * @param claimMap  map containing claims to put in the token payload
     * @param duration  how long it will take until expiration
     * @param secretKey secret to sign token
     * @return created token
     */
    public static String createToken(String subject, Map<String, Object> claimMap, Duration duration, String secretKey) {
        return createToken(subject, claimMap, duration.toMillis(), secretKey, SignatureAlgorithm.HS256);
    }

    /**
     * Creates token from given parameters with given signature algorithm
     *
     * @param subject            subject of the jwt
     * @param claimMap           map containing claims to put in the token payload
     * @param validityInMillis   how long it will take until expiration in milliseconds
     * @param secretKey          secret to sign token
     * @param signatureAlgorithm algorithm to sign token
     * @return created token
     */
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

    /**
     * Extracts subject from token
     *
     * @param token     to get subject from
     * @param secretKey secret that is used to sign token
     * @return subject
     */
    public static String getSubject(String token, String secretKey) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }

    /**
     * Extracts claim with given key
     *
     * @param token     to get claim from
     * @param secretKey secret that is used to sign token
     * @param key       claim key
     * @return claim object
     */
    public static Object getClaim(String token, String secretKey, String key) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().get(key);
    }
}
