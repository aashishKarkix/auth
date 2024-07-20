package com.role.auth.security.service.jwt;

import com.role.auth.security.service.Generator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class JwtTokenUtil {
  public static final String SECRET_KEY = Generator.generateDynamicSecretKey();
  public static final String REFRESH_SECRET_KEY = Generator.generateDynamicSecretKey();
  private static final long ACCESS_TOKEN_EXPIRY = 15 * 60 * 1000;
  private static final long REFRESH_TOKEN_EXPIRY = 7 * 24 * 15 * 60 * 1000;


  private Key getSigningKey(String secretKey) {
    return Keys.hmacShaKeyFor(secretKey.getBytes());
  }

  public String generateAccessToken(Map<String, String> claims, String subject){
    return Jwts.builder()
        .claims(claims)
        .subject(subject)
        .issuedAt(new Date(System.currentTimeMillis()))
        .expiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRY))
        .signWith(getSigningKey(SECRET_KEY))
        .compact();
  }

  public String refreshAccessToken(String refreshToken) {
    if (!isTokenValid(refreshToken, REFRESH_SECRET_KEY)) {
      throw new IllegalArgumentException("Invalid refresh token");
    }
    Claims claims = extractAllClaims(refreshToken, REFRESH_SECRET_KEY);
    return generateAccessToken(claimsToMap(claims), claims.getSubject());
  }


  public String generateRefreshToken(Map<String, String> claims, String subject){
    return Jwts.builder()
        .claims(claims)
        .subject(subject)
        .issuedAt(new Date(System.currentTimeMillis()))
        .expiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRY))
        .signWith(getSigningKey(REFRESH_SECRET_KEY))
        .compact();
  }

  public boolean isTokenExpired(String token, String secretKey){
    return extractAllClaims(token, secretKey)
        .getExpiration()
        .before(new Date());
  }

  public boolean isTokenValid(String token, String secretKey) {
    try {
      extractAllClaims(token, secretKey);
      return true;
    } catch (Exception e) {
      return false;
    }
  }
  public String extractUserName(String token, String secret){
    return extractAllClaims(token, secret).getSubject();
  }

  public <T> T extractClaim(String token, String SECRET_KEY, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token, SECRET_KEY);
    return claimsResolver.apply(claims);
  }

  public Claims extractAllClaims(String token, String SECRET_KEY){
   return Jwts.parser()
       .setSigningKey(getSigningKey(SECRET_KEY))
       .build()
       .parseSignedClaims(token)
       .getPayload();
  }

  private Map<String, String> claimsToMap(Claims claims) {
    return claims.entrySet().stream()
            .collect(Collectors.toMap(Map.Entry::getKey, entry -> String.valueOf(entry.getValue())));
  }
}
