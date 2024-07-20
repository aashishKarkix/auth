package com.role.auth.security.service;

import com.role.auth.security.service.jwt.JwtTokenUtil;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class TokenService {

    private final JwtTokenUtil jwtTokenUtil;

    public TokenService(JwtTokenUtil jwtTokenUtil) {
        this.jwtTokenUtil = jwtTokenUtil;
    }

    public String generateAccessToken(String username) {
        return jwtTokenUtil.generateAccessToken(Map.of("username", username), username);
    }

    public String generateRefreshToken(String username) {
        return jwtTokenUtil.generateRefreshToken(Map.of("username", username), username);
    }

    public String refreshAccessToken(String refreshToken) {
        return jwtTokenUtil.refreshAccessToken(refreshToken);
    }

    public boolean isTokenValid(String token) {
        return jwtTokenUtil.isTokenValid(token, JwtTokenUtil.SECRET_KEY);
    }
}
