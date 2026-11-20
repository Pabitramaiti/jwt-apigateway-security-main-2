package com.javatechie.service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtService {

	public static final String SECRET = "5367566B59703373367639792F423F4528482B4D6251655468576D5A71347437";

	// Validate token
	public void validateToken(final String token) {
		Jwts.parser().verifyWith(getSignKey()).build().parseSignedClaims(token);
	}

	// Generate token
	public String generateToken(String userName) {
		Map<String, Object> claims = new HashMap<>();
		return createToken(claims, userName);
	}

	private String createToken(Map<String, Object> claims, String userName) {
//		return Jwts.builder().claims(claims).subject(userName).issuedAt(new Date(System.currentTimeMillis()))
//				.expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30)) // 30 minutes
//				.signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
		return Jwts.builder()
                .claims(claims)
                .subject(userName)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30)) // 30 minutes
                .signWith(getSignKey())   // algorithm inferred from key
                .compact();

	}

	private SecretKey getSignKey() {
		byte[] keyBytes = Decoders.BASE64.decode(SECRET);
		return Keys.hmacShaKeyFor(keyBytes);
	}

	// Extract username from token
	public String extractUserName(String token) {
		return extractAllClaims(token).getSubject();
	}

	// Extract all claims
	private Claims extractAllClaims(String token) {
		return Jwts.parser().verifyWith(getSignKey()).build().parseSignedClaims(token).getPayload();
	}
}
