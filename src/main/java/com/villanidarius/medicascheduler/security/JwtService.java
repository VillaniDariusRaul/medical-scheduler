package com.villanidarius.medicascheduler.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;


@Service
public class JwtService {

    //gets the values of .env variables, check .env.example
    @Value("${jwt.secret}")
    private String JWT_Secret;
    @Value("${jwt.expiration}")
    private long JWT_Expiration;
    @Value("${jwt.refreshexpiration")
    private long JWT_Refresh_expiration;


    //tokens generation functions:

    //method overloading generateToken, 2 methods that share a signature with different params
    // so you can create a token with or without claims without having to pass the map as arguement
    // generates token without claims
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    //generates the token with claims
    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return buildToken(extraClaims, userDetails, JWT_Expiration);
    }

    //generates the refresh token similar to the access one above it, but much longer lasting.
    public String generateRefreshToken(
            UserDetails userDetails
    ) {
        return buildToken(new HashMap<>(), userDetails, JWT_Refresh_expiration);
    }

    private String buildToken(
            Map<String, Object> extraClaims, //maps the claims that will be added to the token
            UserDetails userDetails,         //for the username
            long expiration
    ) {
        return Jwts
                .builder() //creates a JwtBuilder
                .setClaims(extraClaims) //adds the mapped claims to the token
                .setSubject(userDetails.getUsername()) //adds the username as sub
                .setIssuedAt(new Date(System.currentTimeMillis())) // start date
                .setExpiration(new Date(System.currentTimeMillis() + expiration)) //end date
                .signWith(getSignInKey(), SignatureAlgorithm.HS256) //signature
                .compact();
    }

    //token validations functions
    //checks the user is who he claims to be and checks that the token is not expired
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }


    //payload functions

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public String extractUsername(String token){
        return extractClaim(token,Claims::getSubject); //takes the sub from the token payload
    }

    // helper for extracting data from the payload
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token); // gets the payload
        return claimsResolver.apply(claims); // applies the input function and returns what you need from claims
    }

    // function that extracts all the claims from a jwt using jjwt-api 11.5
    // (most of these function are deprecated in 12)
    // https://javadoc.io/doc/io.jsonwebtoken/jjwt-api for documentation
    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder() //creates a new parserBuilder object
                .setSigningKey(getSignInKey()) //stores the key in the object
                .build() //fills in defaults and creates an immutable jwtParser
                .parseClaimsJws(token) //splits the token into header payload and signature
                                       // compares the keys, checks exp and returns a Jws
                .getBody(); //takes the decoded payload our of Jws
    }

    //needed in order to verify the token was signed with our secret
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(JWT_Secret); //decodes the original jwt key bytes
        return Keys.hmacShaKeyFor(keyBytes); //wraps the bytes in a SecretKey and picks hmac sha based on lenght
    }
}
