package com.murali.security.springsecuirty;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtConfig {

    public JwtConfig() {
    }

    private String JWT_SECRET_KEY="secret";

    public String generateToken(UserDetails userDetails){
        Map<String,Object> claims= new LinkedHashMap<>();
        return createToken(claims,userDetails.getUsername());
    }
    private String createToken(Map<String,Object> claims,String subject){
      return  Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*60*10)).signWith(SignatureAlgorithm.HS256,JWT_SECRET_KEY).compact();

    }

    public String extractUserName(String jwtToken) {
        return extractClaim(jwtToken,Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims,T> claimsTFunction){
        Claims claims = extractAllClaims(token);
        return claimsTFunction.apply(claims);
    }

    private Claims extractAllClaims(String tokens){
        return Jwts.parser().setSigningKey(JWT_SECRET_KEY).parseClaimsJws(tokens).getBody();
    }

    public boolean validateToken(String jwtToken, UserDetails userDetails) {
       String username= extractUserName(jwtToken);
       return username.equals(userDetails.getUsername()) && !isTokenExpired(jwtToken);
    }

    private boolean isTokenExpired(String jwtToken) {
        return extractExpiration(jwtToken).before(new Date());
    }

    private Date extractExpiration(String jwtToken) {
        return extractClaim(jwtToken,Claims::getExpiration);
    }
}
