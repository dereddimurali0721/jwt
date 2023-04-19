package com.murali.security.springsecuirty.controller;

import com.murali.security.springsecuirty.JwtConfig;
import com.murali.security.springsecuirty.model.AuthenticationRequest;
import com.murali.security.springsecuirty.model.AuthenticationResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserDetailsService userDetailsService;

    @Autowired
    JwtConfig jwtConfig;



    @GetMapping("/hello")
    public String helloWorld(){
        return "Welcome to the Successful Authentication";
    }

    @PostMapping("/authenticate")
    public AuthenticationResponse authenticate(@RequestBody AuthenticationRequest authenticationRequest){
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUserName(), authenticationRequest.getPassword()));
        }catch (BadCredentialsException exception){
            throw new RuntimeException("Bad Credentials!!!",exception);
        }

        UserDetails userDetails=userDetailsService.loadUserByUsername(authenticationRequest.getUserName());

        String token= jwtConfig.generateToken(userDetails);

        return new AuthenticationResponse(token);


    }
}
