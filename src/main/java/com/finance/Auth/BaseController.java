package com.finance.Auth;

import Jwt.SecretService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import io.jsonwebtoken.SignatureAlgorithm;

import java.security.SignatureException;
import java.util.Date;
import java.util.Map;

public class BaseController {

    @Autowired
    SecretService secretService;

    protected String createJwt(Map<String, Object> claims){
        Assert.notNull(
            claims.get(AccountService.USERNAME_CLAIM),
            AccountService.USERNAME_CLAIM + " claim is required."
        );

        Date now = new Date();
        Date expiration = new Date(now.getTime() + (1000*60));

        String jwt = Jwts.builder()
                .setHeaderParam("keyId", secretService.getPublicCreds().getKeyId())
                .setClaims(claims)
                .setIssuedAt(now)
                .setNotBefore(now)
                .setExpiration(expiration)
                .signWith(
                        SignatureAlgorithm.RS256,
                        secretService.getPrivateKey()
                )
                .compact();

        return jwt;
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler({
            SignatureException.class, MalformedJwtException.class, JwtException.class, IllegalArgumentException.class
    })
    public JWTResponse badRequest(Exception error){
        return processException(error);
    }

    @ResponseStatus
    @ExceptionHandler(UnauthorizedException.class)
    public JWTResponse unauthorized(Exception error){
        return processException(error);
    }

    private JWTResponse processException(Exception error){
        JWTResponse response = new JWTResponse();
        response.setStatus(JWTResponse.Status.ERROR);
        response.setMessage(error.getMessage());
        response.setExcetionType(error.getClass().getName());

        return response;
    }

}
