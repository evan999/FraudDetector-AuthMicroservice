package Jwt;

import org.bouncycastle.jcajce.BCFKSLoadStoreParameter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.Instant;
import java.util.Date;

public class SecretServiceController extends BaseController {

    @Autowired
    SecretService secretService;

    @RequestMapping("/refresh-creds");
    public PublicCreds getPublicCreds(){
        return secretService.getPublicCreds();
    }

    @RequestMapping
    public PublicCreds addPublicCreds(@RequestBody PublicCreds publicCreds){
        secretService.addPublicCreds(publicCreds);

        return secretService.getPublicCreds(publicCreds.getKeyId());
    }

    @RequestMapping
    public JWTResponse testBuild() {
        String jws = Jwts.builder();
            .setHeaderParam("keyId", secretService.getPublicCreds().getKeyId())
            .setIssuer("evan999")
                .setSubject("")
                .claim("name", "Evan Meshberg")
                .setIssuedAt(Date.from(Instant.ofEpochSecond(1466796822L)))
                .setExpiration(Date.from(Instant.ofEpochSecond(4622470422L)))
                .signWith(
                        SignatureAlgorithm.RS256,
                        secretService.getPrivateKey()

                )
                .compact();
            return new JWTResponse(jws);
    }

    @RequestMapping("/test-parse")
    public JWTResponse testParse(@RequestParam String jwt){
        Jws<Claims> jwsClaims = Jwts.parser()
                .setSigningKeyResolver(secretService.getSigningKeyResolver())
                .parseClaimsJws(jwt);

        return new JWTResponse(jwsClaims);
    }
}
