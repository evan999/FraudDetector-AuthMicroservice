package Jwt;

import org.apache.logging.log4j.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class SecretService {

    private static final Logger log = LoggerFactory.getLogger(SecretService.class);

    private KeyPair keyPair;
    private String keyId;

    private Map<String, PublicKey> publicKeys = new HashMap<>();

    @PostConstruct
    public void setUp(){
        refreshCreds();
    }

    private SigningKeyResolver signingKeyResolver = new SigningKeyResolverAdapter() {

        @Override
        public Key resolveSigningKey(JwsHeader header, Claims claims){
            String keyId = header.getKeyId();

            if(!Strings.hasText(keyId)){
                throw new JwtException("Missing required keyId header param in JWT with claims: " + claims);
            }
            Key key = publicKeys.get(keyId);
            if(key == null){
                throw new JwtException("No public key registered for keyId: " + keyId + ". JWT claims: " + claims);
            }
            return key;
        }
    };

    public SigningKeyResolver getSigningKeyResolver(){
        return signingKeyResolver;
    }

    public PublicCreds getPublicCreds(String keyId){
        return createPublicCreds(keyId, publicKeys.get(keyId));
    }

    public PublicCreds getUserPublicCreds(){
        return createPublicCreds(this.keyId, keyPair.getPublic());
    }

    private PublicCreds createPublicCreds(String keyId, PublicKey key){
        return new PublicCreds(keyId, TextCodec.BASE64URL.encode(key.getEncoded()));
    }

    public PrivateKey getPrivateKey(){
        return keyPair.getPrivate();
    }

    public PublicCreds refreshCreds() {
        keyPair = RsaProvider.generateKeyPair(1024);
        keyId = UUID.randomUUID().toString();

        PublicCreds publicCreds = getUserPublicCreds();

        addPublicCreds(publicCreds);

        return publicCreds;
    }

    public void addPublicCreds(PublicCreds publicCreds){
        byte[] encoded = TextCodec.BASE64URL.decode(publicCreds.getB64UrlPublicKey());

        PublicKey publicKey = null;
        try{
            publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encoded));
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException error) {
            log.error("Unable to create public key: {}", error.getMessage(), error);
        }

        publicKeys.put(publicCreds.getKeyId(), publicKey);
    }


}
