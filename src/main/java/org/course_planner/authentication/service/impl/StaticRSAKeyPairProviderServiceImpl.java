package org.course_planner.authentication.service.impl;

import com.nimbusds.jose.jwk.RSAKey;
import org.course_planner.authentication.service.RSAKeyPairProviderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;

@Service("StaticRSAKeyPairProviderServiceImpl")
public class StaticRSAKeyPairProviderServiceImpl implements RSAKeyPairProviderService {
    private static final String CONST_PRIVATE_KEY_PROPERTY = "org.course_planner.authentication-service.key-pair-configs.private-key";
    private static final String CONST_PUBLIC_KEY_PROPERTY = "org.course_planner.authentication-service.key-pair-configs.public-key";

    private static RSAKey rsaKey;

    @Value("${" + CONST_PUBLIC_KEY_PROPERTY + "}")
    private RSAPublicKey publicKey;
    @Value("${" + CONST_PRIVATE_KEY_PROPERTY + "}")
    private RSAPrivateKey privateKey;

    @Autowired
    private Environment environment;

    public PrivateKey privateKey() throws InvalidKeySpecException, IOException, NoSuchAlgorithmException {
        return privateKey;
    }

    public PublicKey publicKey() throws InvalidKeySpecException, IOException, NoSuchAlgorithmException {
        return publicKey;
    }

    @Override
    public RSAKey rsaKey() throws NoSuchAlgorithmException {
        if (rsaKey == null) {
            try {
                rsaKey = new RSAKey.Builder((RSAPublicKey) publicKey())
                        .privateKey(privateKey())
                        .keyID(UUID.randomUUID().toString())
                        .build();
            } catch (Exception ex) {
                throw new RuntimeException("rsaKey: Unable to load key!");
            }
        }
        return rsaKey;
    }
}