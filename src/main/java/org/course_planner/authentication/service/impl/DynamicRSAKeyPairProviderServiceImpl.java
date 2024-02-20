package org.course_planner.authentication.service.impl;

import com.nimbusds.jose.jwk.RSAKey;
import org.course_planner.authentication.service.RSAKeyPairProviderService;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;

@Service
@Primary
public class DynamicRSAKeyPairProviderServiceImpl implements RSAKeyPairProviderService {
    private static KeyPair generatedKeyPair;
    private static RSAKey rsaKey;
    public PrivateKey privateKey() throws InvalidKeySpecException, IOException, NoSuchAlgorithmException {
        try {
            RSAKey rsaKey = rsaKey();
            return rsaKey.toPrivateKey();
        } catch (Exception ex) {
            return null;
        }
    }

    public PublicKey publicKey() throws InvalidKeySpecException, IOException, NoSuchAlgorithmException {
        try {
            RSAKey rsaKey = rsaKey();
            return rsaKey.toPublicKey();
        } catch (Exception ex) {
            return null;
        }
    }

    @Override
    public RSAKey rsaKey() throws NoSuchAlgorithmException {
        if (rsaKey == null) {
            KeyPair keyPair = generateKeyPair();
            rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey(keyPair.getPrivate())
                    .keyID(UUID.randomUUID().toString())
                    .build();
        }
        return rsaKey;
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        if (generatedKeyPair == null) {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            generatedKeyPair = keyPairGenerator.generateKeyPair();
        }
        return generatedKeyPair;
    }
}