package org.course_planner.authentication.service;

import com.nimbusds.jose.jwk.RSAKey;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public interface RSAKeyPairProviderService {
    PrivateKey privateKey() throws InvalidKeySpecException, IOException, NoSuchAlgorithmException;

    PublicKey publicKey() throws InvalidKeySpecException, IOException, NoSuchAlgorithmException;

    RSAKey rsaKey() throws NoSuchAlgorithmException;
}
