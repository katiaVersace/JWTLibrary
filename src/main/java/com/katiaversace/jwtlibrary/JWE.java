package com.katiaversace.jwtlibrary;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Map;
import java.util.Optional;

public class JWE {

    private RSAEncrypter encrypter;
    private RSADecrypter decrypter;

    public JWE (Map<String, Object> keys){
        encrypter = new RSAEncrypter((RSAPublicKey) keys.get("public"));
        decrypter = new RSADecrypter((RSAPrivateKey) keys.get("private"));
    }

    public Optional<String> encrypt(String payload){
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);
        JWEObject jwe = null;
        try {
            jwe = new JWEObject(header, new Payload(payload));
            jwe.encrypt(encrypter);
        } catch (JOSEException e) {
            e.printStackTrace();
        }
        return Optional.ofNullable(jwe.serialize());
    }

    public Optional<String> decrypt(String encrypted) {
        JWEObject jwe = null;
        try {
            jwe = JWEObject.parse(encrypted);
        jwe.decrypt(decrypter);
        } catch (ParseException e) {
            e.printStackTrace();
        } catch (JOSEException e) {
            e.printStackTrace();
        }
        return Optional.ofNullable(jwe.getPayload().toString());
    }
}
