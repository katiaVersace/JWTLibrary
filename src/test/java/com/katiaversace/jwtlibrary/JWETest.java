package com.katiaversace.jwtlibrary;

import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

class JWETest {


    @Test
    void EncriptDecriptTest() {

        //Generating keys
        Map<String, Object> keys = null;
        try {
            keys = MyJWTLibrary.getRSAKeys();
        } catch (Exception e) {
            e.printStackTrace();
        }

        JWE jwe = new JWE(keys);
        String decrypted = "Hello World!";

        //Encrypt
        String encrypted = jwe.encrypt(decrypted).get();

        //Decrypt
        Assertions.assertEquals(jwe.decrypt(encrypted).get(), decrypted);

    }



}