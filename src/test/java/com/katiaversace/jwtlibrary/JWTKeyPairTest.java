package com.katiaversace.jwtlibrary;

import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

class JWTKeyPairTest {


    @Test
    void EncodeVerifyTest() {

        //Generating keys
        Map<String, Object> keys = null;
        try {
            keys = MyJWTLibrary.getRSAKeys();
        } catch (Exception e) {
            e.printStackTrace();
        }

        PublicKey publicKey = (PublicKey) keys.get("public");
        PrivateKey privateKey = (PrivateKey) keys.get("private");

        Map<String, Object> claims = new HashMap<>();
        String idValue = "1", roleValue = "admin";
        claims.put("id", idValue);
        claims.put("role", roleValue);

        //Encode
        String token =  MyJWTLibrary.encodeKeyPair(privateKey, claims);

        //Verify and get Claims
        Claims c = MyJWTLibrary.verifyKeyPair(token, publicKey);
        Assertions.assertNotNull(c);

        Assertions.assertEquals(c.get("id"), idValue);
        Assertions.assertEquals(c.get("role"), roleValue);

    }


}