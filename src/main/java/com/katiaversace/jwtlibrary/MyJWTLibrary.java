package com.katiaversace.jwtlibrary;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class MyJWTLibrary {

    public static JWSObject JWTDecode(String jwtToken){
        // Parse back and check signature
        JWSObject jwsObject;
        try {
            jwsObject = JWSObject.parse(jwtToken);
            System.out.println("JWS object successfully parsed:\n" + jwsObject.getPayload());
            return jwsObject;
        } catch (ParseException e) {
            System.err.println("Couldn't parse JWS object: " + e.getMessage());
            return null;
        }
    }

    public static String JWTSign(String secretKey, String payloadMessage){
        Payload payload = new Payload(payloadMessage);

        System.out.println("JWS payload message: " + payloadMessage);

        // Create JWS header with HS256 algorithm
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).
                contentType("text/plain").
                build();

        System.out.println("JWS header: " + header.toJSONObject());

        // Create JWS object
        JWSObject jwsObject = new JWSObject(header, payload);

        System.out.println("HMAC key: " + secretKey);

        JWSSigner signer;
        try {
            signer = new MACSigner(secretKey.getBytes());
            jwsObject.sign(signer);
        } catch (Exception e) {
            System.err.println("Couldn't sign JWS object: " + e.getMessage());
            return null;
        }

        // Serialise JWS object to compact format
        String s = jwsObject.serialize();
        System.out.println("Serialised JWS object: " + s);

        return s;
    }

    public static boolean JWTVerify(String secretKey, String jwtToken) {
        JWSVerifier verifier;
        JWSObject jwsObject = null;
        boolean verifiedSignature = false;

        try {
            jwsObject = JWSObject.parse(jwtToken);
            verifier = new MACVerifier(secretKey.getBytes());
            verifiedSignature = jwsObject.verify(verifier);
        } catch (Exception e) {
            System.err.println("Couldn't verify signature: " + e.getMessage());
        }

        if (verifiedSignature) {
            System.out.println("Verified JWS signature!\nRecovered payload message: " + jwsObject.getPayload());
        } else {
            System.out.println("Bad JWS signature!");
        }

        return verifiedSignature;
    }

    public static String encodeKeyPair(PrivateKey privateKey, Map<String, Object> claims) {
        String token = null;
        try {

            Instant now = Instant.now();
            token = Jwts.builder().setClaims(claims).setIssuedAt(Date.from(now))
                    .setExpiration(Date.from(now.plus(5, ChronoUnit.MINUTES))).signWith(SignatureAlgorithm.RS256, privateKey).compact();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return token;
    }

    public static Claims verifyKeyPair(String token, PublicKey publicKey) {
        Claims claims;
        try {
            claims = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token).getBody();
        } catch (Exception e) {
            claims = null;
        }
        return claims;
    }

    public static Map<String, Object> getRSAKeys() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        Map<String, Object> keys = new HashMap<String, Object>();
        keys.put("private", privateKey);
        keys.put("public", publicKey);
        return keys;
    }
}
