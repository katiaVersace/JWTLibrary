package com.katiaversace.jwtlibrary;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;

import java.text.ParseException;

public class MyJWTLibrary {

    public static JWSObject JWTDecode(String jwtToken){
        // Parse back and check signature
        JWSObject jwsObject;
        try {
            jwsObject = JWSObject.parse(jwtToken);
        }
        catch (ParseException e) {

            System.err.println("Couldn't parse JWS object: " + e.getMessage());
            return null;
        }

        System.out.println("JWS object successfully parsed:\n" + jwsObject.getPayload());

        return jwsObject;
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

        JWSSigner signer = null;
        try {
            signer = new MACSigner(secretKey.getBytes());
        } catch (KeyLengthException e) {
            e.printStackTrace();
            return null;
        }

        try {
            jwsObject.sign(signer);
        }
        catch (JOSEException e) {

            System.err.println("Couldn't sign JWS object: " + e.getMessage());
            return null;
        }

        // Serialise JWS object to compact format
        String s = jwsObject.serialize();

        System.out.println("Serialised JWS object: " + s);

        return s;
    }

    public static boolean JVTVerify(String secretKey, String jwtToken){
        JWSObject jwsObject;
        try {
            jwsObject = JWSObject.parse(jwtToken);
        }
        catch (ParseException e) {

            System.err.println("Couldn't parse JWS object: " + e.getMessage());
            return false;
        }
        JWSVerifier verifier = null;
        try {
            verifier = new MACVerifier(secretKey.getBytes());
        } catch (JOSEException e) {
            e.printStackTrace();
            return false;
        }

        boolean verifiedSignature = false;

        try {
            verifiedSignature = jwsObject.verify(verifier);
        }
        catch (JOSEException e) {

            System.err.println("Couldn't verify signature: " + e.getMessage());
            return false;
        }

        if (verifiedSignature) {
            System.out.println("Verified JWS signature!\nRecovered payload message: " + jwsObject.getPayload());
        }
        else {
            System.out.println("Bad JWS signature!");
            return false;
        }
        return true;

    }
}
