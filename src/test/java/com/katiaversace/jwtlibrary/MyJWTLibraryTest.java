package com.katiaversace.jwtlibrary;

import com.nimbusds.jose.JWSObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class MyJWTLibraryTest {

    private final String secretKey = "secretkey-katia-41c3783d6-1cf559b4";

    @Test
    void JWTDecode() {
        String toDecode = "eyJjdHkiOiJ0ZXh0XC9wbGFpbiIsImFsZyI6IkhTMjU2In0.SGVsbG8gd29ybGQh.Zc4yKk2BZGh6LFqIj5L30-qeWvu3CcZPHFbBmGiirpA";
        JWSObject jwsObject = MyJWTLibrary.JWTDecode(toDecode);

        Assertions.assertNotNull(jwsObject);
        Assertions.assertSame(jwsObject.getState(), JWSObject.State.SIGNED);
        Assertions.assertEquals(jwsObject.getPayload().toString(), "Hello world!");
    }

    @Test
    void JWTSign() {
        String toSign = "Hello world!";
        String signed = MyJWTLibrary.JWTSign(secretKey, toSign);

        Assertions.assertNotNull(signed);
        Assertions.assertFalse(signed.isEmpty());
        Assertions.assertTrue(signed.matches(".*\\..*\\..*"));
    }

    @Test
    void JWTVerify() {
        String toVerify = "eyJjdHkiOiJ0ZXh0XC9wbGFpbiIsImFsZyI6IkhTMjU2In0.SGVsbG8gd29ybGQh.Zc4yKk2BZGh6LFqIj5L30-qeWvu3CcZPHFbBmGiirpA";

        Assertions.assertTrue(MyJWTLibrary.JWTVerify(secretKey, toVerify));
    }
}