package com.katiaversace.jwtlibrary;

import com.nimbusds.jose.*;


public class MainApplication {

    public static void main(String[] args) throws JOSEException {

        System.out.println("Test Decode");
        MyJWTLibrary.JWTDecode("eyJjdHkiOiJ0ZXh0XC9wbGFpbiIsImFsZyI6IkhTMjU2In0.SGVsbG8gd29ybGQh.Zc4yKk2BZGh6LFqIj5L30-qeWvu3CcZPHFbBmGiirpA");
        System.out.println("\nTest Verify");
        MyJWTLibrary.JVTVerify("secretkey-katia-41c3783d6-1cf559b4","eyJjdHkiOiJ0ZXh0XC9wbGFpbiIsImFsZyI6IkhTMjU2In0.SGVsbG8gd29ybGQh.Zc4yKk2BZGh6LFqIj5L30-qeWvu3CcZPHFbBmGiirpA");
        System.out.println("\nTest Sign");
        MyJWTLibrary.JWTSign("secretkey-katia-41c3783d6-1cf559b4", "Hello world!");

    }


}
