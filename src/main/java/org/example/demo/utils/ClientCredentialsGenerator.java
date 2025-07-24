package org.example.demo.utils;


import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

public class ClientCredentialsGenerator {

    public static String generateClientId(String prefix){
        return prefix + "_" + UUID.randomUUID().toString().replace("-", "");

    }
    public static String generateClientSecret(){
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return Base64.getEncoder().withoutPadding().encodeToString(randomBytes);
    }
}
