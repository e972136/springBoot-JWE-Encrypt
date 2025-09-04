package com.gaspar.main.helper;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class PemUtils {
    public static RSAPrivateKey loadPrivateKey(String resourcePath) throws Exception {

        String key = readPem(resourcePath)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(key);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);

        RSAPrivateKey p = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);

        return p;
    }

    public static RSAPublicKey loadPublicKey(String resourcePath) throws Exception {

        String key = readPem(resourcePath)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        RSAPublicKey p = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);

        return p;
    }

    private static String readPem(String resourcePath) throws Exception {
        try (InputStream is = PemUtils.class.getClassLoader().getResourceAsStream(resourcePath)) {
            if (is == null) throw new IllegalArgumentException("File not found: " + resourcePath);
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
