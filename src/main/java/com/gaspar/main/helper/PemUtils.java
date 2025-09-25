package com.gaspar.main.helper;

import lombok.extern.slf4j.Slf4j;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Slf4j(topic = "JWE-PemUtils")
public class PemUtils {
    public static RSAPrivateKey loadPrivateKey(String resourcePath) throws Exception {
        log.info("get private key");
        String key = readPem(resourcePath)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(key);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);

        RSAPrivateKey p = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);
        log.info("get private key done");
        return p;
    }

    public static RSAPublicKey loadPublicKey(String resourcePath) throws Exception {
        log.info("get public key");
        String key = readPem(resourcePath)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        RSAPublicKey p = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
        log.info("get public key done");
        return p;
    }

    public static String readPem(String resourcePath) throws Exception {
        log.info("resourcePath: "+resourcePath);
        Path path = Paths.get(resourcePath);
        if (Files.exists(path)) {
            // Caso 1: archivo en el sistema
            return Files.readString(path, StandardCharsets.UTF_8);
        } else {
            // Caso 2: archivo en el classpath (resources dentro del jar)
            try (InputStream is = Thread.currentThread()
                    .getContextClassLoader()
                    .getResourceAsStream(resourcePath)) {
                if (is == null) {
                    throw new IllegalArgumentException("File not found: " + resourcePath);
                }
                return new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }
        }
    }


//    private static String readPem(String resourcePath) throws Exception {
//        try (InputStream is = PemUtils.class.getClassLoader().getResourceAsStream(resourcePath)) {
//            if (is == null) throw new IllegalArgumentException("File not found: " + resourcePath);
//            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
//        }
//    }
}