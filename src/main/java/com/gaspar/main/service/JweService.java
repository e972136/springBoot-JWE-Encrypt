package com.gaspar.main.service;

import com.gaspar.main.entity.InfoToDecrypt;
import com.gaspar.main.entity.InfoToEncrypt;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.shaded.gson.Gson;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

@Service
public class JweService {

    private static Gson gson = new Gson();

    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    @PostConstruct
    public void init() throws Exception{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        publicKey = (RSAPublicKey) keyPair.getPublic();
        privateKey = (RSAPrivateKey) keyPair.getPrivate();
    }

    public String encrypt(InfoToEncrypt info)throws Exception {

        String infoToEncrypt = gson.toJson(info);
        System.out.println("infoToEncrypt: "+infoToEncrypt);

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .type(new JOSEObjectType("JOSE"))       // typ: JOSE
                .customParam("iat", "1625057896")       // igual que en Python
                .keyID("tkn.is.jwe.1")                  // kid
                .build();

        Payload payload = new Payload(infoToEncrypt);

        JWEObject jweObject = new JWEObject(header, payload);

        jweObject.encrypt(new RSAEncrypter(publicKey));

        String jweString = jweObject.serialize();

        return jweString;
    }

    public String decrypt(InfoToDecrypt info) {
        String token = info.token();

        try {
            EncryptedJWT jwt = EncryptedJWT.parse(token);
            jwt.decrypt(new RSADecrypter(privateKey));
            JWTClaimsSet jwtClaimsSet = jwt.getJWTClaimsSet();

            return jwtClaimsSet.toString();

        }
        catch (ParseException e) {
//            return new ResponseEntity<>(TokenResponse.of("-1",e.getMessage(),null), HttpStatus.BAD_REQUEST);
            return "error";
        }
        catch (JOSEException e) {
            return "error";
//            return new ResponseEntity<>(TokenResponse.of("-2",e.getMessage(),null), HttpStatus.BAD_REQUEST);
        }
    }
}
