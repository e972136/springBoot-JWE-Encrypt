package com.gaspar.main.controller;

import com.gaspar.main.entity.InfoToDecrypt;
import com.gaspar.main.entity.InfoToEncrypt;
import com.gaspar.main.service.JweService;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JweController {

    private final JweService jweService;

    public JweController(JweService jweService) {
        this.jweService = jweService;
    }


    @PostMapping("/encrypt")
    public ResponseEntity<String> encrypt(
            @RequestBody InfoToEncrypt info
    )throws Throwable{
        System.out.println(info);
        return ResponseEntity.ok(jweService.encrypt(info));
    }

    @PostMapping("/decrypt")
    public ResponseEntity<String> decrypt(
            @RequestBody InfoToDecrypt info
    ){
        return ResponseEntity.ok(jweService.decrypt(info));
    }


}
