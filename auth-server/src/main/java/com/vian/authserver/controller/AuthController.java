package com.vian.authserver.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {
    @GetMapping("/authorized")
    public String getGrantCode(String code) {
        return code;
    }
}