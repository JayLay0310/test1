package com.bistu.tools.controller;

import com.bistu.tools.dto.HmacRequest;
import com.bistu.tools.dto.HmacResponse;
import com.bistu.tools.service.HmacService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/crypto/hmac")
public class HmacController {

    private final HmacService hmacService;

    @Autowired
    public HmacController(HmacService hmacService) {
        this.hmacService = hmacService;
    }

    @PostMapping("/generate")
    public ResponseEntity<HmacResponse> generateHmac(@RequestBody HmacRequest request) {
        if (request.getInput() == null || request.getKey() == null ||
                request.getAlgorithm() == null || request.getInputFormat() == null) {
            HmacResponse response = new HmacResponse();
            response.setStatus("error");
            response.setMessage("Missing required parameters");
            return ResponseEntity.badRequest().body(response);
        }

        if (!hmacService.isAlgorithmSupported(request.getAlgorithm())) {
            HmacResponse response = new HmacResponse();
            response.setStatus("error");
            response.setMessage("Unsupported algorithm: " + request.getAlgorithm());
            return ResponseEntity.badRequest().body(response);
        }

        HmacResponse response = hmacService.generateHmac(request);
        if ("success".equals(response.getStatus())) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.badRequest().body(response);
        }
    }

    @GetMapping("/algorithms")
    public ResponseEntity<Map<String, Object>> getSupportedAlgorithms() {
        Map<String, Object> response = new HashMap<>();
        response.put("algorithms", new String[] {
                "HmacMD4", "HmacMD5", "HmacSHA1", "HmacSHA224", "HmacSHA256", "HmacSHA384",
                "HmacSHA512", "HmacSHA3-224", "HmacSHA3-256", "HmacSHA3-384", "HmacSHA3-512",
                "HmacRIPEMD160", "HmacSM3"
        });
        response.put("inputFormats", new String[] {"hex", "utf-8", "base64"});
        return ResponseEntity.ok(response);
    }
}