package com.bistu.tools.controller;

import com.bistu.tools.dto.KeyPairRequest;
import com.bistu.tools.dto.KeyPairResponse;
import com.bistu.tools.service.KeyPairService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/crypto/keypair")
public class KeyPairController {

    private final KeyPairService keyPairService;

    @Autowired
    public KeyPairController(KeyPairService keyPairService) {
        this.keyPairService = keyPairService;
    }

    @PostMapping("/generate")
    public ResponseEntity<KeyPairResponse> generateKeyPair(@RequestBody KeyPairRequest request) {
        if (request.getAlgorithm() == null) {
            KeyPairResponse response = new KeyPairResponse();
            response.setStatus("error");
            response.setMessage("Missing required algorithm parameter");
            return ResponseEntity.badRequest().body(response);
        }

        if (!keyPairService.isAlgorithmSupported(request.getAlgorithm())) {
            KeyPairResponse response = new KeyPairResponse();
            response.setStatus("error");
            response.setMessage("Unsupported algorithm: " + request.getAlgorithm());
            return ResponseEntity.badRequest().body(response);
        }

        KeyPairResponse response = keyPairService.generateKeyPair(request);
        if ("success".equals(response.getStatus())) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.badRequest().body(response);
        }
    }

    @GetMapping("/algorithms")
    public ResponseEntity<Map<String, Object>> getSupportedAlgorithms() {
        Map<String, Object> response = new HashMap<>();
        response.put("algorithms", new String[] {"SM2", "RSA", "EC"});
        response.put("rsaKeySizes", new Integer[] {1024, 2048, 3072, 4096});
        response.put("ecCurves", new String[] {
                "secp256r1", "secp384r1", "secp521r1", "prime256v1"
        });
        return ResponseEntity.ok(response);
    }
}