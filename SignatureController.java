package com.bistu.tools.controller;



import com.bistu.tools.dto.SignRequest;
import com.bistu.tools.dto.SignResponse;
import com.bistu.tools.dto.VerifyRequest;
import com.bistu.tools.dto.VerifyResponse;
import com.bistu.tools.service.SignatureService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/crypto/signature")
public class SignatureController {

    private final SignatureService signatureService;

    @Autowired
    public SignatureController(SignatureService signatureService) {
        this.signatureService = signatureService;
    }
    /**
     * 签名
     */
    @PostMapping("/sign")
    public ResponseEntity<SignResponse> generateSignature(@RequestBody SignRequest request) {
        // 验证请求参数
        if (request.getMessage() == null || request.getPrivateKey() == null ||
                request.getAlgorithm() == null || request.getHashAlgorithm() == null) {
            SignResponse response = new SignResponse();
            response.setStatus("error");
            response.setMessage("Missing required parameters");
            return ResponseEntity.badRequest().body(response);
        }

        // 生成签名
        SignResponse response = signatureService.generateSignature(request);

        if ("success".equals(response.getStatus())) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.badRequest().body(response);
        }
    }
    /**
     * 验证签名
     */
    @PostMapping("/verify-specific")
    public ResponseEntity<VerifyResponse> verifySignature(@RequestBody VerifyRequest request) {
        // 验证请求参数
        if (request.getMessage() == null || request.getSignature() == null ||
                request.getAlgorithm() == null || request.getHashAlgorithm() == null ||
                (request.getPublicKey() == null && request.getCertificate() == null)) {
            VerifyResponse response = new VerifyResponse();
            response.setStatus("error");
            response.setMessage("Missing required parameters");
            return ResponseEntity.badRequest().body(response);
        }

        // 验证签名
        VerifyResponse response = signatureService.verifySignature(request);

        if ("success".equals(response.getStatus())) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.badRequest().body(response);
        }
    }

    @GetMapping("/algorithms")
    public ResponseEntity<Map<String, Object>> getAlgorithmInfo() {
        Map<String, Object> response = new HashMap<>();
        response.put("signatureAlgorithms", signatureService.getSupportedSignatureAlgorithms());
        response.put("hashAlgorithms", signatureService.getSupportedHashAlgorithms());
        response.put("validCombinations", signatureService.getValidAlgorithmCombinations());
        response.put("inputFormats", new String[] {"utf-8", "hex", "base64"});
        response.put("outputFormats", new String[] {"hex", "utf-8", "base64"});
        response.put("certificateFormats", new String[] {"PEM", "BASE64", "HEX"});
        return ResponseEntity.ok(response);
    }
}
