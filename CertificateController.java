package com.bistu.tools.controller;

import com.bistu.tools.core.response.Result;
import com.bistu.tools.core.response.ResultGenerator;
import com.bistu.tools.service.CertificateAnalysisService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/certificate")
public class CertificateController {

    @Autowired
    private CertificateAnalysisService certificateAnalysisService;

    /**
     * 分析证书
     */
    @PostMapping("/analyze")
    public Result analyzeCertificate(
            @RequestParam("file") MultipartFile file) {
        try {
            Map<String, Object> result = certificateAnalysisService.analyzeCertificate(file);
            return ResultGenerator.genOkResult(result);
        } catch (Exception e) {
            return ResultGenerator.genFailedResult("证书分析失败: " + e.getMessage());
        }
    }

    /**
     * 验证证书链
     */
    @PostMapping("/validate-chain")
    public Result validateCertificateChain(
            @RequestParam("files") List<MultipartFile> files) {
        try {
            Map<String, Object> result = certificateAnalysisService.validateCertificateChain(files);
            return ResultGenerator.genOkResult(result);
        } catch (Exception e) {

            return ResultGenerator.genFailedResult("证书链验证失败: " + e.getMessage());
        }
    }

    /**
     * 解析ASN.1结构
     */
    @PostMapping("/parse-asn1")
    public Result parseAsn1Structure(
            @RequestParam("file") MultipartFile file) {
        try {
            Map<String, Object> result = certificateAnalysisService.parseAsn1Structure(file);
            return ResultGenerator.genOkResult(result);
        } catch (Exception e) {
            return ResultGenerator.genFailedResult("ASN.1解析失败: " + e.getMessage());
        }
    }

    /**
     * 直接分析Base64、PEM或Hex格式的证书
     */
    @PostMapping("/analyze-text")
    public Result analyzeTextCertificate(
            @RequestParam("certContent") String certContent,
            @RequestParam("format") String format) {
        try {
            Map<String, Object> result = certificateAnalysisService.analyzeTextCertificate(certContent, format);
            return ResultGenerator.genOkResult(result);
        } catch (Exception e) {
            Map<String, Object> error = new HashMap<String, Object>();
            error.put("code", 400);
            error.put("message", "证书分析失败: " + e.getMessage());
            return ResultGenerator.genFailedResult("证书分析失败: " + e.getMessage());
        }
    }
}
