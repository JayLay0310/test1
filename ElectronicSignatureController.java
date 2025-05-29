package com.bistu.tools.controller;

import com.bistu.tools.core.response.Result;
import com.bistu.tools.core.response.ResultGenerator;
import com.bistu.tools.dto.ElectronicSignatureDTO;
import com.bistu.tools.service.ElectronicSignatureService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

/**
 * 电子签章解析控制器
 * 处理OFD文档中电子签名的解析请求
 */
@RestController
@RequestMapping("/api/electronic-signature")
public class ElectronicSignatureController {

    private final ElectronicSignatureService electronicSignatureService;

    @Autowired
    public ElectronicSignatureController(ElectronicSignatureService electronicSignatureService) {
        this.electronicSignatureService = electronicSignatureService;
    }

    /**
     * 解析上传的电子签章文件
     * @param file 上传的OFD或PDF文件
     * @return 包含签名信息的分析结果
     */
    @PostMapping(value = "/analyze", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public Result<ElectronicSignatureDTO.AnalysisResultDTO> analyzeSignature(
            @RequestParam("file") MultipartFile file) {
        try {
            ElectronicSignatureDTO.AnalysisResultDTO result = electronicSignatureService.analyzeSignature(file);
            return ResultGenerator.genOkResult(result);
        } catch (Exception e) {
            return ResultGenerator.genFailedResult("解析电子签章失败: " + e.getMessage());
        }
    }

    /**
     * 使用附加参数解析电子签章
     * @param request 包含文件数据和附加参数的请求
     * @return 包含签名信息的分析结果
     */
    @PostMapping(value = "/analyze-with-params", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Result<ElectronicSignatureDTO.AnalysisResultDTO> analyzeSignatureWithParams(
            @RequestBody ElectronicSignatureDTO.AnalysisRequestDTO request) {
        try {
            ElectronicSignatureDTO.AnalysisResultDTO result = electronicSignatureService.analyzeSignatureWithParams(request);
            return ResultGenerator.genOkResult(result);
        } catch (Exception e) {
            return ResultGenerator.genFailedResult("解析电子签章失败: " + e.getMessage());
        }
    }
}