package com.bistu.tools.controller;

import com.bistu.tools.core.response.Result;
import com.bistu.tools.core.response.ResultGenerator;
import com.bistu.tools.dto.HashVerificationRequest;
import com.bistu.tools.model.HashResult;
import com.bistu.tools.service.HashVerificationService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import jakarta.validation.Valid;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/hash")
@Api(tags = "哈希验证接口")
public class HashVerificationController {

    private static final int MAX_ITERATIONS = 10000;
    private static final long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB 文件大小限制

    @Autowired
    private HashVerificationService hashVerificationService;

    @PostMapping("/verify")
    @ApiOperation(value = "验证哈希值(文本)", notes = "使用JSON格式请求，仅支持文本明文")
    public Result verifyHashText(@Valid @RequestBody HashVerificationRequest request) {
        try {
            // 验证输入
            if (request.getHash() == null || request.getHash().trim().isEmpty()) {
                return ResultGenerator.genFailedResult("哈希值不能为空");
            }

            if (request.getIterations() < 1 || request.getIterations() > MAX_ITERATIONS) {
                return ResultGenerator.genFailedResult("迭代次数必须在1至" + MAX_ITERATIONS + "之间");
            }

            if (!request.hasPlaintextInput()) {
                return ResultGenerator.genFailedResult("请提供明文");
            }

            List<HashResult> results = hashVerificationService.verifyHash(
                    request.getPlaintext(),
                    request.getHash(),
                    request.getIterations(),
                    request.getSalt()
            );

            // 筛选出匹配的结果
            List<HashResult> matches = results.stream()
                    .filter(HashResult::isMatched)
                    .collect(Collectors.toList());

            // 只返回匹配的算法名称
            if (!matches.isEmpty()) {
                // 创建简化的输出结构，只包含算法名和哈希值
                Map<String, String> matchedAlgorithms = new HashMap<>();
                for (HashResult result : matches) {
                    matchedAlgorithms.put(result.getAlgorithm(), result.getComputedHash());
                }
                return ResultGenerator.genOkResult(matchedAlgorithms);
            } else {
                return ResultGenerator.genFailedResult("没有找到匹配的哈希算法");
            }
        } catch (Exception e) {
            return ResultGenerator.genFailedResult("处理错误: " + e.getMessage());
        }
    }

    @PostMapping("/verify-file")
    @ApiOperation(value = "验证哈希值(文件)", notes = "使用multipart/form-data请求，支持文件上传")
    public Result verifyHashFile(
            @Valid @RequestPart(value = "request") HashVerificationRequest request,
            @RequestPart(value = "file") MultipartFile file) {

        try {
            // 验证输入
            if (request.getHash() == null || request.getHash().trim().isEmpty()) {
                return ResultGenerator.genFailedResult("哈希值不能为空");
            }

            if (request.getIterations() < 1 || request.getIterations() > MAX_ITERATIONS) {
                return ResultGenerator.genFailedResult("迭代次数必须在1至" + MAX_ITERATIONS + "之间");
            }

            // 检查文件
            if (file == null || file.isEmpty()) {
                return ResultGenerator.genFailedResult("请提供文件");
            }

            // 检查文件大小限制
            if (file.getSize() > MAX_FILE_SIZE) {
                return ResultGenerator.genFailedResult("文件大小超过限制（最大" + (MAX_FILE_SIZE / (1024 * 1024)) + "MB）");
            }

            List<HashResult> results = hashVerificationService.verifyHashFromFile(
                    file,
                    request.getHash(),
                    request.getIterations(),
                    request.getSalt()
            );

            // 筛选出匹配的结果
            List<HashResult> matches = results.stream()
                    .filter(HashResult::isMatched)
                    .collect(Collectors.toList());

            // 只返回匹配的算法名称
            if (!matches.isEmpty()) {
                // 创建简化的输出结构，只包含算法名和哈希值
                Map<String, String> matchedAlgorithms = new HashMap<>();
                for (HashResult result : matches) {
                    matchedAlgorithms.put(result.getAlgorithm(), result.getComputedHash());
                }
                return ResultGenerator.genOkResult(matchedAlgorithms);
            } else {
                return ResultGenerator.genFailedResult("没有找到匹配的哈希算法");
            }
        } catch (IOException e) {
            return ResultGenerator.genFailedResult("文件读取错误: " + e.getMessage());
        } catch (Exception e) {
            return ResultGenerator.genFailedResult("处理错误: " + e.getMessage());
        }
    }

    @GetMapping("/supported-algorithms")
    @ApiOperation(value = "获取支持的哈希算法列表")
    public Result<List<String>> getSupportedAlgorithms() {
        List<String> algorithms = java.util.Arrays.asList(
                "MD4", "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512",
                "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "RIPEMD160", "SM3"
        );
        return ResultGenerator.genOkResult(algorithms);
    }
}