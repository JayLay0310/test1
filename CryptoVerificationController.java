package com.bistu.tools.controller;

import com.bistu.tools.core.Result;
import com.bistu.tools.core.ResultGenerator;
import com.bistu.tools.dto.FileVerifyRequestDTO;
import com.bistu.tools.service.CryptoVerificationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;


import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 统一密码学验证控制器
 * 提供哈希、对称加密、非对称加密和数字签名的验证API
 */
@RestController
@RequestMapping("/api/crypto")
@Api(tags = "密码学验证接口")
public class CryptoVerificationController {

    private static final Logger logger = LoggerFactory.getLogger(CryptoVerificationController.class);
    private static final long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

    @Autowired
    private CryptoVerificationService cryptoService;

    @GetMapping("/supported-algorithms")
    @ApiOperation(value = "获取支持的算法信息", notes = "返回所有支持的密码学算法、模式和填充方式")
    public Result getSupportedAlgorithms() {
        Map<String, Object> algorithms = cryptoService.getSupportedAlgorithms();
        return ResultGenerator.genSuccessResult(algorithms);
    }

    @PostMapping("/generate-key")
    @ApiOperation(value = "生成密钥", notes = "为指定的加密算法生成密钥")
    public Result generateKey(@RequestBody Map<String, Object> request) {
        try {
            String algorithm = (String) request.get("algorithm");

            if (algorithm == null || algorithm.trim().isEmpty()) {
                return ResultGenerator.genFailResult("算法名称不能为空");
            }

            logger.info("正在为算法{}生成密钥", algorithm);
            Map<String, Object> keyResult = cryptoService.generateKey(algorithm, request);

            if (keyResult.containsKey("error")) {
                return ResultGenerator.genFailResult((String) keyResult.get("error"));
            }

            return ResultGenerator.genSuccessResult(keyResult);
        } catch (Exception e) {
            logger.error("密钥生成失败", e);
            return ResultGenerator.genFailResult("密钥生成失败: " + e.getMessage());
        }
    }

    @PostMapping("/hash/verify")
    @ApiOperation(value = "验证哈希值", notes = "计算哈希值并与预期结果比较，支持盐值和迭代")
    public Result verifyHash(@RequestBody Map<String, Object> request) {
        try {
            // 提取参数
            String algorithm = (String) request.get("algorithm");
            String input = (String) request.get("input");
            String inputFormat = (String) request.get("inputFormat");
            String hmacKey = (String) request.get("hmacKey");
            String salt = (String) request.get("salt");
            String saltPosition = (String) request.get("saltPosition");
            Integer customPosition = (Integer) request.get("customPosition");
            Integer iterations = (Integer) request.get("iterations");
            String expectedHash = (String) request.get("expectedHash");
            String hashFormat = (String) request.get("hashFormat");

            // 验证必要参数
            if (algorithm == null || algorithm.trim().isEmpty()) {
                return ResultGenerator.genFailResult("哈希算法名称不能为空");
            }

            if (input == null || input.trim().isEmpty()) {
                return ResultGenerator.genFailResult("输入数据不能为空");
            }

            logger.info("处理{}哈希验证请求 (迭代次数: {})", algorithm, iterations != null ? iterations : 1);
            Map<String, Object> result = cryptoService.verifyHash(
                    algorithm, input, inputFormat, hmacKey, salt, saltPosition,
                    customPosition, iterations, expectedHash, hashFormat);

            // 处理结果
            if (result.containsKey("error")) {
                return ResultGenerator.genFailResult((String) result.get("error"));
            }

            return ResultGenerator.genSuccessResult(result);
        } catch (Exception e) {
            logger.error("哈希验证失败", e);
            return ResultGenerator.genFailResult("哈希验证失败: " + e.getMessage());
        }
    }

    @PostMapping("/symmetric/verify")
    @ApiOperation(value = "验证对称加密", notes = "执行对称加密/解密并验证结果")
    public Result verifySymmetricCipher(@RequestBody Map<String, Object> request) {
        try {
            // 提取参数
            String algorithm = (String) request.get("algorithm");
            String operation = (String) request.get("operation");
            String input = (String) request.get("input");
            String inputFormat = (String) request.get("inputFormat");
            String key = (String) request.get("key");
            String iv = (String) request.get("iv");
            String mode = (String) request.get("mode");
            String padding = (String) request.get("padding");
            String expectedOutput = (String) request.get("expectedOutput");
            String expectedOutputFormat = (String) request.get("expectedOutputFormat");

            // 验证必要参数
            if (algorithm == null || algorithm.trim().isEmpty()) {
                return ResultGenerator.genFailResult("加密算法名称不能为空");
            }

            if (operation == null || operation.trim().isEmpty()) {
                return ResultGenerator.genFailResult("操作类型不能为空（ENCRYPT或DECRYPT）");
            }

            if (input == null || input.trim().isEmpty()) {
                return ResultGenerator.genFailResult("输入数据不能为空");
            }

            if (key == null || key.trim().isEmpty()) {
                return ResultGenerator.genFailResult("密钥不能为空");
            }

            logger.info("处理{}对称{}验证请求", algorithm, operation);
            Map<String, Object> result = cryptoService.verifySymmetricCipher(
                    algorithm, operation, input, inputFormat, key, iv,
                    mode, padding, expectedOutput, expectedOutputFormat);

            // 处理结果
            if (result.containsKey("error")) {
                return ResultGenerator.genFailResult((String) result.get("error"));
            }

            return ResultGenerator.genSuccessResult(result);
        } catch (Exception e) {
            logger.error("对称加密验证失败", e);
            return ResultGenerator.genFailResult("对称加密验证失败: " + e.getMessage());
        }
    }

    @PostMapping("/asymmetric/verify")
    @ApiOperation(value = "验证非对称加密", notes = "执行非对称加密/解密并验证结果")
    public Result verifyAsymmetricCipher(@RequestBody Map<String, Object> request) {
        try {
            // 提取参数
            String algorithm = (String) request.get("algorithm");
            String operation = (String) request.get("operation");
            String input = (String) request.get("input");
            String inputFormat = (String) request.get("inputFormat");
            String publicKey = (String) request.get("publicKey");
            String privateKey = (String) request.get("privateKey");
            String padding = (String) request.get("padding");
            String expectedOutput = (String) request.get("expectedOutput");
            String expectedOutputFormat = (String) request.get("expectedOutputFormat");

            @SuppressWarnings("unchecked")
            Map<String, Object> params = (Map<String, Object>) request.get("params");

            // 验证必要参数
            if (algorithm == null || algorithm.trim().isEmpty()) {
                return ResultGenerator.genFailResult("加密算法名称不能为空");
            }

            if (operation == null || operation.trim().isEmpty()) {
                return ResultGenerator.genFailResult("操作类型不能为空（ENCRYPT或DECRYPT）");
            }

            if (input == null || input.trim().isEmpty()) {
                return ResultGenerator.genFailResult("输入数据不能为空");
            }

            boolean isEncrypt = "ENCRYPT".equalsIgnoreCase(operation);

            if (isEncrypt && (publicKey == null || publicKey.trim().isEmpty())) {
                return ResultGenerator.genFailResult("加密操作需要提供公钥");
            }

            if (!isEncrypt && (privateKey == null || privateKey.trim().isEmpty())) {
                return ResultGenerator.genFailResult("解密操作需要提供私钥");
            }

            logger.info("处理{}非对称{}验证请求", algorithm, operation);
            Map<String, Object> result = cryptoService.verifyAsymmetricCipher(
                    algorithm, operation, input, inputFormat, publicKey, privateKey,
                    padding, params, expectedOutput, expectedOutputFormat);

            // 处理结果
            if (result.containsKey("error")) {
                return ResultGenerator.genFailResult((String) result.get("error"));
            }

            return ResultGenerator.genSuccessResult(result);
        } catch (Exception e) {
            logger.error("非对称加密验证失败", e);
            return ResultGenerator.genFailResult("非对称加密验证失败: " + e.getMessage());
        }
    }

    @PostMapping("/signature/verify")
    @ApiOperation(value = "验证数字签名", notes = "执行签名/验签操作并验证结果")
    public Result verifySignature(@RequestBody Map<String, Object> request) {
        try {
            // 提取参数
            String algorithm = (String) request.get("algorithm");
            String operation = (String) request.get("operation");
            String input = (String) request.get("input");
            String inputFormat = (String) request.get("inputFormat");
            String publicKey = (String) request.get("publicKey");
            String privateKey = (String) request.get("privateKey");
            String signAlgorithm = (String) request.get("signAlgorithm");
            String signature = (String) request.get("signature");
            String signatureFormat = (String) request.get("signatureFormat");

            @SuppressWarnings("unchecked")
            Map<String, Object> params = (Map<String, Object>) request.get("params");

            // 验证必要参数
            if (algorithm == null || algorithm.trim().isEmpty()) {
                return ResultGenerator.genFailResult("签名算法名称不能为空");
            }

            if (operation == null || operation.trim().isEmpty()) {
                return ResultGenerator.genFailResult("操作类型不能为空（SIGN或VERIFY）");
            }

            if (input == null || input.trim().isEmpty()) {
                return ResultGenerator.genFailResult("输入数据不能为空");
            }

            boolean isSign = "SIGN".equalsIgnoreCase(operation);

            if (isSign && (privateKey == null || privateKey.trim().isEmpty())) {
                return ResultGenerator.genFailResult("签名操作需要提供私钥");
            }

            if (!isSign && (publicKey == null || publicKey.trim().isEmpty())) {
                return ResultGenerator.genFailResult("验签操作需要提供公钥");
            }

            if (!isSign && (signature == null || signature.trim().isEmpty())) {
                return ResultGenerator.genFailResult("验签操作需要提供签名");
            }

            logger.info("处理{}数字签名{}验证请求", algorithm, operation);
            Map<String, Object> result = cryptoService.verifySignature(
                    algorithm, operation, input, inputFormat, publicKey, privateKey,
                    signAlgorithm, signature, signatureFormat, params);

            // 处理结果
            if (result.containsKey("error")) {
                return ResultGenerator.genFailResult((String) result.get("error"));
            }

            return ResultGenerator.genSuccessResult(result);
        } catch (Exception e) {
            logger.error("数字签名验证失败", e);
            return ResultGenerator.genFailResult("数字签名验证失败: " + e.getMessage());
        }
    }
    @PostMapping(value = "/file/verify", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @ApiOperation(value = "验证文件操作", notes = "对文件执行密码学操作并验证结果")
    public Result verifyFile(@ModelAttribute FileVerifyRequestDTO request) {
        logger.info("接收到文件{}操作请求，算法：{}", request.getOperation(), request.getAlgorithm());

        try {
            // 验证文件
            if (request.getFile() == null || request.getFile().isEmpty()) {
                return ResultGenerator.genFailResult("请提供文件");
            }

            // 检查文件大小限制
            if (request.getFile().getSize() > MAX_FILE_SIZE) {
                return ResultGenerator.genFailResult("文件大小超过限制（最大" + (MAX_FILE_SIZE / 1024 / 1024) + "MB）");
            }

            // 解析其他参数
            Map<String, Object> params = new HashMap<>();
            if (request.getParamsJson() != null && !request.getParamsJson().trim().isEmpty()) {
                try {
                    // 使用Spring自带的JSON解析器，保持与原代码一致
                    params = new org.springframework.boot.json.JacksonJsonParser().parseMap(request.getParamsJson());
                } catch (Exception e) {
                    logger.error("参数JSON解析错误", e);
                    return ResultGenerator.genFailResult("参数解析错误: " + e.getMessage());
                }
            }

            // 对于哈希操作，确保参数中包含盐值和迭代次数信息，保持与原代码一致的行为
            if ("HASH".equalsIgnoreCase(request.getOperation())) {
                if (!params.containsKey("iterations")) {
                    params.put("iterations", 1);  // 默认迭代次数为1
                }
            }

            // 调用服务
            Map<String, Object> result = cryptoService.verifyFile(
                    request.getOperation(), request.getAlgorithm(), request.getFile(),
                    request.getFileFormat(), params);

            // 处理结果
            if (result.containsKey("error")) {
                return ResultGenerator.genFailResult((String) result.get("error"));
            }

            // 移除binary字段，避免在JSON响应中包含大量二进制数据
            result.remove("binary");

            return ResultGenerator.genSuccessResult(result);
        } catch (IOException e) {
            logger.error("文件读取错误", e);
            return ResultGenerator.genFailResult("文件读取错误: " + e.getMessage());
        } catch (Exception e) {
            logger.error("文件处理失败", e);
            return ResultGenerator.genFailResult("文件处理失败: " + e.getMessage());
        }
    }

}
