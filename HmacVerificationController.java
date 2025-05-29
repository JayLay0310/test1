package com.bistu.tools.controller;

import com.bistu.tools.core.Result;
import com.bistu.tools.core.ResultGenerator;
import com.bistu.tools.service.HmacVerificationService;
import io.swagger.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * HMAC验证控制器
 */
@RestController
@RequestMapping("/api/hmac")
@Api(tags = "HMAC验证接口")
public class HmacVerificationController {

    private static final Logger logger = LoggerFactory.getLogger(HmacVerificationController.class);
    private static final int MAX_ITERATIONS = 10000;
    private static final long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

    @Autowired
    private HmacVerificationService hmacVerificationService;

    @PostMapping("/verify")
    @ApiOperation(value = "验证HMAC值", notes = "输入明文、密钥和HMAC值，检查是否匹配已知算法。可以指定各项输入的格式。")
    public Result verifyHmac(@RequestBody Map<String, Object> request) {
        try {
            // 从请求中提取基本参数
            String plaintext = (String) request.get("plaintext");
            String key = (String) request.get("key");
            String hmac = (String) request.get("hmac");

            // 获取格式参数，默认为TEXT和HEX
            String plaintextFormat = request.get("plaintextFormat") != null ?
                    (String) request.get("plaintextFormat") : "TEXT";
            String keyFormat = request.get("keyFormat") != null ?
                    (String) request.get("keyFormat") : "TEXT";
            String hmacFormat = request.get("hmacFormat") != null ?
                    (String) request.get("hmacFormat") : "HEX";

            // 获取附加参数
            Integer iterations = request.get("iterations") != null ?
                    (Integer) request.get("iterations") : 1;
            String salt = request.get("salt") != null ? (String) request.get("salt") : "";
            String saltPosition = request.get("saltPosition") != null ?
                    (String) request.get("saltPosition") : "AFTER";

            logger.debug("接收到HMAC验证请求 - HMAC值: {}, HMAC格式: {}, 明文格式: {}, 密钥格式: {}, 迭代次数: {}, 盐值位置: {}",
                    hmac, hmacFormat, plaintextFormat, keyFormat, iterations, saltPosition);

            // 验证输入参数
            if (plaintext == null || plaintext.trim().isEmpty()) {
                return ResultGenerator.genFailResult("明文不能为空");
            }

            if (key == null || key.trim().isEmpty()) {
                return ResultGenerator.genFailResult("密钥不能为空");
            }

            if (hmac == null || hmac.trim().isEmpty()) {
                return ResultGenerator.genFailResult("HMAC值不能为空");
            }

            if (iterations < 1 || iterations > MAX_ITERATIONS) {
                return ResultGenerator.genFailResult("迭代次数必须在1至" + MAX_ITERATIONS + "之间");
            }

            // 验证格式参数
            if (!isValidFormat(plaintextFormat)) {
                return ResultGenerator.genFailResult("无效的明文格式，支持的格式: TEXT, HEX, BASE64");
            }

            if (!isValidFormat(keyFormat)) {
                return ResultGenerator.genFailResult("无效的密钥格式，支持的格式: TEXT, HEX, BASE64");
            }

            if (!isValidHashFormat(hmacFormat)) {
                return ResultGenerator.genFailResult("无效的HMAC格式，支持的格式: HEX, BASE64");
            }

            // 验证盐值位置
            if (!"BEFORE".equalsIgnoreCase(saltPosition) && !"AFTER".equalsIgnoreCase(saltPosition)) {
                return ResultGenerator.genFailResult("无效的盐值位置，支持的值: BEFORE, AFTER");
            }

            logger.info("处理HMAC验证 - 明文长度: {} 字符, 密钥长度: {} 字符, 明文格式: {}, 密钥格式: {}, HMAC格式: {}",
                    plaintext.length(), key.length(), plaintextFormat, keyFormat, hmacFormat);

            // 调用Service进行验证
            Map<String, Map<String, String>> results = hmacVerificationService.verifyHmac(
                    plaintext, plaintextFormat, key, keyFormat, hmac, hmacFormat,
                    salt, saltPosition, iterations);

            // 检查是否有匹配结果
            if (!results.get("hex").isEmpty()) {
                Map<String, Object> response = new HashMap<>();
                response.put("matches", results.get("hex"));
                response.put("matchesBase64", results.get("base64"));
                response.put("count", results.get("hex").size());

                logger.info("HMAC验证成功 - 找到 {} 个匹配算法", results.get("hex").size());
                return ResultGenerator.genSuccessResult(response);
            } else {
                logger.info("HMAC验证 - 未找到匹配的算法");
                return ResultGenerator.genFailResult("没有找到匹配的HMAC算法");
            }
        } catch (Exception e) {
            logger.error("HMAC验证处理错误", e);
            return ResultGenerator.genFailResult("处理错误: " + e.getMessage());
        }
    }

    @PostMapping(value = "/verify-file", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @ApiOperation(value = "验证文件HMAC值", notes = "上传文件并验证其HMAC值。可以指定密钥和HMAC值的格式。")
    public Result verifyFileHmac(
            @ApiParam(value = "要验证的文件", required = true)
            @RequestParam(value = "file", required = true) MultipartFile file,

            @ApiParam(value = "密钥", required = true)
            @RequestParam(value = "key", required = true) String key,

            @ApiParam(value = "密钥格式 (TEXT, HEX 或 BASE64)", defaultValue = "TEXT")
            @RequestParam(value = "keyFormat", required = false, defaultValue = "TEXT") String keyFormat,

            @ApiParam(value = "HMAC值", required = true)
            @RequestParam(value = "hmac", required = true) String hmac,

            @ApiParam(value = "HMAC值格式 (HEX 或 BASE64)", defaultValue = "HEX")
            @RequestParam(value = "hmacFormat", required = false, defaultValue = "HEX") String hmacFormat,

            @ApiParam(value = "盐值", defaultValue = "")
            @RequestParam(value = "salt", required = false, defaultValue = "") String salt,

            @ApiParam(value = "盐值位置 (BEFORE 或 AFTER)", defaultValue = "AFTER")
            @RequestParam(value = "saltPosition", required = false, defaultValue = "AFTER") String saltPosition,

            @ApiParam(value = "迭代次数", defaultValue = "1")
            @RequestParam(value = "iterations", required = false, defaultValue = "1") int iterations) {

        logger.debug("接收到文件HMAC验证请求 - HMAC值: {}, HMAC格式: {}, 密钥格式: {}, 迭代次数: {}, 盐值位置: {}",
                hmac, hmacFormat, keyFormat, iterations, saltPosition);

        try {
            // 验证输入参数
            if (file == null || file.isEmpty()) {
                return ResultGenerator.genFailResult("请提供文件");
            }

            if (key == null || key.trim().isEmpty()) {
                return ResultGenerator.genFailResult("密钥不能为空");
            }

            if (hmac == null || hmac.trim().isEmpty()) {
                return ResultGenerator.genFailResult("HMAC值不能为空");
            }

            if (iterations < 1 || iterations > MAX_ITERATIONS) {
                return ResultGenerator.genFailResult("迭代次数必须在1至" + MAX_ITERATIONS + "之间");
            }

            // 验证格式参数
            if (!isValidFormat(keyFormat)) {
                return ResultGenerator.genFailResult("无效的密钥格式，支持的格式: TEXT, HEX, BASE64");
            }

            if (!isValidHashFormat(hmacFormat)) {
                return ResultGenerator.genFailResult("无效的HMAC格式，支持的格式: HEX, BASE64");
            }

            // 验证盐值位置
            if (!"BEFORE".equalsIgnoreCase(saltPosition) && !"AFTER".equalsIgnoreCase(saltPosition)) {
                return ResultGenerator.genFailResult("无效的盐值位置，支持的值: BEFORE, AFTER");
            }

            // 检查文件大小限制
            if (file.getSize() > MAX_FILE_SIZE) {
                return ResultGenerator.genFailResult("文件大小超过限制（最大" + (MAX_FILE_SIZE / (1024 * 1024)) + "MB）");
            }

            logger.info("处理文件HMAC验证 - 文件大小: {} 字节, 密钥长度: {} 字符, 密钥格式: {}, HMAC格式: {}",
                    file.getSize(), key.length(), keyFormat, hmacFormat);

            // 调用Service进行验证
            Map<String, Map<String, String>> results = hmacVerificationService.verifyHmacFromFile(
                    file, key, keyFormat, hmac, hmacFormat, salt, saltPosition, iterations);

            // 检查是否有匹配结果
            if (!results.get("hex").isEmpty()) {
                Map<String, Object> response = new HashMap<>();
                response.put("matches", results.get("hex"));
                response.put("matchesBase64", results.get("base64"));
                response.put("count", results.get("hex").size());

                logger.info("文件HMAC验证成功 - 找到 {} 个匹配算法", results.get("hex").size());
                return ResultGenerator.genSuccessResult(response);
            } else {
                logger.info("文件HMAC验证 - 未找到匹配的算法");
                return ResultGenerator.genFailResult("没有找到匹配的HMAC算法");
            }
        } catch (IOException e) {
            logger.error("文件读取错误", e);
            return ResultGenerator.genFailResult("文件读取错误: " + e.getMessage());
        } catch (Exception e) {
            logger.error("文件HMAC验证处理错误", e);
            return ResultGenerator.genFailResult("处理错误: " + e.getMessage());
        }
    }

    @GetMapping("/supported-algorithms")
    @ApiOperation(value = "获取支持的HMAC算法列表")
    public Result<List<String>> getSupportedAlgorithms() {
        List<String> algorithms = hmacVerificationService.getSupportedAlgorithms();
        return ResultGenerator.genSuccessResult(algorithms);
    }

    /**
     * 检查输入格式是否有效
     * @param format 格式
     * @return 是否有效
     */
    private boolean isValidFormat(String format) {
        if (format == null) {
            return false;
        }
        String upperFormat = format.toUpperCase();
        return "TEXT".equals(upperFormat) || "HEX".equals(upperFormat) || "BASE64".equals(upperFormat);
    }

    /**
     * 检查哈希/HMAC格式是否有效
     * @param format 格式
     * @return 是否有效
     */
    private boolean isValidHashFormat(String format) {
        if (format == null) {
            return false;
        }
        String upperFormat = format.toUpperCase();
        return "HEX".equals(upperFormat) || "BASE64".equals(upperFormat);
    }
}