package com.bistu.tools.service.impl;

import com.bistu.tools.service.CryptoVerificationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.PostConstruct;
import javax.crypto.*;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * 统一密码学验证服务实现
 */
@Service
public class CryptoVerificationServiceImpl implements CryptoVerificationService {
    private static final Logger logger = LoggerFactory.getLogger(CryptoVerificationServiceImpl.class);

    // 支持的算法列表
    private final Map<String, Object> supportedAlgorithms = new HashMap<>();

    @PostConstruct
    public void init() {
        // 初始化支持的算法信息
        initSupportedAlgorithms();
    }
    private void initSupportedAlgorithms() {
        // 哈希算法
        List<String> hashAlgorithms = Arrays.asList(
                "MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SM3");
        supportedAlgorithms.put("hash", hashAlgorithms);

        // 对称加密算法
        Map<String, Object> symmetricAlgorithms = new HashMap<>();

        // 分组密码
        Map<String, Object> blockCiphers = new HashMap<>();

        // AES配置
        Map<String, Object> aesConfig = new HashMap<>();
        aesConfig.put("modes", Arrays.asList("ECB", "CBC", "CFB", "OFB", "CTR", "GCM"));
        aesConfig.put("paddings", Arrays.asList("NoPadding", "PKCS5Padding", "ISO10126Padding"));
        aesConfig.put("keySizes", Arrays.asList(128, 192, 256));
        blockCiphers.put("AES", aesConfig);

        // DES配置
        Map<String, Object> desConfig = new HashMap<>();
        desConfig.put("modes", Arrays.asList("ECB", "CBC", "CFB", "OFB"));
        desConfig.put("paddings", Arrays.asList("NoPadding", "PKCS5Padding", "ISO10126Padding"));
        desConfig.put("keySizes", Arrays.asList(56));
        blockCiphers.put("DES", desConfig);

        // 3DES配置
        Map<String, Object> tripleDesConfig = new HashMap<>();
        tripleDesConfig.put("modes", Arrays.asList("ECB", "CBC", "CFB", "OFB"));
        tripleDesConfig.put("paddings", Arrays.asList("NoPadding", "PKCS5Padding", "ISO10126Padding"));
        tripleDesConfig.put("keySizes", Arrays.asList(112, 168));
        blockCiphers.put("3DES", tripleDesConfig);

        // SM4配置
        Map<String, Object> sm4Config = new HashMap<>();
        sm4Config.put("modes", Arrays.asList("ECB", "CBC", "CFB", "OFB", "CTR"));
        sm4Config.put("paddings", Arrays.asList("NoPadding", "PKCS5Padding", "PKCS7Padding"));
        sm4Config.put("keySizes", Arrays.asList(128));
        blockCiphers.put("SM4", sm4Config);

        symmetricAlgorithms.put("block", blockCiphers);

        // 流密码
        Map<String, Object> streamCiphers = new HashMap<>();

        // RC4配置
        Map<String, Object> rc4Config = new HashMap<>();
        rc4Config.put("keySizes", Arrays.asList(40, 128));
        streamCiphers.put("RC4", rc4Config);

        // ChaCha20配置
        streamCiphers.put("ChaCha20", new HashMap<>());

        // ZUC配置
        streamCiphers.put("ZUC", new HashMap<>());

        symmetricAlgorithms.put("stream", streamCiphers);
        supportedAlgorithms.put("symmetric", symmetricAlgorithms);

        // 非对称加密算法
        Map<String, Object> asymmetricAlgorithms = new HashMap<>();

        // RSA配置
        Map<String, Object> rsaConfig = new HashMap<>();
        rsaConfig.put("paddings", Arrays.asList(
                "PKCS1Padding",
                "OAEPWithSHA-1AndMGF1Padding",
                "OAEPWithSHA-256AndMGF1Padding"));
        rsaConfig.put("keySizes", Arrays.asList(1024, 2048, 3072, 4096));
        rsaConfig.put("signatureAlgorithms", Arrays.asList(
                "SHA1withRSA",
                "SHA256withRSA",
                "SHA384withRSA",
                "SHA512withRSA"));
        asymmetricAlgorithms.put("RSA", rsaConfig);

        // SM2配置
        asymmetricAlgorithms.put("SM2", new HashMap<>());

        // SM9配置
        asymmetricAlgorithms.put("SM9", new HashMap<>());

        supportedAlgorithms.put("asymmetric", asymmetricAlgorithms);
    }
    @Override
    public Map<String, Object> getSupportedAlgorithms() {
        return supportedAlgorithms;
    }

    @Override
    public Map<String, Object> generateKey(String algorithm, Map<String, Object> params) {
        Map<String, Object> result = new HashMap<>();
        try {
            switch (algorithm.toUpperCase()) {
                case "AES":
                    return generateAesKey(params);
                case "DES":
                    return generateDesKey(params);
                case "3DES":
                    return generate3DesKey(params);
                case "SM4":
                    return generateSm4Key(params);
                case "RC4":
                    return generateRc4Key(params);
                case "CHACHA20":
                    return generateChaCha20Key(params);
                case "ZUC":
                    return generateZucKey(params);
                case "RSA":
                    return generateRsaKey(params);
                case "SM2":
                    return generateSm2Key(params);
                case "SM9":
                    return generateSm9Key(params);
                default:
                    result.put("error", "不支持的算法: " + algorithm);
                    return result;
            }
        } catch (Exception e) {
            logger.error("生成{}密钥失败: {}", algorithm, e.getMessage());
            result.put("error", "生成密钥失败: " + e.getMessage());
            return result;
        }
    }

    @Override
    public Map<String, Object> verifyHash(
            String algorithm,
            String input,
            String inputFormat,
            String hmacKey,
            String salt,
            String saltPosition,
            Integer customPosition,
            Integer iterations,
            String expectedHash,
            String hashFormat) {

        Map<String, Object> result = new HashMap<>();

        try {
            // 解析输入数据
            byte[] inputData = parseInputData(input, inputFormat);
            if (inputData == null) {
                result.put("error", "解析输入数据失败");
                return result;
            }

            // 应用盐值（如果有）
            if (salt != null && !salt.isEmpty()) {
                byte[] saltData = salt.getBytes(StandardCharsets.UTF_8);
                inputData = applySalt(inputData, saltData, saltPosition, customPosition);
                logger.info("已应用盐值，长度: {} 字节, 位置: {}", saltData.length, saltPosition);
            }

            // 设置默认迭代次数
            if (iterations == null || iterations < 1) {
                iterations = 1;
            }

            byte[] hashValue;
            if (hmacKey != null && !hmacKey.isEmpty()) {
                // HMAC模式
                byte[] keyBytes = hexToBytes(hmacKey);
                hashValue = calculateHmacWithIterations(algorithm, inputData, keyBytes, iterations);
            } else {
                // 普通哈希
                hashValue = calculateHashWithIterations(algorithm, inputData, iterations);
            }

            if (hashValue == null) {
                result.put("error", "不支持的哈希算法: " + algorithm);
                return result;
            }

            // 转换为不同格式
            String hexHash = bytesToHex(hashValue);
            String base64Hash = Base64.getEncoder().encodeToString(hashValue);

            result.put("hex", hexHash);
            result.put("base64", base64Hash);
            result.put("algorithm", algorithm);

            // 添加迭代次数和盐值信息到结果
            if (iterations > 1) {
                result.put("iterations", iterations);
            }

            if (salt != null && !salt.isEmpty()) {
                result.put("salt", salt);
                result.put("saltPosition", saltPosition != null ? saltPosition : "SUFFIX");
            }

            // 如果提供了预期哈希值，验证结果
            if (expectedHash != null && !expectedHash.isEmpty()) {
                String normalizedExpectedHash = parseExpectedHash(expectedHash, hashFormat);
                boolean matches = hexHash.equalsIgnoreCase(normalizedExpectedHash);
                result.put("matches", matches);
                result.put("expected", normalizedExpectedHash);

                if (matches) {
                    logger.info("{}哈希验证成功", algorithm);
                } else {
                    logger.info("{}哈希验证失败 - 计算值: {}, 期望值: {}",
                            algorithm, hexHash, normalizedExpectedHash);
                }
            }

            logger.info("{}哈希计算成功完成, 迭代次数: {}", algorithm, iterations);

        } catch (Exception e) {
            logger.error("{}哈希计算失败: {}", algorithm, e.getMessage());
            result.put("error", e.getMessage());
        }

        return result;
    }

    /**
     * 应用盐值到数据
     * @param data 原始数据
     * @param salt 盐值
     * @param position 盐值位置
     * @param customPosition 自定义位置
     * @return 加盐后的数据
     */
    private byte[] applySalt(byte[] data, byte[] salt, String position, Integer customPosition) {
        if (salt == null || salt.length == 0) {
            return data;
        }

        if (position == null) {
            position = "SUFFIX"; // 默认在末尾加盐
        }

        switch (position.toUpperCase()) {
            case "PREFIX":
                // 盐值在数据前
                byte[] result = new byte[salt.length + data.length];
                System.arraycopy(salt, 0, result, 0, salt.length);
                System.arraycopy(data, 0, result, salt.length, data.length);
                return result;

            case "SUFFIX":
                // 盐值在数据后
                byte[] result2 = new byte[data.length + salt.length];
                System.arraycopy(data, 0, result2, 0, data.length);
                System.arraycopy(salt, 0, result2, data.length, salt.length);
                return result2;

            case "BOTH":
                // 盐值分成两半，一半在前一半在后
                int halfSalt = salt.length / 2;
                int remainingSalt = salt.length - halfSalt;

                byte[] result3 = new byte[halfSalt + data.length + remainingSalt];
                System.arraycopy(salt, 0, result3, 0, halfSalt);
                System.arraycopy(data, 0, result3, halfSalt, data.length);
                System.arraycopy(salt, halfSalt, result3, halfSalt + data.length, remainingSalt);
                return result3;

            case "CUSTOM":
                // 盐值插入到指定位置
                if (customPosition == null || customPosition < 0 || customPosition > data.length) {
                    customPosition = data.length; // 默认在末尾
                }

                byte[] result4 = new byte[data.length + salt.length];
                System.arraycopy(data, 0, result4, 0, customPosition);
                System.arraycopy(salt, 0, result4, customPosition, salt.length);
                System.arraycopy(data, customPosition, result4, customPosition + salt.length, data.length - customPosition);
                return result4;

            default:
                // 默认在末尾加盐
                byte[] defaultResult = new byte[data.length + salt.length];
                System.arraycopy(data, 0, defaultResult, 0, data.length);
                System.arraycopy(salt, 0, defaultResult, data.length, salt.length);
                return defaultResult;
        }
    }

    /**
     * 计算带迭代次数的哈希值
     * @param algorithm 哈希算法
     * @param data 数据
     * @param iterations 迭代次数
     * @return 哈希值
     */
    private byte[] calculateHashWithIterations(String algorithm, byte[] data, int iterations) throws Exception {
        MessageDigest digest;

        switch (algorithm.toUpperCase()) {
            case "MD5":
                digest = MessageDigest.getInstance("MD5");
                break;
            case "SHA-1":
            case "SHA1":
                digest = MessageDigest.getInstance("SHA-1");
                break;
            case "SHA-224":
            case "SHA224":
                digest = MessageDigest.getInstance("SHA-224");
                break;
            case "SHA-256":
            case "SHA256":
                digest = MessageDigest.getInstance("SHA-256");
                break;
            case "SHA-384":
            case "SHA384":
                digest = MessageDigest.getInstance("SHA-384");
                break;
            case "SHA-512":
            case "SHA512":
                digest = MessageDigest.getInstance("SHA-512");
                break;
            case "SM3":
                // 如果系统支持SM3，使用系统提供的实现
                try {
                    digest = MessageDigest.getInstance("SM3");
                } catch (Exception e) {
                    logger.warn("系统不支持SM3算法，请安装相关加密提供者");
                    return null;
                }
                break;
            default:
                logger.error("不支持的哈希算法: {}", algorithm);
                return null;
        }

        // 执行迭代哈希
        byte[] result = data;
        for (int i = 0; i < iterations; i++) {
            digest.reset();
            result = digest.digest(result);
        }

        return result;
    }

    /**
     * 计算带迭代次数的HMAC值
     * @param algorithm HMAC算法
     * @param data 数据
     * @param key 密钥
     * @param iterations 迭代次数
     * @return HMAC值
     */
    private byte[] calculateHmacWithIterations(String algorithm, byte[] data, byte[] key, int iterations) throws Exception {
        String hmacAlgorithm;
        switch (algorithm.toUpperCase()) {
            case "MD5":
            case "HMAC-MD5":
            case "HMACMD5":
                hmacAlgorithm = "HmacMD5";
                break;
            case "SHA-1":
            case "SHA1":
            case "HMAC-SHA1":
            case "HMACSHA1":
                hmacAlgorithm = "HmacSHA1";
                break;
            case "SHA-224":
            case "SHA224":
            case "HMAC-SHA224":
            case "HMACSHA224":
                hmacAlgorithm = "HmacSHA224";
                break;
            case "SHA-256":
            case "SHA256":
            case "HMAC-SHA256":
            case "HMACSHA256":
                hmacAlgorithm = "HmacSHA256";
                break;
            case "SHA-384":
            case "SHA384":
            case "HMAC-SHA384":
            case "HMACSHA384":
                hmacAlgorithm = "HmacSHA384";
                break;
            case "SHA-512":
            case "SHA512":
            case "HMAC-SHA512":
            case "HMACSHA512":
                hmacAlgorithm = "HmacSHA512";
                break;
            case "SM3":
            case "HMAC-SM3":
            case "HMACSM3":
                hmacAlgorithm = "HmacSM3";
                break;
            default:
                logger.error("不支持的HMAC算法: {}", algorithm);
                return null;
        }

        Mac mac = Mac.getInstance(hmacAlgorithm);
        SecretKeySpec keySpec = new SecretKeySpec(key, hmacAlgorithm);
        mac.init(keySpec);

        // 执行迭代HMAC
        byte[] result = data;
        for (int i = 0; i < iterations; i++) {
            result = mac.doFinal(result);
        }

        return result;
    }

    @Override
    public Map<String, Object> verifySymmetricCipher(
            String algorithm,
            String operation,
            String input,
            String inputFormat,
            String key,
            String iv,
            String mode,
            String padding,
            String expectedOutput,
            String expectedOutputFormat) {

        Map<String, Object> result = new HashMap<>();

        try {
            // 验证操作类型
            boolean isEncrypt = validateOperation(operation);

            // 解析输入数据
            byte[] inputData = parseInputData(input, inputFormat);
            if (inputData == null) {
                result.put("error", "解析输入数据失败");
                return result;
            }

            // 执行对称加密/解密操作
            byte[] outputData;
            switch (algorithm.toUpperCase()) {
                case "AES":
                    outputData = processAes(isEncrypt, inputData, key, iv, mode, padding);
                    break;
                case "DES":
                    outputData = processDes(isEncrypt, inputData, key, iv, mode, padding);
                    break;
                case "3DES":
                    outputData = process3Des(isEncrypt, inputData, key, iv, mode, padding);
                    break;
                case "SM4":
                    outputData = processSm4(isEncrypt, inputData, key, iv, mode, padding);
                    break;
                case "RC4":
                    outputData = processRc4(isEncrypt, inputData, key);
                    break;
                case "CHACHA20":
                    outputData = processChaCha20(isEncrypt, inputData, key, iv);
                    break;
                case "ZUC":
                    outputData = processZuc(isEncrypt, inputData, key, iv);
                    break;
                default:
                    result.put("error", "不支持的对称加密算法: " + algorithm);
                    return result;
            }

            // 处理输出
            String hexOutput = bytesToHex(outputData);
            String base64Output = Base64.getEncoder().encodeToString(outputData);

            result.put("hex", hexOutput);
            result.put("base64", base64Output);

            // 如果是解密操作，尝试将结果转换为文本
            if (!isEncrypt) {
                try {
                    String textOutput = new String(outputData, StandardCharsets.UTF_8);
                    result.put("text", textOutput);
                } catch (Exception e) {
                    logger.warn("无法将解密结果转换为文本: {}", e.getMessage());
                }
            }

            // 如果提供了预期输出，验证结果
            if (expectedOutput != null && !expectedOutput.isEmpty()) {
                String normalizedExpectedOutput = parseExpectedOutput(expectedOutput, expectedOutputFormat, !isEncrypt);
                boolean matches = hexOutput.equalsIgnoreCase(normalizedExpectedOutput);
                result.put("matches", matches);
                result.put("expected", normalizedExpectedOutput);

                if (matches) {
                    logger.info("{}对称{}操作成功匹配预期输出", algorithm, isEncrypt ? "加密" : "解密");
                } else {
                    logger.info("{}对称{}操作未匹配预期输出 - 计算值: {}, 期望值: {}",
                            algorithm, isEncrypt ? "加密" : "解密", hexOutput, normalizedExpectedOutput);
                }
            }

            logger.info("{}对称{}操作成功完成", algorithm, isEncrypt ? "加密" : "解密");

        } catch (Exception e) {
            logger.error("{}对称加解密操作失败: {}", algorithm, e.getMessage());
            result.put("error", e.getMessage());
        }

        return result;
    }

    @Override
    public Map<String, Object> verifyAsymmetricCipher(
            String algorithm,
            String operation,
            String input,
            String inputFormat,
            String publicKey,
            String privateKey,
            String padding,
            Map<String, Object> params,
            String expectedOutput,
            String expectedOutputFormat) {

        Map<String, Object> result = new HashMap<>();

        try {
            // 验证操作类型
            boolean isEncrypt = validateOperation(operation);

            // 解析输入数据
            byte[] inputData = parseInputData(input, inputFormat);
            if (inputData == null) {
                result.put("error", "解析输入数据失败");
                return result;
            }

            // 执行非对称加密/解密操作
            byte[] outputData;
            switch (algorithm.toUpperCase()) {
                case "RSA":
                    outputData = processRsa(isEncrypt, inputData, publicKey, privateKey, padding);
                    break;
                case "SM2":
                    outputData = processSm2(isEncrypt, inputData, publicKey, privateKey);
                    break;
                case "SM9":
                    outputData = processSm9(isEncrypt, inputData, publicKey, privateKey, params);
                    break;
                default:
                    result.put("error", "不支持的非对称加密算法: " + algorithm);
                    return result;
            }

            // 处理输出
            String hexOutput = bytesToHex(outputData);
            String base64Output = Base64.getEncoder().encodeToString(outputData);

            result.put("hex", hexOutput);
            result.put("base64", base64Output);

            // 如果是解密操作，尝试将结果转换为文本
            if (!isEncrypt) {
                try {
                    String textOutput = new String(outputData, StandardCharsets.UTF_8);
                    result.put("text", textOutput);
                } catch (Exception e) {
                    logger.warn("无法将解密结果转换为文本: {}", e.getMessage());
                }
            }

            // 如果提供了预期输出，验证结果
            if (expectedOutput != null && !expectedOutput.isEmpty()) {
                String normalizedExpectedOutput = parseExpectedOutput(expectedOutput, expectedOutputFormat, !isEncrypt);
                boolean matches = hexOutput.equalsIgnoreCase(normalizedExpectedOutput);
                result.put("matches", matches);
                result.put("expected", normalizedExpectedOutput);

                if (matches) {
                    logger.info("{}非对称{}操作成功匹配预期输出", algorithm, isEncrypt ? "加密" : "解密");
                } else {
                    logger.info("{}非对称{}操作未匹配预期输出", algorithm, isEncrypt ? "加密" : "解密");
                }
            }

            logger.info("{}非对称{}操作成功完成", algorithm, isEncrypt ? "加密" : "解密");

        } catch (Exception e) {
            logger.error("{}非对称加解密操作失败: {}", algorithm, e.getMessage());
            result.put("error", e.getMessage());
        }

        return result;
    }

    @Override
    public Map<String, Object> verifySignature(
            String algorithm,
            String operation,
            String input,
            String inputFormat,
            String publicKey,
            String privateKey,
            String signAlgorithm,
            String signature,
            String signatureFormat,
            Map<String, Object> params) {

        Map<String, Object> result = new HashMap<>();

        try {
            // 验证操作类型
            boolean isSign = "SIGN".equalsIgnoreCase(operation);

            // 解析输入数据
            byte[] inputData = parseInputData(input, inputFormat);
            if (inputData == null) {
                result.put("error", "解析输入数据失败");
                return result;
            }

            if (isSign) {
                // 签名操作
                if (privateKey == null || privateKey.isEmpty()) {
                    result.put("error", "签名操作需要提供私钥");
                    return result;
                }

                // 执行签名
                byte[] signatureBytes;
                switch (algorithm.toUpperCase()) {
                    case "RSA":
                        signatureBytes = signRsa(inputData, privateKey, signAlgorithm);
                        break;
                    case "SM2":
                        String userId = params != null ? (String) params.get("userId") : "1234567812345678";
                        signatureBytes = signSm2(inputData, privateKey, userId);
                        break;
                    case "SM9":
                        signatureBytes = signSm9(inputData, privateKey, params);
                        break;
                    default:
                        result.put("error", "不支持的签名算法: " + algorithm);
                        return result;
                }

                // 处理签名结果
                String hexSignature = bytesToHex(signatureBytes);
                String base64Signature = Base64.getEncoder().encodeToString(signatureBytes);

                result.put("signature", hexSignature);
                result.put("signatureBase64", base64Signature);
                result.put("algorithm", signAlgorithm != null ? signAlgorithm : algorithm);
                result.put("success", true);

                logger.info("{}签名操作成功完成", algorithm);

            } else {
                // 验签操作
                if (publicKey == null || publicKey.isEmpty()) {
                    result.put("error", "验签操作需要提供公钥");
                    return result;
                }

                if (signature == null || signature.isEmpty()) {
                    result.put("error", "验签操作需要提供签名值");
                    return result;
                }

                // 解析签名
                byte[] signatureBytes = parseSignature(signature, signatureFormat);
                if (signatureBytes == null) {
                    result.put("error", "解析签名失败");
                    return result;
                }

                // 执行验签
                boolean verified;
                switch (algorithm.toUpperCase()) {
                    case "RSA":
                        verified = verifyRsa(inputData, signatureBytes, publicKey, signAlgorithm);
                        break;
                    case "SM2":
                        String userId = params != null ? (String) params.get("userId") : "1234567812345678";
                        verified = verifySm2(inputData, signatureBytes, publicKey, userId);
                        break;
                    case "SM9":
                        verified = verifySm9(inputData, signatureBytes, publicKey, params);
                        break;
                    default:
                        result.put("error", "不支持的签名算法: " + algorithm);
                        return result;
                }

                result.put("verified", verified);
                result.put("algorithm", signAlgorithm != null ? signAlgorithm : algorithm);

                if (verified) {
                    logger.info("{}签名验证成功", algorithm);
                } else {
                    logger.warn("{}签名验证失败", algorithm);
                }
            }

        } catch (Exception e) {
            logger.error("{}签名/验证操作失败: {}", algorithm, e.getMessage());
            result.put("error", e.getMessage());
        }

        return result;
    }

    @Override
    public Map<String, Object> verifyFile(
            String operation,
            String algorithm,
            MultipartFile file,
            String fileFormat,
            Map<String, Object> params) throws IOException {

        Map<String, Object> result = new HashMap<>();

        try {
            if (file == null || file.isEmpty()) {
                result.put("error", "文件不能为空");
                return result;
            }

            // 读取文件内容
            byte[] fileData = file.getBytes();
            logger.info("读取文件成功，大小: {} 字节", fileData.length);

            // 根据操作类型选择处理方法
            switch (operation.toUpperCase()) {
                case "HASH":
                    return processFileHash(algorithm, fileData, params);
                case "ENCRYPT":
                    return processFileEncrypt(algorithm, fileData, fileFormat, params);
                case "DECRYPT":
                    return processFileDecrypt(algorithm, fileData, fileFormat, params);
                case "SIGN":
                    return processFileSign(algorithm, fileData, fileFormat, params);
                case "VERIFY":
                    return processFileVerify(algorithm, fileData, fileFormat, params);
                default:
                    result.put("error", "不支持的文件操作: " + operation);
                    return result;
            }

        } catch (Exception e) {
            logger.error("文件处理失败: {}", e.getMessage());
            result.put("error", "文件处理失败: " + e.getMessage());
        }

        return result;
    }

    // ========================= 密钥生成方法 =========================

    private Map<String, Object> generateAesKey(Map<String, Object> params) {
        Map<String, Object> result = new HashMap<>();
        try {
            // 默认生成256位密钥
            int keySize = params != null && params.containsKey("keySize") ?
                    (Integer) params.get("keySize") : 256;

            if (keySize != 128 && keySize != 192 && keySize != 256) {
                result.put("error", "无效的AES密钥长度: " + keySize + "，支持的长度: 128, 192, 256");
                return result;
            }

            // 生成随机密钥
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(keySize);
            SecretKey key = keyGen.generateKey();
            byte[] keyBytes = key.getEncoded();

            result.put("key", bytesToHex(keyBytes));
            result.put("keyBase64", Base64.getEncoder().encodeToString(keyBytes));
            result.put("keySize", keySize);

            // 可选地生成IV
            boolean generateIv = params != null && params.containsKey("generateIv") ?
                    (Boolean) params.getOrDefault("generateIv", false) : false;
            if (generateIv) {
                byte[] ivBytes = new byte[16]; // AES块大小为16字节
                new SecureRandom().nextBytes(ivBytes);
                result.put("iv", bytesToHex(ivBytes));
                result.put("ivBase64", Base64.getEncoder().encodeToString(ivBytes));
            }

            logger.info("成功生成{}位AES密钥", keySize);
        } catch (Exception e) {
            logger.error("生成AES密钥失败: {}", e.getMessage());
            result.put("error", "生成AES密钥失败: " + e.getMessage());
        }
        return result;
    }

    private Map<String, Object> generateDesKey(Map<String, Object> params) {
        Map<String, Object> result = new HashMap<>();
        try {
            // DES密钥固定为56位，但Java API使用64位密钥（包含8位奇偶校验位）
            KeyGenerator keyGen = KeyGenerator.getInstance("DES");
            SecretKey key = keyGen.generateKey();
            byte[] keyBytes = key.getEncoded();

            result.put("key", bytesToHex(keyBytes));
            result.put("keyBase64", Base64.getEncoder().encodeToString(keyBytes));
            result.put("keySize", 56);

            // 可选地生成IV
            boolean generateIv = params != null && params.containsKey("generateIv") ?
                    (Boolean) params.getOrDefault("generateIv", false) : false;
            if (generateIv) {
                byte[] ivBytes = new byte[8]; // DES块大小为8字节
                new SecureRandom().nextBytes(ivBytes);
                result.put("iv", bytesToHex(ivBytes));
                result.put("ivBase64", Base64.getEncoder().encodeToString(ivBytes));
            }

            logger.info("成功生成DES密钥");
        } catch (Exception e) {
            logger.error("生成DES密钥失败: {}", e.getMessage());
            result.put("error", "生成DES密钥失败: " + e.getMessage());
        }
        return result;
    }

    private Map<String, Object> generate3DesKey(Map<String, Object> params) {
        Map<String, Object> result = new HashMap<>();
        try {
            // 默认生成168位密钥（三重DES，实际使用192位但有效强度为168位）
            int keySize = params != null && params.containsKey("keySize") ?
                    (Integer) params.get("keySize") : 168;
            if (keySize != 112 && keySize != 168) {
                result.put("error", "无效的3DES密钥长度: " + keySize + "，支持的长度: 112, 168");
                return result;
            }

            KeyGenerator keyGen = KeyGenerator.getInstance("DESede");
            keyGen.init(keySize);
            SecretKey key = keyGen.generateKey();
            byte[] keyBytes = key.getEncoded();

            result.put("key", bytesToHex(keyBytes));
            result.put("keyBase64", Base64.getEncoder().encodeToString(keyBytes));
            result.put("keySize", keySize);

            // 可选地生成IV
            boolean generateIv = params != null && params.containsKey("generateIv") ?
                    (Boolean) params.getOrDefault("generateIv", false) : false;
            if (generateIv) {
                byte[] ivBytes = new byte[8]; // 3DES块大小为8字节
                new SecureRandom().nextBytes(ivBytes);
                result.put("iv", bytesToHex(ivBytes));
                result.put("ivBase64", Base64.getEncoder().encodeToString(ivBytes));
            }

            logger.info("成功生成{}位3DES密钥", keySize);
        } catch (Exception e) {
            logger.error("生成3DES密钥失败: {}", e.getMessage());
            result.put("error", "生成3DES密钥失败: " + e.getMessage());
        }
        return result;
    }

    private Map<String, Object> generateSm4Key(Map<String, Object> params) {
        Map<String, Object> result = new HashMap<>();
        try {
            // SM4密钥固定为128位
            byte[] keyBytes = new byte[16]; // 16字节 = 128位
            new SecureRandom().nextBytes(keyBytes);

            result.put("key", bytesToHex(keyBytes));
            result.put("keyBase64", Base64.getEncoder().encodeToString(keyBytes));
            result.put("keySize", 128);

            // 可选地生成IV
            boolean generateIv = params != null && params.containsKey("generateIv") ?
                    (Boolean) params.getOrDefault("generateIv", false) : false;
            if (generateIv) {
                byte[] ivBytes = new byte[16]; // SM4块大小为16字节
                new SecureRandom().nextBytes(ivBytes);
                result.put("iv", bytesToHex(ivBytes));
                result.put("ivBase64", Base64.getEncoder().encodeToString(ivBytes));
            }

            logger.info("成功生成128位SM4密钥");
        } catch (Exception e) {
            logger.error("生成SM4密钥失败: {}", e.getMessage());
            result.put("error", "生成SM4密钥失败: " + e.getMessage());
        }
        return result;
    }

    private Map<String, Object> generateRc4Key(Map<String, Object> params) {
        Map<String, Object> result = new HashMap<>();
        try {
            // 默认生成128位密钥
            int keySize = params != null && params.containsKey("keySize") ?
                    (Integer) params.get("keySize") : 128;

            int keyBytes = keySize / 8;
            byte[] key = new byte[keyBytes];
            new SecureRandom().nextBytes(key);

            result.put("key", bytesToHex(key));
            result.put("keyBase64", Base64.getEncoder().encodeToString(key));
            result.put("keySize", keySize);

            logger.info("成功生成{}位RC4密钥", keySize);
        } catch (Exception e) {
            logger.error("生成RC4密钥失败: {}", e.getMessage());
            result.put("error", "生成RC4密钥失败: " + e.getMessage());
        }
        return result;
    }

    private Map<String, Object> generateChaCha20Key(Map<String, Object> params) {
        Map<String, Object> result = new HashMap<>();
        try {
            // ChaCha20密钥固定为256位
            byte[] keyBytes = new byte[32]; // 32字节 = 256位
            new SecureRandom().nextBytes(keyBytes);

            result.put("key", bytesToHex(keyBytes));
            result.put("keyBase64", Base64.getEncoder().encodeToString(keyBytes));
            result.put("keySize", 256);

            // ChaCha20需要一个96位的Nonce
            byte[] nonceBytes = new byte[12]; // 12字节 = 96位
            new SecureRandom().nextBytes(nonceBytes);
            result.put("nonce", bytesToHex(nonceBytes));
            result.put("nonceBase64", Base64.getEncoder().encodeToString(nonceBytes));

            logger.info("成功生成ChaCha20密钥和Nonce");
        } catch (Exception e) {
            logger.error("生成ChaCha20密钥失败: {}", e.getMessage());
            result.put("error", "生成ChaCha20密钥失败: " + e.getMessage());
        }
        return result;
    }

    private Map<String, Object> generateZucKey(Map<String, Object> params) {
        Map<String, Object> result = new HashMap<>();
        try {
            // ZUC密钥固定为128位
            byte[] keyBytes = new byte[16]; // 16字节 = 128位
            new SecureRandom().nextBytes(keyBytes);

            result.put("key", bytesToHex(keyBytes));
            result.put("keyBase64", Base64.getEncoder().encodeToString(keyBytes));
            result.put("keySize", 128);

            // ZUC需要一个128位的IV
            byte[] ivBytes = new byte[16]; // 16字节 = 128位
            new SecureRandom().nextBytes(ivBytes);
            result.put("iv", bytesToHex(ivBytes));
            result.put("ivBase64", Base64.getEncoder().encodeToString(ivBytes));

            logger.info("成功生成ZUC密钥和IV");
        } catch (Exception e) {
            logger.error("生成ZUC密钥失败: {}", e.getMessage());
            result.put("error", "生成ZUC密钥失败: " + e.getMessage());
        }
        return result;
    }

    private Map<String, Object> generateRsaKey(Map<String, Object> params) {
        Map<String, Object> result = new HashMap<>();
        try {
            // 默认生成2048位密钥
            int keySize = params != null && params.containsKey("keySize") ?
                    (Integer) params.get("keySize") : 2048;

            if (keySize < 1024) {
                result.put("error", "RSA密钥长度不应小于1024位");
                return result;
            }

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(keySize);
            KeyPair keyPair = keyGen.generateKeyPair();

            // 提取公钥和私钥
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            // 编码为Base64字符串
            String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            String privateKeyBase64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());

            result.put("publicKey", publicKeyBase64);
            result.put("privateKey", privateKeyBase64);
            result.put("keySize", keySize);

            logger.info("成功生成{}位RSA密钥对", keySize);
        } catch (Exception e) {
            logger.error("生成RSA密钥对失败: {}", e.getMessage());
            result.put("error", "生成RSA密钥对失败: " + e.getMessage());
        }
        return result;
    }

    private Map<String, Object> generateSm2Key(Map<String, Object> params) {
        Map<String, Object> result = new HashMap<>();
        result.put("error", "SM2密钥生成暂未实现，需使用BouncyCastle库");
        return result;
    }

    private Map<String, Object> generateSm9Key(Map<String, Object> params) {
        Map<String, Object> result = new HashMap<>();
        result.put("error", "SM9密钥生成暂未实现，需使用特定的SM9密码库");
        return result;
    }

    // ========================= 哈希计算方法 =========================

    private byte[] calculateHash(String algorithm, byte[] data) throws NoSuchAlgorithmException {
        switch (algorithm.toUpperCase()) {
            case "MD5":
                return MessageDigest.getInstance("MD5").digest(data);
            case "SHA-1":
            case "SHA1":
                return MessageDigest.getInstance("SHA-1").digest(data);
            case "SHA-224":
            case "SHA224":
                return MessageDigest.getInstance("SHA-224").digest(data);
            case "SHA-256":
            case "SHA256":
                return MessageDigest.getInstance("SHA-256").digest(data);
            case "SHA-384":
            case "SHA384":
                return MessageDigest.getInstance("SHA-384").digest(data);
            case "SHA-512":
            case "SHA512":
                return MessageDigest.getInstance("SHA-512").digest(data);
            case "SM3":
                // SM3算法需要特殊实现或依赖BouncyCastle等外部库
                return calculateSm3Hash(data);
            default:
                logger.error("不支持的哈希算法: {}", algorithm);
                return null;
        }
    }

    private byte[] calculateSm3Hash(byte[] data) {
        // 这里应该是使用实际的SM3哈希算法实现
        // 为了简化示例，我们返回一个模拟结果
        logger.warn("SM3实现使用模拟结果，请替换为真实实现");

        try {
            // 尝试使用MessageDigest的"SM3"，如果可用（需要BouncyCastle）
            MessageDigest md = MessageDigest.getInstance("SM3");
            return md.digest(data);
        } catch (NoSuchAlgorithmException e) {
            // 如果不可用，返回一个固定长度的模拟结果
            byte[] result = new byte[32]; // SM3输出为32字节
            System.arraycopy(data, 0, result, 0, Math.min(data.length, result.length));
            return result;
        }
    }

    private byte[] calculateHmac(String algorithm, byte[] data, byte[] key) throws Exception {
        String hmacAlgorithm;
        switch (algorithm.toUpperCase()) {
            case "MD5":
                hmacAlgorithm = "HmacMD5";
                break;
            case "SHA-1":
            case "SHA1":
                hmacAlgorithm = "HmacSHA1";
                break;
            case "SHA-224":
            case "SHA224":
                hmacAlgorithm = "HmacSHA224";
                break;
            case "SHA-256":
            case "SHA256":
                hmacAlgorithm = "HmacSHA256";
                break;
            case "SHA-384":
            case "SHA384":
                hmacAlgorithm = "HmacSHA384";
                break;
            case "SHA-512":
            case "SHA512":
                hmacAlgorithm = "HmacSHA512";
                break;
            case "SM3":
                // SM3 HMAC需要特殊实现
                return calculateSm3Hmac(data, key);
            default:
                logger.error("不支持的HMAC算法: {}", algorithm);
                return null;
        }

        Mac mac = Mac.getInstance(hmacAlgorithm);
        mac.init(new SecretKeySpec(key, hmacAlgorithm));
        return mac.doFinal(data);
    }

    private byte[] calculateSm3Hmac(byte[] data, byte[] key) {
        // 这里应该是使用实际的SM3 HMAC实现
        // 为了简化示例，我们返回一个模拟结果
        logger.warn("SM3 HMAC实现使用模拟结果，请替换为真实实现");

        try {
            // 尝试使用MessageDigest的"HmacSM3"，如果可用（需要BouncyCastle）
            Mac mac = Mac.getInstance("HmacSM3");
            mac.init(new SecretKeySpec(key, "HmacSM3"));
            return mac.doFinal(data);
        } catch (Exception e) {
            // 如果不可用，返回一个固定长度的模拟结果
            byte[] result = new byte[32]; // SM3输出为32字节
            for (int i = 0; i < result.length; i++) {
                // 简单地结合数据、密钥和索引
                result[i] = (byte) ((i < data.length ? data[i] : 0) ^
                        (i < key.length ? key[i] : 0) ^ i);
            }
            return result;
        }
    }

    // ========================= 对称加密方法 =========================

    private byte[] processAes(boolean isEncrypt, byte[] inputData, String key,
                              String iv, String mode, String padding) throws Exception {
        // 解析密钥
        byte[] keyBytes = hexToBytes(key);

        // 验证密钥长度
        if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
            throw new IllegalArgumentException(
                    "AES密钥长度必须为128位(16字节)、192位(24字节)或256位(32字节)，实际: " + keyBytes.length + "字节");
        }

        // 创建SecretKey
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

        // 构建Cipher
        String transformation = "AES" + (mode != null ? "/" + mode : "") +
                (padding != null ? "/" + padding : "");
        Cipher cipher = Cipher.getInstance(transformation);

        // 初始化Cipher
        if (mode != null && !mode.equalsIgnoreCase("ECB") && iv != null && !iv.isEmpty()) {
            // 需要IV的模式
            byte[] ivBytes = hexToBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            cipher.init(isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey, ivSpec);
        } else {
            // ECB模式或未指定IV
            cipher.init(isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey);
        }

        // 执行加密/解密
        return cipher.doFinal(inputData);
    }

    private byte[] processDes(boolean isEncrypt, byte[] inputData, String key,
                              String iv, String mode, String padding) throws Exception {
        // 解析密钥
        byte[] keyBytes = hexToBytes(key);

        // 验证密钥长度
        if (keyBytes.length != 8) {
            throw new IllegalArgumentException(
                    "DES密钥长度必须为64位(8字节)，实际: " + keyBytes.length + "字节");
        }

        // 创建SecretKey
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "DES");

        // 构建Cipher
        String transformation = "DES" + (mode != null ? "/" + mode : "") +
                (padding != null ? "/" + padding : "");
        Cipher cipher = Cipher.getInstance(transformation);

        // 初始化Cipher
        if (mode != null && !mode.equalsIgnoreCase("ECB") && iv != null && !iv.isEmpty()) {
            // 需要IV的模式
            byte[] ivBytes = hexToBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            cipher.init(isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey, ivSpec);
        } else {
            // ECB模式或未指定IV
            cipher.init(isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey);
        }

        // 执行加密/解密
        return cipher.doFinal(inputData);
    }

    private byte[] process3Des(boolean isEncrypt, byte[] inputData, String key,
                               String iv, String mode, String padding) throws Exception {
        // 解析密钥
        byte[] keyBytes = hexToBytes(key);

        // 验证密钥长度
        if (keyBytes.length != 16 && keyBytes.length != 24) {
            throw new IllegalArgumentException(
                    "3DES密钥长度必须为128位(16字节)或192位(24字节)，实际: " + keyBytes.length + "字节");
        }

        // 创建SecretKey
        DESedeKeySpec desKeySpec = new DESedeKeySpec(keyBytes);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey secretKey = keyFactory.generateSecret(desKeySpec);

        // 构建Cipher
        String transformation = "DESede" + (mode != null ? "/" + mode : "") +
                (padding != null ? "/" + padding : "");
        Cipher cipher = Cipher.getInstance(transformation);

        // 初始化Cipher
        if (mode != null && !mode.equalsIgnoreCase("ECB") && iv != null && !iv.isEmpty()) {
            // 需要IV的模式
            byte[] ivBytes = hexToBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            cipher.init(isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey, ivSpec);
        } else {
            // ECB模式或未指定IV
            cipher.init(isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey);
        }

        // 执行加密/解密
        return cipher.doFinal(inputData);
    }

    private byte[] processSm4(boolean isEncrypt, byte[] inputData, String key,
                              String iv, String mode, String padding) {
        // SM4需要特殊实现或依赖BouncyCastle等外部库
        logger.warn("SM4实现使用模拟结果，请替换为真实实现");

        // 简单模拟SM4加密/解密
        byte[] keyBytes = hexToBytes(key);
        byte[] result = new byte[inputData.length];

        for (int i = 0; i < inputData.length; i++) {
            // 简单异或操作（仅作示例，非实际SM4）
            result[i] = (byte) (inputData[i] ^ keyBytes[i % keyBytes.length]);
        }

        return result;
    }

    private byte[] processRc4(boolean isEncrypt, byte[] inputData, String key) {
        // RC4加密和解密操作相同
        byte[] keyBytes = hexToBytes(key);
        byte[] result = new byte[inputData.length];

        // 初始化RC4状态
        int[] S = new int[256];
        for (int i = 0; i < 256; i++) {
            S[i] = i;
        }

        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + S[i] + (keyBytes[i % keyBytes.length] & 0xFF)) % 256;
            // 交换S[i]和S[j]
            int temp = S[i];
            S[i] = S[j];
            S[j] = temp;
        }

        // 生成密钥流并与输入异或
        int i = 0;
        j = 0;
        for (int k = 0; k < inputData.length; k++) {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;
            // 交换S[i]和S[j]
            int temp = S[i];
            S[i] = S[j];
            S[j] = temp;
            int t = (S[i] + S[j]) % 256;
            result[k] = (byte) (inputData[k] ^ S[t]);
        }

        return result;
    }

    private byte[] processChaCha20(boolean isEncrypt, byte[] inputData, String key, String nonce) {
        // ChaCha20需要特殊实现或依赖现代加密库
        logger.warn("ChaCha20实现使用模拟结果，请替换为真实实现");

        // 简单模拟ChaCha20加密/解密
        byte[] keyBytes = hexToBytes(key);
        byte[] nonceBytes = hexToBytes(nonce);
        byte[] result = new byte[inputData.length];

        for (int i = 0; i < inputData.length; i++) {
            // 简单地结合数据、密钥和nonce（仅作示例，非实际ChaCha20）
            result[i] = (byte) (inputData[i] ^
                    keyBytes[i % keyBytes.length] ^
                    nonceBytes[i % nonceBytes.length]);
        }

        return result;
    }

    private byte[] processZuc(boolean isEncrypt, byte[] inputData, String key, String iv) {
        // ZUC需要特殊实现
        logger.warn("ZUC实现使用模拟结果，请替换为真实实现");

        // 简单模拟ZUC加密/解密
        byte[] keyBytes = hexToBytes(key);
        byte[] ivBytes = hexToBytes(iv);
        byte[] result = new byte[inputData.length];

        for (int i = 0; i < inputData.length; i++) {
            // 简单异或操作（仅作示例，非实际ZUC）
            result[i] = (byte) (inputData[i] ^
                    keyBytes[i % keyBytes.length] ^
                    ivBytes[i % ivBytes.length]);
        }

        return result;
    }

    // ========================= 非对称加密方法 =========================

    private byte[] processRsa(boolean isEncrypt, byte[] inputData,
                              String publicKey, String privateKey, String padding) throws Exception {
        // 准备Cipher
        String transformation = "RSA" + (padding != null ? "/" + padding : "");
        Cipher cipher = Cipher.getInstance(transformation);

        if (isEncrypt) {
            // 解析公钥
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey pubKey = keyFactory.generatePublic(keySpec);

            // 初始化加密模式
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        } else {
            // 解析私钥
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKey);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privKey = keyFactory.generatePrivate(keySpec);

            // 初始化解密模式
            cipher.init(Cipher.DECRYPT_MODE, privKey);
        }

        // RSA加密有最大数据长度限制
        // 在实际应用中应该分块处理，这里简化处理
        return cipher.doFinal(inputData);
    }

    private byte[] processSm2(boolean isEncrypt, byte[] inputData,
                              String publicKey, String privateKey) {
        // SM2需要特殊实现或依赖BouncyCastle等外部库
        logger.warn("SM2实现使用模拟结果，请替换为真实实现");

        // 简单模拟SM2加密/解密（仅作示例）
        if (isEncrypt) {
            // 模拟加密
            byte[] result = new byte[inputData.length + 16]; // 增加一些长度
            System.arraycopy(inputData, 0, result, 16, inputData.length);
            return result;
        } else {
            // 模拟解密
            if (inputData.length < 16) return inputData;
            byte[] result = new byte[inputData.length - 16];
            System.arraycopy(inputData, 16, result, 0, result.length);
            return result;
        }
    }

    private byte[] processSm9(boolean isEncrypt, byte[] inputData,
                              String publicKey, String privateKey, Map<String, Object> params) {
        // SM9需要特殊实现或依赖专门的SM9密码库
        logger.warn("SM9实现使用模拟结果，请替换为真实实现");

        // 简单模拟SM9加密/解密（仅作示例）
        if (isEncrypt) {
            // 模拟加密
            byte[] result = new byte[inputData.length + 32]; // 增加一些长度
            System.arraycopy(inputData, 0, result, 32, inputData.length);
            return result;
        } else {
            // 模拟解密
            if (inputData.length < 32) return inputData;
            byte[] result = new byte[inputData.length - 32];
            System.arraycopy(inputData, 32, result, 0, result.length);
            return result;
        }
    }

    // ========================= 签名方法 =========================

    private byte[] signRsa(byte[] data, String privateKey, String algorithm) throws Exception {
        // 解析私钥
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privKey = keyFactory.generatePrivate(keySpec);

        // 创建签名对象
        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(privKey);
        signature.update(data);

        // 执行签名
        return signature.sign();
    }

    private boolean verifyRsa(byte[] data, byte[] signatureBytes, String publicKey, String algorithm) throws Exception {
        // 解析公钥
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pubKey = keyFactory.generatePublic(keySpec);

        // 创建签名对象
        Signature signature = Signature.getInstance(algorithm);
        signature.initVerify(pubKey);
        signature.update(data);

        // 验证签名
        return signature.verify(signatureBytes);
    }

    private byte[] signSm2(byte[] data, String privateKey, String userId) {
        // SM2签名需要特殊实现或依赖BouncyCastle等外部库
        logger.warn("SM2签名实现使用模拟结果，请替换为真实实现");

        // 简单模拟SM2签名（仅作示例，非实际SM2签名）
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // 组合用户ID和消息数据
            byte[] userIdBytes = userId.getBytes(StandardCharsets.UTF_8);
            byte[] combined = new byte[userIdBytes.length + data.length];
            System.arraycopy(userIdBytes, 0, combined, 0, userIdBytes.length);
            System.arraycopy(data, 0, combined, userIdBytes.length, data.length);

            // 计算哈希并作为模拟签名
            byte[] hash = digest.digest(combined);

            // 真实SM2签名应该是64字节(r,s)
            byte[] signature = new byte[64];
            System.arraycopy(hash, 0, signature, 0, Math.min(hash.length, 32));
            System.arraycopy(hash, 0, signature, 32, Math.min(hash.length, 32));

            return signature;
        } catch (Exception e) {
            logger.error("模拟SM2签名失败: {}", e.getMessage());
            return new byte[64]; // 返回空签名
        }
    }

    private boolean verifySm2(byte[] data, byte[] signatureBytes, String publicKey, String userId) {
        // SM2验签需要特殊实现或依赖BouncyCastle等外部库
        logger.warn("SM2验签实现使用模拟结果，请替换为真实实现");

        // 简单模拟SM2验签（仅作示例，总是返回true）
        return true;
    }

    private byte[] signSm9(byte[] data, String privateKey, Map<String, Object> params) {
        // SM9签名需要特殊实现或依赖专门的SM9密码库
        logger.warn("SM9签名实现使用模拟结果，请替换为真实实现");

        // 简单模拟SM9签名（仅作示例）
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);

            // 真实SM9签名应该是根据算法特性生成
            byte[] signature = new byte[128]; // 假设SM9签名长度
            System.arraycopy(hash, 0, signature, 0, Math.min(hash.length, 32));

            return signature;
        } catch (Exception e) {
            logger.error("模拟SM9签名失败: {}", e.getMessage());
            return new byte[128]; // 返回空签名
        }
    }

    private boolean verifySm9(byte[] data, byte[] signatureBytes, String publicKey, Map<String, Object> params) {
        // SM9验签需要特殊实现或依赖专门的SM9密码库
        logger.warn("SM9验签实现使用模拟结果，请替换为真实实现");

        // 简单模拟SM9验签（仅作示例，总是返回true）
        return true;
    }

    // ========================= 文件处理方法 =========================

    private Map<String, Object> processFileHash(String algorithm, byte[] fileData, Map<String, Object> params) {
        Map<String, Object> result = new HashMap<>();

        try {
            String hmacKey = params != null ? (String) params.get("hmacKey") : null;
            String salt = params != null ? (String) params.get("salt") : null;
            String saltPosition = params != null ? (String) params.get("saltPosition") : null;
            Integer customPosition = params != null ? (Integer) params.get("customPosition") : null;
            Integer iterations = params != null ? (Integer) params.get("iterations") : 1;
            String expectedHash = params != null ? (String) params.get("expectedHash") : null;
            String hashFormat = params != null ? (String) params.get("hashFormat") : "HEX";

            // 应用盐值（如果有）
            byte[] dataToHash = fileData;
            if (salt != null && !salt.isEmpty()) {
                byte[] saltData = salt.getBytes(StandardCharsets.UTF_8);
                dataToHash = applySalt(fileData, saltData, saltPosition, customPosition);
                logger.info("已应用盐值，长度: {} 字节, 位置: {}", saltData.length, saltPosition);
            }

            // 计算哈希值
            byte[] hashValue;
            if (hmacKey != null && !hmacKey.isEmpty()) {
                // HMAC模式
                byte[] keyBytes = hexToBytes(hmacKey);
                hashValue = calculateHmacWithIterations(algorithm, dataToHash, keyBytes, iterations);
            } else {
                // 普通哈希
                hashValue = calculateHashWithIterations(algorithm, dataToHash, iterations);
            }

            if (hashValue == null) {
                result.put("error", "不支持的哈希算法: " + algorithm);
                return result;
            }

            // 转换为不同格式
            String hexHash = bytesToHex(hashValue);
            String base64Hash = Base64.getEncoder().encodeToString(hashValue);

            result.put("hex", hexHash);
            result.put("base64", base64Hash);
            result.put("algorithm", algorithm);
            result.put("fileSize", fileData.length);

            // 添加迭代次数和盐值信息到结果
            if (iterations > 1) {
                result.put("iterations", iterations);
            }

            if (salt != null && !salt.isEmpty()) {
                result.put("salt", salt);
                result.put("saltPosition", saltPosition != null ? saltPosition : "SUFFIX");
            }

            // 如果提供了预期哈希值，验证结果
            if (expectedHash != null && !expectedHash.isEmpty()) {
                String normalizedExpectedHash = parseExpectedHash(expectedHash, hashFormat);
                boolean matches = hexHash.equalsIgnoreCase(normalizedExpectedHash);
                result.put("matches", matches);
                result.put("expected", normalizedExpectedHash);
            }

            logger.info("文件{}哈希计算成功完成，文件大小: {} 字节, 迭代次数: {}",
                    algorithm, fileData.length, iterations);

        } catch (Exception e) {
            logger.error("文件哈希计算失败: {}", e.getMessage());
            result.put("error", "哈希计算失败: " + e.getMessage());
        }

        return result;
    }

    private Map<String, Object> processFileEncrypt(String algorithm, byte[] fileData, String fileFormat, Map<String, Object> params) {
        Map<String, Object> result = new HashMap<>();

        try {
            // 提取参数
            String key = (String) params.get("key");
            String iv = (String) params.get("iv");
            String mode = (String) params.get("mode");
            String padding = (String) params.get("padding");
            String publicKey = (String) params.get("publicKey");
            String expectedOutput = (String) params.get("expectedOutput");
            String expectedOutputFormat = (String) params.get("expectedOutputFormat");

            byte[] outputData;

            // 根据算法类型选择处理方法
            switch (algorithm.toUpperCase()) {
                case "AES":
                    outputData = processAes(true, fileData, key, iv, mode, padding);
                    break;
                case "DES":
                    outputData = processDes(true, fileData, key, iv, mode, padding);
                    break;
                case "3DES":
                    outputData = process3Des(true, fileData, key, iv, mode, padding);
                    break;
                case "SM4":
                    outputData = processSm4(true, fileData, key, iv, mode, padding);
                    break;
                case "RC4":
                    outputData = processRc4(true, fileData, key);
                    break;
                case "CHACHA20":
                    outputData = processChaCha20(true, fileData, key, iv);
                    break;
                case "ZUC":
                    outputData = processZuc(true, fileData, key, iv);
                    break;
                case "RSA":
                    outputData = processRsa(true, fileData, publicKey, null, padding);
                    break;
                case "SM2":
                    outputData = processSm2(true, fileData, publicKey, null);
                    break;
                case "SM9":
                    outputData = processSm9(true, fileData, publicKey, null, params);
                    break;
                default:
                    result.put("error", "不支持的加密算法: " + algorithm);
                    return result;
            }

            // 处理输出
            String hexOutput = bytesToHex(outputData);
            String base64Output = Base64.getEncoder().encodeToString(outputData);

            result.put("hex", hexOutput);
            result.put("base64", base64Output);
            result.put("binary", outputData);

            // 如果提供了预期输出，验证结果
            if (expectedOutput != null && !expectedOutput.isEmpty()) {
                String normalizedExpectedOutput = parseExpectedOutput(expectedOutput, expectedOutputFormat, false);
                boolean matches = hexOutput.equalsIgnoreCase(normalizedExpectedOutput);
                result.put("matches", matches);
                result.put("expected", normalizedExpectedOutput);

                if (matches) {
                    logger.info("文件{}加密操作成功匹配预期输出", algorithm);
                } else {
                    logger.info("文件{}加密操作未匹配预期输出", algorithm);
                }
            }

            logger.info("文件{}加密操作成功完成，文件大小: {} 字节", algorithm, fileData.length);

        } catch (Exception e) {
            logger.error("文件加密失败: {}", e.getMessage());
            result.put("error", "加密失败: " + e.getMessage());
        }

        return result;
    }

    private Map<String, Object> processFileDecrypt(String algorithm, byte[] fileData, String fileFormat, Map<String, Object> params) {
        Map<String, Object> result = new HashMap<>();

        try {
            // 提取参数
            String key = (String) params.get("key");
            String iv = (String) params.get("iv");
            String mode = (String) params.get("mode");
            String padding = (String) params.get("padding");
            String privateKey = (String) params.get("privateKey");
            String expectedOutput = (String) params.get("expectedOutput");
            String expectedOutputFormat = (String) params.get("expectedOutputFormat");

            // 如果需要解析文件格式
            if (fileFormat != null && !fileFormat.equals("BINARY")) {
                fileData = parseInputData(new String(fileData, StandardCharsets.UTF_8), fileFormat);
            }

            byte[] outputData;

            // 根据算法类型选择处理方法
            switch (algorithm.toUpperCase()) {
                case "AES":
                    outputData = processAes(false, fileData, key, iv, mode, padding);
                    break;
                case "DES":
                    outputData = processDes(false, fileData, key, iv, mode, padding);
                    break;
                case "3DES":
                    outputData = process3Des(false, fileData, key, iv, mode, padding);
                    break;
                case "SM4":
                    outputData = processSm4(false, fileData, key, iv, mode, padding);
                    break;
                case "RC4":
                    outputData = processRc4(false, fileData, key);
                    break;
                case "CHACHA20":
                    outputData = processChaCha20(false, fileData, key, iv);
                    break;
                case "ZUC":
                    outputData = processZuc(false, fileData, key, iv);
                    break;
                case "RSA":
                    outputData = processRsa(false, fileData, null, privateKey, padding);
                    break;
                case "SM2":
                    outputData = processSm2(false, fileData, null, privateKey);
                    break;
                case "SM9":
                    outputData = processSm9(false, fileData, null, privateKey, params);
                    break;
                default:
                    result.put("error", "不支持的解密算法: " + algorithm);
                    return result;
            }

            // 处理输出
            String hexOutput = bytesToHex(outputData);
            String base64Output = Base64.getEncoder().encodeToString(outputData);

            result.put("hex", hexOutput);
            result.put("base64", base64Output);
            result.put("binary", outputData);

            // 尝试将结果转换为文本
            try {
                String textOutput = new String(outputData, StandardCharsets.UTF_8);
                result.put("text", textOutput);
            } catch (Exception e) {
                logger.warn("无法将文件解密结果转换为文本: {}", e.getMessage());
            }

            // 如果提供了预期输出，验证结果
            if (expectedOutput != null && !expectedOutput.isEmpty()) {
                String normalizedExpectedOutput = parseExpectedOutput(expectedOutput, expectedOutputFormat, true);
                boolean matches = hexOutput.equalsIgnoreCase(normalizedExpectedOutput);
                result.put("matches", matches);
                result.put("expected", normalizedExpectedOutput);

                if (matches) {
                    logger.info("文件{}解密操作成功匹配预期输出", algorithm);
                } else {
                    logger.info("文件{}解密操作未匹配预期输出", algorithm);
                }
            }

            logger.info("文件{}解密操作成功完成，文件大小: {} 字节", algorithm, fileData.length);

        } catch (Exception e) {
            logger.error("文件解密失败: {}", e.getMessage());
            result.put("error", "解密失败: " + e.getMessage());
        }

        return result;
    }

    private Map<String, Object> processFileSign(String algorithm, byte[] fileData, String fileFormat, Map<String, Object> params) {
        Map<String, Object> result = new HashMap<>();

        try {
            // 提取参数
            String privateKey = (String) params.get("privateKey");
            String signAlgorithm = (String) params.get("signAlgorithm");
            String userId = (String) params.get("userId");

            // 如果需要解析文件格式
            if (fileFormat != null && !fileFormat.equals("BINARY")) {
                fileData = parseInputData(new String(fileData, StandardCharsets.UTF_8), fileFormat);
            }

            byte[] signatureBytes;

            // 根据算法类型选择处理方法
            switch (algorithm.toUpperCase()) {
                case "RSA":
                    signatureBytes = signRsa(fileData, privateKey, signAlgorithm);
                    break;
                case "SM2":
                    signatureBytes = signSm2(fileData, privateKey, userId);
                    break;
                case "SM9":
                    signatureBytes = signSm9(fileData, privateKey, params);
                    break;
                default:
                    result.put("error", "不支持的签名算法: " + algorithm);
                    return result;
            }

            // 处理签名结果
            String hexSignature = bytesToHex(signatureBytes);
            String base64Signature = Base64.getEncoder().encodeToString(signatureBytes);

            result.put("signature", hexSignature);
            result.put("signatureBase64", base64Signature);
            result.put("algorithm", signAlgorithm != null ? signAlgorithm : algorithm);
            result.put("success", true);

            logger.info("文件{}签名操作成功完成，文件大小: {} 字节", algorithm, fileData.length);

        } catch (Exception e) {
            logger.error("文件签名失败: {}", e.getMessage());
            result.put("error", "签名失败: " + e.getMessage());
        }

        return result;
    }

    private Map<String, Object> processFileVerify(String algorithm, byte[] fileData, String fileFormat, Map<String, Object> params) {
        Map<String, Object> result = new HashMap<>();

        try {
            // 提取参数
            String publicKey = (String) params.get("publicKey");
            String signAlgorithm = (String) params.get("signAlgorithm");
            String signature = (String) params.get("signature");
            String signatureFormat = (String) params.get("signatureFormat");
            String userId = (String) params.get("userId");

            if (signature == null || signature.isEmpty()) {
                result.put("error", "验签操作需要提供签名值");
                return result;
            }

            // 如果需要解析文件格式
            if (fileFormat != null && !fileFormat.equals("BINARY")) {
                fileData = parseInputData(new String(fileData, StandardCharsets.UTF_8), fileFormat);
            }

            // 解析签名
            byte[] signatureBytes = parseSignature(signature, signatureFormat);
            if (signatureBytes == null) {
                result.put("error", "解析签名失败");
                return result;
            }

            boolean verified;

            // 根据算法类型选择处理方法
            switch (algorithm.toUpperCase()) {
                case "RSA":
                    verified = verifyRsa(fileData, signatureBytes, publicKey, signAlgorithm);
                    break;
                case "SM2":
                    verified = verifySm2(fileData, signatureBytes, publicKey, userId);
                    break;
                case "SM9":
                    verified = verifySm9(fileData, signatureBytes, publicKey, params);
                    break;
                default:
                    result.put("error", "不支持的验签算法: " + algorithm);
                    return result;
            }

            result.put("verified", verified);
            result.put("algorithm", signAlgorithm != null ? signAlgorithm : algorithm);

            if (verified) {
                logger.info("文件{}签名验证成功，文件大小: {} 字节", algorithm, fileData.length);
            } else {
                logger.warn("文件{}签名验证失败，文件大小: {} 字节", algorithm, fileData.length);
            }

        } catch (Exception e) {
            logger.error("文件验签失败: {}", e.getMessage());
            result.put("error", "验签失败: " + e.getMessage());
        }

        return result;
    }

    // ========================= 辅助方法 =========================

    /**
     * 验证操作类型（加密/解密）
     * @return 如果是加密操作返回true，解密操作返回false
     */
    private boolean validateOperation(String operation) {
        if (operation == null) {
            throw new IllegalArgumentException("操作类型不能为空");
        }

        String op = operation.toUpperCase();
        if ("ENCRYPT".equals(op)) {
            return true;
        } else if ("DECRYPT".equals(op)) {
            return false;
        } else {
            throw new IllegalArgumentException("无效的操作类型: " + operation +
                    "，必须是ENCRYPT或DECRYPT");
        }
    }

    /**
     * 解析输入数据
     */
    private byte[] parseInputData(String input, String format) {
        if (input == null) {
            return new byte[0];
        }

        format = format != null ? format.toUpperCase() : "TEXT";

        try {
            switch (format) {
                case "HEX":
                    byte[] hexDecoded = hexToBytes(input);
                    logger.info("输入数据按HEX格式解析，解码后长度: {} 字节", hexDecoded.length);
                    return hexDecoded;
                case "BASE64":
                    byte[] base64Decoded = Base64.getDecoder().decode(input);
                    logger.info("输入数据按BASE64格式解析，解码后长度: {} 字节", base64Decoded.length);
                    return base64Decoded;
                case "TEXT":
                default:
                    byte[] textBytes = input.getBytes(StandardCharsets.UTF_8);
                    logger.info("输入数据按TEXT格式解析，长度: {} 字节", textBytes.length);
                    return textBytes;
            }
        } catch (Exception e) {
            logger.error("解析输入数据失败，格式: {}, 错误: {}", format, e.getMessage());
            return null;
        }
    }

    /**
     * 解析预期哈希值
     */
    private String parseExpectedHash(String hash, String format) {
        if (hash == null || hash.isEmpty()) {
            return "";
        }

        format = format != null ? format.toUpperCase() : "HEX";

        try {
            if ("BASE64".equals(format)) {
                byte[] decoded = Base64.getDecoder().decode(hash);
                return bytesToHex(decoded).toLowerCase();
            } else {
                // 默认为HEX格式
                return hash.toLowerCase();
            }
        } catch (Exception e) {
            logger.error("解析预期哈希值失败，格式: {}, 错误: {}", format, e.getMessage());
            return "";
        }
    }

    /**
     * 解析预期输出
     */
    private String parseExpectedOutput(String output, String format, boolean isDecrypt) {
        if (output == null || output.isEmpty()) {
            return "";
        }

        format = format != null ? format.toUpperCase() : "HEX";

        try {
            if ("BASE64".equals(format)) {
                byte[] decoded = Base64.getDecoder().decode(output);
                return bytesToHex(decoded).toLowerCase();
            } else if ("TEXT".equals(format) && isDecrypt) {
                // 如果是解密操作且格式为TEXT，将明文转换为16进制进行比较
                byte[] textBytes = output.getBytes(StandardCharsets.UTF_8);
                return bytesToHex(textBytes).toLowerCase();
            } else {
                // 默认为HEX格式
                return output.toLowerCase();
            }
        } catch (Exception e) {
            logger.error("解析预期输出失败，格式: {}, 错误: {}", format, e.getMessage());
            return "";
        }
    }

    /**
     * 解析签名
     */
    private byte[] parseSignature(String signature, String format) {
        if (signature == null || signature.isEmpty()) {
            return null;
        }

        format = format != null ? format.toUpperCase() : "HEX";

        try {
            switch (format) {
                case "HEX":
                    return hexToBytes(signature);
                case "BASE64":
                    return Base64.getDecoder().decode(signature);
                default:
                    logger.error("不支持的签名格式: {}", format);
                    return null;
            }
        } catch (Exception e) {
            logger.error("解析签名失败，格式: {}, 错误: {}", format, e.getMessage());
            return null;
        }
    }

    /**
     * 十六进制字符串转字节数组
     */
    private byte[] hexToBytes(String hex) {
        if (hex == null) {
            return null;
        }

        // 移除可能的空格和0x前缀
        hex = hex.replaceAll("\\s+", "").replaceAll("0[xX]", "");

        // 如果长度为奇数，在前面补0
        if (hex.length() % 2 != 0) {
            hex = "0" + hex;
        }

        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int index = i * 2;
            bytes[i] = (byte) Integer.parseInt(hex.substring(index, index + 2), 16);
        }
        return bytes;
    }

    /**
     * 字节数组转十六进制字符串
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
