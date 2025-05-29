package com.bistu.tools.controller;

import com.bistu.tools.core.response.Result;
import com.bistu.tools.core.response.ResultGenerator;
import com.bistu.tools.dto.EncodingDto;
import com.bistu.tools.dto.EncodingExpertDto;
import com.bistu.tools.service.EncodingService;
import io.swagger.annotations.ApiOperation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
@Tag(name="编码和转换工具")
@RestController
@RequestMapping("/api")
public class EncodingController {

    private final EncodingService encodingService;

    public EncodingController(EncodingService encodingService) {
        this.encodingService = encodingService;
    }

    // 专家模式接口
    @PostMapping("/expert-convert")
    @ApiOperation(value = "专家模式接口")
    public Result expertConvert(@RequestBody EncodingExpertDto request) {
        try {
            return ResultGenerator.genOkResult(encodingService.expertConvert(request));
        } catch (Exception e) {
            return ResultGenerator.genFailedResult(e.getMessage());
        }
    }
    // 原有接口
    @PostMapping("/base64url-to-hex")
    @ApiOperation(value = "Base64+URL转HEX")
    public Result base64UrlToHex(@RequestBody EncodingDto request) {
        try {
            return ResultGenerator.genOkResult(encodingService.base64UrlToHex(request.getInput()));
        } catch (Exception e) {
            return ResultGenerator.genFailedResult(e.getMessage());
        }
    }

    @PostMapping("/hex-to-base64url")
    @ApiOperation(value = "HEX转Base64+URL")
    public Result hexToBase64Url(@RequestBody EncodingDto request) {
        try {
            return ResultGenerator.genOkResult(encodingService.hexToBase64Url(request.getInput()));
        } catch (Exception e) {
            return ResultGenerator.genFailedResult(e.getMessage());
        }
    }

    @PostMapping("/hex-to-base64")
    @ApiOperation(value = "HEX转Base64")
    public Result hexToBase64(@RequestBody EncodingDto request) {
        try {
            return ResultGenerator.genOkResult(encodingService.hexToBase64(request.getInput()));
        } catch (Exception e) {
            return ResultGenerator.genFailedResult(e.getMessage());
        }
    }
    @PostMapping("/base64-to-hex")
    @ApiOperation(value = "Base64转HEX")
    public Result base64ToHex(@RequestBody EncodingDto request) {
        try {
            return ResultGenerator.genOkResult(encodingService.base64ToHex(request.getInput()));
        } catch (Exception e) {
            return ResultGenerator.genFailedResult(e.getMessage());
        }
    }
    @PostMapping("/base64url-encode")
    @ApiOperation(value = "Base64+URL编码")
    public Result base64UrlEncode(@RequestBody EncodingDto request) {
        try {
            return ResultGenerator.genOkResult(encodingService.base64UrlEncode(request.getInput()));
        } catch (Exception e) {
            return ResultGenerator.genFailedResult(e.getMessage());
        }
    }

    @PostMapping("/base64url-decode")
    @ApiOperation(value = "Base64+URL解码")
    public Result base64UrlDecode(@RequestBody EncodingDto request) {
        try {
            return ResultGenerator.genOkResult(encodingService.base64UrlDecode(request.getInput()));
        } catch (Exception e) {
            return ResultGenerator.genFailedResult(e.getMessage());
        }
    }

    @PostMapping("/base64-encode")
    @ApiOperation(value = "Base64编码")
    public Result base64Encode(@RequestBody EncodingDto request) {
        try {
            return ResultGenerator.genOkResult(encodingService.base64Encode(request.getInput()));
        } catch (Exception e) {
            return ResultGenerator.genFailedResult(e.getMessage());
        }
    }

    @PostMapping("/base64-decode")
    @ApiOperation(value = "Base64解码")
    public Result base64Decode(@RequestBody EncodingDto request) {
        try {
            return ResultGenerator.genOkResult(encodingService.base64Decode(request.getInput()));
        } catch (Exception e) {
            return ResultGenerator.genFailedResult(e.getMessage());
        }
    }

    @PostMapping("/hex-to-decimal")
    @ApiOperation(value = "HEX转十进制")
    public Result hexToDecimal(@RequestBody EncodingDto request) {
        try {
            return ResultGenerator.genOkResult(encodingService.hexToDecimal(request.getInput()));
        } catch (Exception e) {
            return ResultGenerator.genFailedResult(e.getMessage());
        }
    }

}
