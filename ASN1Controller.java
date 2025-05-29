package com.bistu.tools.controller;

import com.bistu.tools.core.response.Result;
import com.bistu.tools.core.response.ResultGenerator;
import com.bistu.tools.dto.ASN1Request;
import com.bistu.tools.dto.ASN1Response;
import com.bistu.tools.service.ASN1Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/asn1")
public class ASN1Controller {

    @Autowired
    private ASN1Service asn1Service;

    /**
     * 通过文件上传处理ASN.1数据
     */
    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public Result<ASN1Response> processASN1File(@RequestParam("file") MultipartFile file,
                                        @RequestParam("format") String format) {
        try {
            ASN1Response response = asn1Service.processASN1FromFile(file, format);
            if (response.isSuccess()) {
                return ResultGenerator.genOkResult(response);
            } else {
                return ResultGenerator.genFailedResult(response.getMessage());
            }
        } catch (Exception e) {
            return ResultGenerator.genFailedResult("处理ASN.1文件失败: " + e.getMessage());
        }
    }

    /**
     * 通过手动输入处理ASN.1数据
     */
    @PostMapping("/process")
    public Result<ASN1Response> processASN1Data(@RequestBody ASN1Request request) {
        try {
            ASN1Response response = asn1Service.processASN1Data(request.getData(), request.getFormat(), request.getInputType());
            if (response.isSuccess()) {
                return ResultGenerator.genOkResult(response);
            } else {
                return ResultGenerator.genFailedResult(response.getMessage());
            }
        } catch (Exception e) {
            return ResultGenerator.genFailedResult("处理ASN.1数据失败: " + e.getMessage());
        }
    }

    /**
     * 全局异常处理
     */
    @ControllerAdvice
    public static class GlobalExceptionHandler {

        @ExceptionHandler(MaxUploadSizeExceededException.class)
        public Result<ASN1Response> handleMaxSizeException(MaxUploadSizeExceededException exc) {
            return ResultGenerator.genFailedResult("文件过大。允许的最大大小为10MB。");
        }
    }
}