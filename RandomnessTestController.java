package com.bistu.tools.controller;

import com.bistu.tools.core.response.Result;
import com.bistu.tools.core.response.ResultGenerator;
import com.bistu.tools.dto.*;
import com.bistu.tools.service.RandomnessTestService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/randomness")
public class RandomnessTestController {

    @Autowired
    private RandomnessTestService randomnessTestService;


    @PostMapping("/randomCheck")
    public Result doRandomCheck(@RequestBody RandomTestRequestDto randomTestRequestDto) throws Exception {
        Map<String, Object> results =new HashMap<>();
        switch (randomTestRequestDto.getRandomType()){
            case "Hex":
                results = randomnessTestService.testRandomnessByHex(
                        randomTestRequestDto.getInputString(), randomTestRequestDto.getTestTypes());
                break;
            case "base64":
                results = randomnessTestService.testRandomnessByBase64(
                        randomTestRequestDto.getInputString(), randomTestRequestDto.getTestTypes());
                break;
            case "bin":
                results =  randomnessTestService.testRandomness(
                        randomTestRequestDto.getInputString(), randomTestRequestDto.getTestTypes());
                break;
            default:
                break;
        }

        return ResultGenerator.genOkResult(results);
    }
    /**
     * 通过文本输入进行随机性检测
     * @param request 包含输入文本和测试类型的DTO
     * @return 测试结果
     */
    @PostMapping("/test-by-text")
    public Result testRandomnessByText(
            @RequestBody RandomnessTestTextRequestDTO request) {
        try {
            Map<String, Object> results = randomnessTestService.testRandomness(
                    request.getInputText(), request.getTestTypes());
            return ResultGenerator.genOkResult(results);
        } catch (Exception e) {

            return ResultGenerator.genFailedResult("测试失败: " + e.getMessage());
        }
    }

    /**
     * 通过十六进制文本进行随机性检测
     * @param request 包含十六进制文本和测试类型的DTO
     * @return 测试结果
     */
    @PostMapping("/test-by-hex")
    public Result testRandomnessByHex(
            @RequestBody RandomnessTestHexRequestDTO request) {
        try {
            Map<String, Object> results = randomnessTestService.testRandomnessByHex(
                    request.getHexText(), request.getTestTypes());
            return ResultGenerator.genOkResult(results);
        } catch (Exception e) {
            return ResultGenerator.genFailedResult("测试失败: " + e.getMessage());
        }
    }

    /**
     * 通过Base64文本进行随机性检测
     * @param request 包含Base64文本和测试类型的DTO
     * @return 测试结果
     */
    @PostMapping("/test-by-base64")
    public Result testRandomnessByBase64(
            @RequestBody RandomnessTestBase64RequestDTO request) {
        try {
            Map<String, Object> results = randomnessTestService.testRandomnessByBase64(
                    request.getBase64Text(), request.getTestTypes());
            return ResultGenerator.genOkResult(results);
        } catch (Exception e) {
            Map<String, Object> error = new HashMap<String, Object>();
            error.put("error", "测试失败: " + e.getMessage());
            return ResultGenerator.genFailedResult("测试失败: " + e.getMessage());
        }
    }

    /**
     * 通过文件进行随机性检测
     * @param request 包含上传文件和测试类型的DTO
     * @return 测试结果
     */
    @PostMapping(value = "/test-by-file", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public Result testRandomnessByFile(
            @ModelAttribute RandomnessTestFileRequestDTO request) {
        try {
            Map<String, Object> results = randomnessTestService.testRandomnessByFile(
                    request.getFile(), request.getTestTypes());
            return ResultGenerator.genOkResult(results);
        } catch (Exception e) {
            Map<String, Object> error = new HashMap<String, Object>();
            error.put("error", "测试失败: " + e.getMessage());
            return ResultGenerator.genFailedResult("测试失败: " + e.getMessage());
        }
    }

    /**
     * 获取测试结果详情
     * @param testId 测试ID
     * @return 详细测试结果
     */
    @GetMapping("/results/{testId}")
    public Result getTestResults(@PathVariable String testId) {
        try {
            Map<String, Object> results = randomnessTestService.getTestResults(testId);
            if (results == null) {
                Map<String, Object> error = new HashMap<String, Object>();
                error.put("error", "找不到测试结果");
                return ResultGenerator.genFailedResult("找不到测试结果");
            }
            return ResultGenerator.genOkResult(results);
        } catch (Exception e) {

            return ResultGenerator.genFailedResult("获取结果失败: " + e.getMessage());
        }
    }
}
