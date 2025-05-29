package com.bistu.tools.controller;

import com.bistu.tools.core.response.Result;
import com.bistu.tools.core.response.ResultGenerator;
import com.bistu.tools.service.HexCalculateService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.bistu.tools.model.HexCalculateRequest;
import com.bistu.tools.model.HexCalculateResponse;

@RestController
@RequestMapping("/api/hex")
public class HexCalculateController {

    private final HexCalculateService hexCalculateService;

    @Autowired
    public HexCalculateController(HexCalculateService hexCalculateService) {
        this.hexCalculateService = hexCalculateService;
    }

    @PostMapping("/xor")
    public Result calculateXor(@RequestBody HexCalculateRequest request) {
        System.out.println("接收到XOR计算请求: " + request);
        return ResultGenerator.genOkResult(hexCalculateService.calculateXor(request));
    }

    @GetMapping("/reset")
    public HexCalculateResponse reset() {
        HexCalculateResponse response = new HexCalculateResponse();
        response.setSuccess(true);
        response.setMessage("重置成功");
        response.setResult("");
        response.setByteCount(0);
        return response;
    }
}
