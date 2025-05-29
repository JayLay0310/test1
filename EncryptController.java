package com.bistu.tools.controller;

import com.bistu.tools.dto.HashEncryptDto;
import com.bistu.tools.core.response.Result;
import com.bistu.tools.core.response.ResultGenerator;
import com.bistu.tools.service.IHashEncryptService;
import com.bistu.tools.vo.HashEncryptVo;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name="加密工具方法")
@RestController
@RequestMapping("/api")
public class EncryptController {

    @Autowired IHashEncryptService hashEncryptService;

    @PostMapping("/hashEncrypt")
    public Result hashEncrypt(@RequestBody HashEncryptDto hashEncryptDto) throws Exception {

        //对加密数据进行处理，后续加密方法只执行加密操作

        String md4 = hashEncryptService.md4Function(hashEncryptDto);
        String md5 = hashEncryptService.md5Function(hashEncryptDto);
        String sha1 = hashEncryptService.sha1Function(hashEncryptDto);
        HashEncryptVo hashEncryptVo = new HashEncryptVo();
        hashEncryptVo.setMd4(md4);
        hashEncryptVo.setMd5(md5);
        hashEncryptVo.setSha1(sha1);
        return ResultGenerator.genOkResult(hashEncryptVo);
    }
}
