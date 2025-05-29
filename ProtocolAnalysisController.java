package com.bistu.tools.controller;

import com.bistu.tools.core.response.Result;
import com.bistu.tools.core.response.ResultGenerator;
import com.bistu.tools.dto.AnalysisResultDto;
import com.bistu.tools.dto.CertificateDto;
import com.bistu.tools.dto.SessionDto;
import com.bistu.tools.service.ProtocolAnalysisService;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps; // 提供PCAP文件操作工具的类
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.UUID;

@Tag(name="协议分析工具")
@RestController
@RequestMapping("/api/analysis")
public class ProtocolAnalysisController {

    @Value("${upload.local-path}")

    private String uploadPath;
    @Autowired
    private ProtocolAnalysisService analysisService;

    /**
     * 协议分析工具
     *
     * @param file 用户上传的PCAP文件
     * @return 返回包含分析结果的AnalysisResultDto对象
     */
    @PostMapping("/processPcap") // 定义POST请求接口，路径为"/processPcap"
    @ResponseBody // 表示返回值将作为HTTP响应体
    public Result processPcapFile(@RequestParam("file") MultipartFile file) {
        // 创建一个新的AnalysisResultDto对象，用于存储分析结果
        AnalysisResultDto res = new AnalysisResultDto();
        // 检查上传的文件是否为空
        if (file.isEmpty()) {
            // 如果文件为空，设置分析失败标志并返回结果
            res.setSuccess(false);
            return ResultGenerator.genOkResult(res);
        }
        try {
            // 将上传的文件保存到临时目录，生成一个临时文件
           /* File tempFile = File.createTempFile("temp-pcap", ".pcap");
            file.transferTo(tempFile); // 将文件内容写入临时文件

            // 获取临时文件的绝对路径
            String inputFile = tempFile.getAbsolutePath();*/



              Path tempDir = Paths.get(uploadPath);
              Path tempFile = tempDir.resolve("upload-" + UUID.randomUUID() + ".pcap");
              System.err.println(tempFile);
              file.transferTo(tempFile); // 将文件内容写入临时文件

              // 获取临时文件的绝对路径
             String inputFile = tempFile.toAbsolutePath().toString();

            System.err.println(inputFile);
            // 使用PcapHandle打开离线PCAP文件，创建两个独立的句柄
            PcapHandle handle = Pcaps.openOffline(inputFile);
            PcapHandle handle1 = Pcaps.openOffline(inputFile);

            // 调用服务方法分析流量数据，获取会话信息
            List<SessionDto> sessionDtos = analysisService.analyzeTraffic(handle);

            // 调用服务方法分析证书数据，获取证书信息
            List<CertificateDto> certificateDtos = analysisService.analyzeCertificate(handle1);

            // 关闭PcapHandle以释放资源
            handle.close();
            handle1.close();

            // 删除临时文件以清理磁盘空间
            //tempFile.delete();
            Files.delete(tempFile);

            // 设置分析结果中的证书和会话信息，并标记分析成功
            res.setCertificates(certificateDtos);
            res.setSessions(sessionDtos);
            res.setSuccess(true);

        } catch (IOException e) {
            // 捕获IO异常，打印堆栈信息，设置分析失败标志并返回结果
            e.printStackTrace();
            res.setSuccess(false);
            ResultGenerator.genOkResult(res);
        } catch (Exception e) {
            // 捕获其他异常，打印堆栈信息，设置分析失败标志并返回结果
            e.printStackTrace();
            res.setSuccess(false);
            ResultGenerator.genOkResult(res);
        }
        // 返回最终的分析结果
        return ResultGenerator.genOkResult(res);
    }
}
