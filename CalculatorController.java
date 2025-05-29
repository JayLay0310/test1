package com.bistu.tools.controller;

import com.bistu.tools.core.service.calculatorService;
import com.bistu.tools.core.service.BigNumberCalculateService;
import com.bistu.tools.core.response.Result;
import com.bistu.tools.core.response.ResultGenerator;
import com.bistu.tools.dto.CalculatorRequests;
import org.springframework.web.bind.annotation.*;
import java.math.BigInteger;

@RestController
@RequestMapping("/api/calculator")
public class CalculatorController {

    // 定义内部异常类
    private static class InvalidInputException extends RuntimeException {
        public InvalidInputException(String message) {
            super(message);
        }
    }

    private final calculatorService calculatorService;
    private final BigNumberCalculateService bigNumberCalculateService;

    public CalculatorController(calculatorService calculatorService, BigNumberCalculateService bigNumberCalculateService) {
        this.calculatorService = calculatorService;
        this.bigNumberCalculateService = bigNumberCalculateService;
    }

    // 验证十六进制输入
    private void validateHexInput(String input) {
        if (input == null || input.trim().isEmpty()) {
            throw new InvalidInputException("输入不能为空");
        }

        // 去除所有空格并转换为大写
        String cleanInput = input.replaceAll("\\s+", "").toUpperCase();

        // 验证是否只包含有效的十六进制字符
        if (!cleanInput.matches("^[0-9A-F]+$")) {
            throw new InvalidInputException("输入包含无效的十六进制字符");
        }
    }

    // 验证十进制输入
    private void validateDecimalInput(String input) {
        if (input == null || input.trim().isEmpty()) {
            throw new InvalidInputException("输入不能为空");
        }

        // 去除所有空格
        String cleanInput = input.replaceAll("\\s+", "");

        // 验证是否只包含有效的十进制字符（允许负号）
        if (!cleanInput.matches("^-?[0-9]+$")) {
            throw new InvalidInputException("输入包含无效的十进制字符");
        }
    }

    // 验证除数（不能为零）
    private void validateDivisor(String input, boolean isHex) {
        if (isHex) {
            validateHexInput(input);
            if (input.replaceAll("\\s+", "").matches("^0+$")) {
                throw new InvalidInputException("除数不能为零");
            }
        } else {
            validateDecimalInput(input);
            if (input.replaceAll("\\s+", "").matches("^-?0+$")) {
                throw new InvalidInputException("除数不能为零");
            }
        }
    }

    // 验证模数（必须为正数）
    private void validateModulus(String input, boolean isHex) {
        validateDivisor(input, isHex);
        BigInteger modulus;
        if (isHex) {
            modulus = new BigInteger(input.replaceAll("\\s+", ""), 16);
        } else {
            modulus = new BigInteger(input.replaceAll("\\s+", ""));
        }
        if (modulus.compareTo(BigInteger.ZERO) <= 0) {
            throw new InvalidInputException("模数必须为正数");
        }
    }

    @PostMapping("/add")
    public Result<String> add(@RequestBody CalculatorRequests.TwoNumberRequest request) {
        try {
            // 验证输入
            if (request.isInputHex()) {
                validateHexInput(request.getA());
                validateHexInput(request.getB());
            } else {
                validateDecimalInput(request.getA());
                validateDecimalInput(request.getB());
            }

            BigInteger result = calculatorService.add(request.getA(), request.getB(), request.isInputHex());
            return ResultGenerator.genOkResult(request.isOutputHex() ? result.toString(16).toUpperCase() : result.toString());
        } catch (Exception ex) {
            return ResultGenerator.genFailedResult(ex.getMessage());
        }
    }

    @PostMapping("/subtract")
    public Result<String> subtract(@RequestBody CalculatorRequests.TwoNumberRequest request) {
        try {
            // 验证输入
            if (request.isInputHex()) {
                validateHexInput(request.getA());
                validateHexInput(request.getB());
            } else {
                validateDecimalInput(request.getA());
                validateDecimalInput(request.getB());
            }

            BigInteger result = calculatorService.subtract(request.getA(), request.getB(), request.isInputHex());
            return ResultGenerator.genOkResult(request.isOutputHex() ? result.toString(16).toUpperCase() : result.toString());
        } catch (Exception ex) {
            return ResultGenerator.genFailedResult(ex.getMessage());
        }
    }

    @PostMapping("/multiply")
    public Result<String> multiply(@RequestBody CalculatorRequests.TwoNumberRequest request) {
        try {
            // 验证输入
            if (request.isInputHex()) {
                validateHexInput(request.getA());
                validateHexInput(request.getB());
            } else {
                validateDecimalInput(request.getA());
                validateDecimalInput(request.getB());
            }

            BigInteger result = calculatorService.multiply(request.getA(), request.getB(), request.isInputHex());
            return ResultGenerator.genOkResult(request.isOutputHex() ? result.toString(16).toUpperCase() : result.toString());
        } catch (Exception ex) {
            return ResultGenerator.genFailedResult(ex.getMessage());
        }
    }

    @PostMapping("/divide")
    public Result<String> divide(@RequestBody CalculatorRequests.TwoNumberRequest request) {
        try {
            // 验证输入
            if (request.isInputHex()) {
                validateHexInput(request.getA());
                validateDivisor(request.getB(), true);
            } else {
                validateDecimalInput(request.getA());
                validateDivisor(request.getB(), false);
            }

            String result = calculatorService.divide(request.getA(), request.getB(), request.isInputHex());
            return ResultGenerator.genOkResult(result);
        } catch (Exception ex) {
            return ResultGenerator.genFailedResult(ex.getMessage());
        }
    }

    @PostMapping("/gcd")
    public Result<String> gcd(@RequestBody CalculatorRequests.TwoNumberRequest request) {
        try {
            // 验证输入
            if (request.isInputHex()) {
                validateHexInput(request.getA());
                validateHexInput(request.getB());
            } else {
                validateDecimalInput(request.getA());
                validateDecimalInput(request.getB());
            }

            BigInteger result = calculatorService.gcd(request.getA(), request.getB(), request.isInputHex());
            return ResultGenerator.genOkResult(request.isOutputHex() ? result.toString(16).toUpperCase() : result.toString());
        } catch (Exception ex) {
            return ResultGenerator.genFailedResult(ex.getMessage());
        }
    }

    @PostMapping("/lcm")
    public Result<String> lcm(@RequestBody CalculatorRequests.TwoNumberRequest request) {
        try {
            // 验证输入
            if (request.isInputHex()) {
                validateHexInput(request.getA());
                validateHexInput(request.getB());
            } else {
                validateDecimalInput(request.getA());
                validateDecimalInput(request.getB());
            }

            BigInteger result = calculatorService.lcm(request.getA(), request.getB(), request.isInputHex());
            return ResultGenerator.genOkResult(request.isOutputHex() ? result.toString(16).toUpperCase() : result.toString());
        } catch (Exception ex) {
            return ResultGenerator.genFailedResult(ex.getMessage());
        }
    }

    @PostMapping("/extendedGcd")
    public Result<String[]> extendedGcd(@RequestBody CalculatorRequests.TwoNumberRequest request) {
        try {
            // 验证输入
            if (request.isInputHex()) {
                validateHexInput(request.getA());
                validateHexInput(request.getB());
            } else {
                validateDecimalInput(request.getA());
                validateDecimalInput(request.getB());
            }

            BigInteger[] result = calculatorService.exgcd(request.getA(), request.getB(), request.isInputHex());
            String[] outputResult = new String[3];
            for (int i = 0; i < 3; i++) {
                outputResult[i] = request.isOutputHex() ? result[i].toString(16).toUpperCase() : result[i].toString();
            }
            return ResultGenerator.genOkResult(outputResult);
        } catch (Exception ex) {
            return ResultGenerator.genFailedResult(ex.getMessage());
        }
    }

    @PostMapping("/power")
    public Result<String> power(@RequestBody CalculatorRequests.PowerRequest request) {
        try {
            // 验证输入
            if (request.isInputHex()) {
                validateHexInput(request.getA());
                validateHexInput(request.getE());
            } else {
                validateDecimalInput(request.getA());
                validateDecimalInput(request.getE());
            }

            BigInteger result = calculatorService.power(request.getA(), request.getE(), request.isInputHex());
            return ResultGenerator.genOkResult(request.isOutputHex() ? result.toString(16).toUpperCase() : result.toString());
        } catch (Exception ex) {
            return ResultGenerator.genFailedResult(ex.getMessage());
        }
    }

    @PostMapping("/addMod")
    public Result<String> addMod(@RequestBody CalculatorRequests.ThreeNumberRequest request) {
        try {
            // 验证输入
            if (request.isInputHex()) {
                validateHexInput(request.getA());
                validateHexInput(request.getB());
                validateModulus(request.getN(), true);
            } else {
                validateDecimalInput(request.getA());
                validateDecimalInput(request.getB());
                validateModulus(request.getN(), false);
            }

            BigInteger result = calculatorService.addMod(request.getA(), request.getB(), request.getN(), request.isInputHex());
            return ResultGenerator.genOkResult(request.isOutputHex() ? result.toString(16).toUpperCase() : result.toString());
        } catch (Exception ex) {
            return ResultGenerator.genFailedResult(ex.getMessage());
        }
    }

    @PostMapping("/subtractMod")
    public Result<String> subtractMod(@RequestBody CalculatorRequests.ThreeNumberRequest request) {
        try {
            // 验证输入
            if (request.isInputHex()) {
                validateHexInput(request.getA());
                validateHexInput(request.getB());
                validateModulus(request.getN(), true);
            } else {
                validateDecimalInput(request.getA());
                validateDecimalInput(request.getB());
                validateModulus(request.getN(), false);
            }

            BigInteger result = calculatorService.subtractMod(request.getA(), request.getB(), request.getN(), request.isInputHex());
            return ResultGenerator.genOkResult(request.isOutputHex() ? result.toString(16).toUpperCase() : result.toString());
        } catch (Exception ex) {
            return ResultGenerator.genFailedResult(ex.getMessage());
        }
    }

    @PostMapping("/multiplyMod")
    public Result<String> multiplyMod(@RequestBody CalculatorRequests.ThreeNumberRequest request) {
        try {
            // 验证输入
            if (request.isInputHex()) {
                validateHexInput(request.getA());
                validateHexInput(request.getB());
                validateModulus(request.getN(), true);
            } else {
                validateDecimalInput(request.getA());
                validateDecimalInput(request.getB());
                validateModulus(request.getN(), false);
            }

            BigInteger result = calculatorService.multiplyMod(request.getA(), request.getB(), request.getN(), request.isInputHex());
            return ResultGenerator.genOkResult(request.isOutputHex() ? result.toString(16).toUpperCase() : result.toString());
        } catch (Exception ex) {
            return ResultGenerator.genFailedResult(ex.getMessage());
        }
    }

    @PostMapping("/divideMod")
    public Result<String> divideMod(@RequestBody CalculatorRequests.ThreeNumberRequest request) {
        try {
            // 验证输入
            if (request.isInputHex()) {
                validateHexInput(request.getA());
                validateDivisor(request.getB(), true);
                validateModulus(request.getN(), true);
            } else {
                validateDecimalInput(request.getA());
                validateDivisor(request.getB(), false);
                validateModulus(request.getN(), false);
            }

            BigInteger result = calculatorService.divideMod(request.getA(), request.getB(), request.getN(), request.isInputHex());
            return ResultGenerator.genOkResult(request.isOutputHex() ? result.toString(16).toUpperCase() : result.toString());
        } catch (Exception ex) {
            return ResultGenerator.genFailedResult(ex.getMessage());
        }
    }

    @PostMapping("/powerMod")
    public Result<String> powerMod(@RequestBody CalculatorRequests.PowerModRequest request) {
        try {
            // 验证输入
            if (request.isInputHex()) {
                validateHexInput(request.getA());
                validateHexInput(request.getE());
                validateModulus(request.getN(), true);
            } else {
                validateDecimalInput(request.getA());
                validateDecimalInput(request.getE());
                validateModulus(request.getN(), false);
            }

            BigInteger result = calculatorService.powerMod(request.getA(), request.getE(), request.getN(), request.isInputHex());
            return ResultGenerator.genOkResult(request.isOutputHex() ? result.toString(16).toUpperCase() : result.toString());
        } catch (Exception ex) {
            return ResultGenerator.genFailedResult(ex.getMessage());
        }
    }

    @PostMapping("/powerModN1")
    public Result<String> powerModN1(@RequestBody CalculatorRequests.OneNumberModRequest request) {
        try {
            // 验证输入
            if (request.isInputHex()) {
                validateHexInput(request.getA());
                validateModulus(request.getN(), true);
            } else {
                validateDecimalInput(request.getA());
                validateModulus(request.getN(), false);
            }

            BigInteger result = calculatorService.powerModN1(request.getA(), request.getN(), request.isInputHex());
            return ResultGenerator.genOkResult(request.isOutputHex() ? result.toString(16).toUpperCase() : result.toString());
        } catch (Exception ex) {
            return ResultGenerator.genFailedResult(ex.getMessage());
        }
    }

    @PostMapping("/leftShift")
    public Result<String> leftShift(@RequestBody CalculatorRequests.ShiftRequest request) {
        try {
            // 验证输入
            if (request.isInputHex()) {
                validateHexInput(request.getA());
            } else {
                validateDecimalInput(request.getA());
            }
            if (request.getBits() < 0) {
                throw new InvalidInputException("位移量不能为负数");
            }

            BigInteger numA = new BigInteger(request.getA(), request.isInputHex() ? 16 : 10);
            BigInteger result = numA.shiftLeft(request.getBits());
            return ResultGenerator.genOkResult(request.isOutputHex() ? result.toString(16).toUpperCase() : result.toString());
        } catch (Exception ex) {
            return ResultGenerator.genFailedResult(ex.getMessage());
        }
    }

    @PostMapping("/rightShift")
    public Result<String> rightShift(@RequestBody CalculatorRequests.ShiftRequest request) {
        try {
            // 验证输入
            if (request.isInputHex()) {
                validateHexInput(request.getA());
            } else {
                validateDecimalInput(request.getA());
            }
            if (request.getBits() < 0) {
                throw new InvalidInputException("位移量不能为负数");
            }

            BigInteger numA = new BigInteger(request.getA(), request.isInputHex() ? 16 : 10);
            BigInteger result = numA.shiftRight(request.getBits());
            return ResultGenerator.genOkResult(request.isOutputHex() ? result.toString(16).toUpperCase() : result.toString());
        } catch (Exception ex) {
            return ResultGenerator.genFailedResult(ex.getMessage());
        }
    }
}