package com.bistu.tools.controller;

import com.bistu.tools.dto.ApiResult;
import com.bistu.tools.dto.CalculatorRequests;
import com.bistu.tools.service.DecimalCalculatorService;
import org.springframework.web.bind.annotation.*;
import java.math.BigInteger;

@RestController
@RequestMapping("/api/decimal-calculator")
public class DecimalCalculatorController {

    // 定义内部异常类
    private static class InvalidInputException extends RuntimeException {
        public InvalidInputException(String message) {
            super(message);
        }
    }

    private final DecimalCalculatorService calculatorService;

    public DecimalCalculatorController(DecimalCalculatorService calculatorService) {
        this.calculatorService = calculatorService;
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
    private void validateDecimalDivisor(String input) {
        validateDecimalInput(input);

        // 除数不能为零
        if (input.replaceAll("\\s+", "").matches("^-?0+$")) {
            throw new InvalidInputException("除数不能为零");
        }
    }

    // 验证模数（必须为正数）
    private void validateDecimalModulus(String input) {
        validateDecimalDivisor(input);

        // 模数必须为正
        BigInteger modulus = new BigInteger(input.trim());
        if (modulus.compareTo(BigInteger.ZERO) <= 0) {
            throw new InvalidInputException("模数必须为正数");
        }
    }

    @PostMapping("/add")
    public ApiResult<String> add(@RequestBody CalculatorRequests.TwoNumberRequest request) {
        try {
            // 验证输入
            validateDecimalInput(request.getA());
            validateDecimalInput(request.getB());

            BigInteger result = calculatorService.add(request.getA(), request.getB());
            return ApiResult.success(result.toString());
        } catch (Exception ex) {
            return ApiResult.fail(ex.getMessage());
        }
    }

    @PostMapping("/subtract")
    public ApiResult<String> subtract(@RequestBody CalculatorRequests.TwoNumberRequest request) {
        try {
            // 验证输入
            validateDecimalInput(request.getA());
            validateDecimalInput(request.getB());

            BigInteger result = calculatorService.subtract(request.getA(), request.getB());
            return ApiResult.success(result.toString());
        } catch (Exception ex) {
            return ApiResult.fail(ex.getMessage());
        }
    }

    @PostMapping("/multiply")
    public ApiResult<String> multiply(@RequestBody CalculatorRequests.TwoNumberRequest request) {
        try {
            // 验证输入
            validateDecimalInput(request.getA());
            validateDecimalInput(request.getB());

            BigInteger result = calculatorService.multiply(request.getA(), request.getB());
            return ApiResult.success(result.toString());
        } catch (Exception ex) {
            return ApiResult.fail(ex.getMessage());
        }
    }

    /**
     * 计算两个大数的商
     * @param a 第一个数
     * @param b 第二个数
     * @return 返回十进制字符串，保留两位小数
     */
    @GetMapping("/divide")
    public String divide(@RequestParam String a, @RequestParam String b) {
        return calculatorService.divide(a, b);
    }

    @PostMapping("/gcd")
    public ApiResult<String> gcd(@RequestBody CalculatorRequests.TwoNumberRequest request) {
        try {
            // 验证输入
            validateDecimalInput(request.getA());
            validateDecimalInput(request.getB());

            BigInteger result = calculatorService.gcd(request.getA(), request.getB());
            return ApiResult.success(result.toString());
        } catch (Exception ex) {
            return ApiResult.fail(ex.getMessage());
        }
    }

    @PostMapping("/lcm")
    public ApiResult<String> lcm(@RequestBody CalculatorRequests.TwoNumberRequest request) {
        try {
            // 验证输入
            validateDecimalInput(request.getA());
            validateDecimalInput(request.getB());

            BigInteger result = calculatorService.lcm(request.getA(), request.getB());
            return ApiResult.success(result.toString());
        } catch (Exception ex) {
            return ApiResult.fail(ex.getMessage());
        }
    }

    @PostMapping("/extendedGcd")
    public ApiResult<String[]> extendedGcd(@RequestBody CalculatorRequests.TwoNumberRequest request) {
        try {
            // 验证输入
            validateDecimalInput(request.getA());
            validateDecimalInput(request.getB());

            BigInteger[] result = calculatorService.exgcd(request.getA(), request.getB());
            String[] decResult = new String[3];
            for (int i = 0; i < 3; i++) {
                decResult[i] = result[i].toString();
            }
            return ApiResult.success(decResult);
        } catch (Exception ex) {
            return ApiResult.fail(ex.getMessage());
        }
    }

    @PostMapping("/power")
    public ApiResult<String> power(@RequestBody CalculatorRequests.PowerRequest request) {
        try {
            // 验证输入
            validateDecimalInput(request.getA());
            validateDecimalInput(request.getE());

            BigInteger result = calculatorService.power(request.getA(), request.getE());
            return ApiResult.success(result.toString());
        } catch (Exception ex) {
            return ApiResult.fail(ex.getMessage());
        }
    }

    @PostMapping("/addMod")
    public ApiResult<String> addMod(@RequestBody CalculatorRequests.ThreeNumberRequest request) {
        try {
            // 验证输入
            validateDecimalInput(request.getA());
            validateDecimalInput(request.getB());
            validateDecimalModulus(request.getN());

            BigInteger result = calculatorService.addMod(request.getA(), request.getB(), request.getN());
            return ApiResult.success(result.toString());
        } catch (Exception ex) {
            return ApiResult.fail(ex.getMessage());
        }
    }

    @PostMapping("/subtractMod")
    public ApiResult<String> subtractMod(@RequestBody CalculatorRequests.ThreeNumberRequest request) {
        try {
            // 验证输入
            validateDecimalInput(request.getA());
            validateDecimalInput(request.getB());
            validateDecimalModulus(request.getN());

            BigInteger result = calculatorService.subtractMod(request.getA(), request.getB(), request.getN());
            return ApiResult.success(result.toString());
        } catch (Exception ex) {
            return ApiResult.fail(ex.getMessage());
        }
    }

    @PostMapping("/multiplyMod")
    public ApiResult<String> multiplyMod(@RequestBody CalculatorRequests.ThreeNumberRequest request) {
        try {
            // 验证输入
            validateDecimalInput(request.getA());
            validateDecimalInput(request.getB());
            validateDecimalModulus(request.getN());

            BigInteger result = calculatorService.multiplyMod(request.getA(), request.getB(), request.getN());
            return ApiResult.success(result.toString());
        } catch (Exception ex) {
            return ApiResult.fail(ex.getMessage());
        }
    }

    @PostMapping("/divideMod")
    public ApiResult<String> divideMod(@RequestBody CalculatorRequests.ThreeNumberRequest request) {
        try {
            // 验证输入
            validateDecimalInput(request.getA());
            validateDecimalDivisor(request.getB());
            validateDecimalModulus(request.getN());

            BigInteger result = calculatorService.divideMod(request.getA(), request.getB(), request.getN());
            return ApiResult.success(result.toString());
        } catch (Exception ex) {
            return ApiResult.fail(ex.getMessage());
        }
    }

    @PostMapping("/powerMod")
    public ApiResult<String> powerMod(@RequestBody CalculatorRequests.PowerModRequest request) {
        try {
            // 验证输入
            validateDecimalInput(request.getA());
            validateDecimalInput(request.getE());
            validateDecimalModulus(request.getN());

            BigInteger result = calculatorService.powerMod(request.getA(), request.getE(), request.getN());
            return ApiResult.success(result.toString());
        } catch (Exception ex) {
            return ApiResult.fail(ex.getMessage());
        }
    }

    @PostMapping("/powerModN1")
    public ApiResult<String> powerModN1(@RequestBody CalculatorRequests.OneNumberModRequest request) {
        try {
            // 验证输入
            validateDecimalInput(request.getA());
            validateDecimalModulus(request.getN());

            BigInteger result = calculatorService.powerModN1(request.getA(), request.getN());
            return ApiResult.success(result.toString());
        } catch (Exception ex) {
            return ApiResult.fail(ex.getMessage());
        }
    }

    // 添加左移和右移操作
    @PostMapping("/leftShift")
    public ApiResult<String> leftShift(@RequestParam("a") String a, @RequestParam("bits") int bits) {
        try {
            // 验证输入
            validateDecimalInput(a);
            if (bits < 0) {
                throw new InvalidInputException("位移量不能为负数");
            }

            BigInteger numA = new BigInteger(a);
            BigInteger result = numA.shiftLeft(bits);
            return ApiResult.success(result.toString());
        } catch (Exception ex) {
            return ApiResult.fail(ex.getMessage());
        }
    }

    @PostMapping("/rightShift")
    public ApiResult<String> rightShift(@RequestParam("a") String a, @RequestParam("bits") int bits) {
        try {
            // 验证输入
            validateDecimalInput(a);
            if (bits < 0) {
                throw new InvalidInputException("位移量不能为负数");
            }

            BigInteger numA = new BigInteger(a);
            BigInteger result = numA.shiftRight(bits);
            return ApiResult.success(result.toString());
        } catch (Exception ex) {
            return ApiResult.fail(ex.getMessage());
        }
    }
}