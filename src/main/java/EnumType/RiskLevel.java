package EnumType;

import java.util.ArrayList;
import java.util.List;

public enum RiskLevel {
    CONFIG("config"),               //要求全匹配任意关键字规则 少见
    HIGH("high"),
    MEDIUM("medium"),
    LOWER("lower");

    private final String value;

    // 构造方法
    RiskLevel(String value) {
        this.value = value;
    }

    // 获取枚举对应的字符串值
    public String getValue() {
        return value;
    }

    // 根据字符串值获取对应的枚举
    public static RiskLevel fromValue(String value) {
        for (RiskLevel type : RiskLevel.values()) {
            if (type.getValue().equalsIgnoreCase(value)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Invalid match type: " + value);
    }

    /**
     * 将 riskLevel 枚举的所有值转换为 List<String>。
     *
     * @return 包含所有 riskLevel 值的列表
     */
    public static String[] getValues() {
        // 创建一个可变的列表来存储字符串值
        List<String> riskLevels = new ArrayList<>();
        // 遍历枚举值并提取其对应的字符串值
        for (RiskLevel type : RiskLevel.values()) {
            riskLevels.add(type.getValue());
        }
        // 将 List<String> 转换为 String[]
        return riskLevels.toArray(new String[0]);
    }
}