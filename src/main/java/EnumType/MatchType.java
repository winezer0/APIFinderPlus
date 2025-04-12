package EnumType;

import java.util.ArrayList;
import java.util.List;

public enum MatchType {
    ANY_KEYWORD("any_keyword"), //要求匹配任意关键字 少见
    ALL_KEYWORD("all_keyword"), //要求匹配所有关键字 常见
    ANY_REGULAR("any_regular"), //要求匹配任意正则 常见
    ALL_REGULAR("all_regular"); //要求匹配所有正则 少见

    private final String value;

    // 构造方法
    MatchType(String value) {
        this.value = value;
    }

    // 获取枚举对应的字符串值
    public String getValue() {
        return value;
    }

    // 根据字符串值获取对应的枚举
    public static MatchType fromValue(String value) {
        for (MatchType type : MatchType.values()) {
            if (type.getValue().equalsIgnoreCase(value)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Invalid match type: " + value);
    }

    /**
     * 将 matchType 枚举的所有值转换为 List<String>。
     *
     * @return 包含所有 matchType 值的列表
     */
    public static String[] getValues() {
        // 创建一个可变的列表来存储字符串值
        List<String> matchTypes = new ArrayList<>();
        // 遍历枚举值并提取其对应的字符串值
        for (MatchType type : MatchType.values()) {
            matchTypes.add(type.getValue());
        }
        // 将 List<String> 转换为 String[]
        return matchTypes.toArray(new String[0]);
    }
}