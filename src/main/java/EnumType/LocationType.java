package EnumType;

import java.util.ArrayList;
import java.util.List;

public enum LocationType {
    CONFIG("config"),
    PATH("path"),
    TITLE("title"),
    BODY("body"),
    HEADER("header"),
    RESPONSE("response"),
    ICON_HASH("icon_hash");

    private final String value;

    // 构造方法
    LocationType(String value) {
        this.value = value;
    }

    // 获取枚举对应的字符串值
    public String getValue() {
        return value;
    }

    // 根据字符串值获取对应的枚举
    public static LocationType fromValue(String value) {
        for (LocationType type : LocationType.values()) {
            if (type.getValue().equalsIgnoreCase(value)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Invalid location type: " + value);
    }

    /**
     * 将 LocationType 枚举的所有值转换为 List<String>。
     *
     * @return 包含所有 LocationType 值的列表
     */
    public static String[] getValues() {
        // 创建一个可变的列表来存储字符串值
        List<String> locationTypes = new ArrayList<>();
        // 遍历枚举值并提取其对应的字符串值
        for (LocationType type : LocationType.values()) {
            locationTypes.add(type.getValue());
        }
        // 将 List<String> 转换为 String[]
        return locationTypes.toArray(new String[0]);
    }
}