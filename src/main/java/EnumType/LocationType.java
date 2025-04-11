package EnumType;

import java.util.ArrayList;
import java.util.List;

public enum LocationType {
    PATH("path"),
    TITLE("title"),
    BODY("body"),
    HEADER("header"),
    RESPONSE("response");

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
    public static List<String> getLocationList() {
        // 创建一个可变的列表来存储字符串值
        List<String> locations = new ArrayList<>();

        // 遍历枚举值并提取其对应的字符串值
        LocationType[] locationTypes = LocationType.values();
        for (LocationType type : locationTypes) {
            locations.add(type.getValue());
        }

        return locations;
    }
}