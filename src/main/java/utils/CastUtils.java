package utils;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.CRC32;

public class CastUtils {
    /**
     * 防止操作的list是null值
     * @param list
     * @return
     */
    private static List<String> fixedNullList(List<String> list) {
        if (list == null)  list = new ArrayList<>();
        return list;
    }

    /**
     * 将任意类型的List转为Json字符串
     * @param list
     * @return
     */
    public static String toJson(List<?> list){
        if (list == null) list = new ArrayList<>();

        return com.alibaba.fastjson2.JSON.toJSONString(list);
    }

    /**
     * List<String> list 元素去重
     */
    public static List<String> deduplicateStringList(List<String> list) {
        if (list == null || list.isEmpty()) return new ArrayList<>();

        return new ArrayList<>(new HashSet<>(list));
    }


    /**
     * 去除List<JSONObject>中的重复项。
     *
     * @param list 需要去重的原始列表。
     * @return 去重后的列表。
     */
    public static List<JSONObject> deduplicateJsonList(List<JSONObject> list) {
        if (list == null || list.isEmpty()) return new ArrayList<>();

        // 使用LinkedHashMap来保持插入顺序并去除重复
        Map<String, JSONObject> map = new LinkedHashMap<>();

        for (JSONObject jsonObject : list) {
            // 将每个JSONObject转换成字符串，并用作Map的键
            String jsonString = jsonObject.toString();
            map.putIfAbsent(jsonString, jsonObject);
        }

        // 将Map的值转换回List
        return new ArrayList<>(map.values());
    }

    /**
     * 返回两个集合的差集。该集合包含在listA中但不在listB中的所有元素。
     * @param listA 第一个集合
     * @param listB 第二个集合
     * @return 差集
     */
    public static List<String> listReduceList(List<String> listA, List<String> listB) {
        listA = fixedNullList(listA);
        listB = fixedNullList(listB);

        if (listA.isEmpty() || listB.isEmpty()) return listA;

        Set<String> result = new HashSet<>(listA);
        result.removeAll(listB);
        return new ArrayList<>(result);
    }

    /**
     * 将任意类型的 Json字符串 转为 JSONArray
     * @param jsonString
     * @return
     */
    public static JSONArray toJsonArray(String jsonString){
        if (jsonString == null)
            return new JSONArray();

        return JSONArray.parseArray(jsonString);

    }

    /**
     * 将任意类型的 Json字符串 转为 Json 对象
     * @param jsonString
     * @return
     */
    public static JSONObject toJsonObject(String jsonString){
        if (jsonString == null)
            return new JSONObject();

        return JSONObject.parseObject(jsonString);
    }


    /**
     * 将JsonArray 转为 List<String>
     * @param array
     * @return
     */
    public static List<String> toStringList(JSONArray array){
        if (array == null || array.isEmpty()) return new ArrayList<>();

        return array.toList(String.class);
    }

    /**
     * 格式化Json数据为可输出的状态
     * @param jsonArrayString
     * @return
     */
    public static String stringJsonArrayFormat(String jsonArrayString) {
        if (jsonArrayString == null || jsonArrayString.length()<=2 )
            return "";

        // 解析JSON数组
        JSONArray jsonArray = toJsonArray(jsonArrayString);
        StringBuilder formattedString = new StringBuilder();
        for (Object item : jsonArray) {
            if (item instanceof String) {
                formattedString.append((String) item).append("\n");
            } else {
                throw new IllegalArgumentException("JSONArray contains non-string element.");
            }
        }
        return formattedString.toString();
    }


    /**
     * 合并两个 List<String> 并去重
     *
     * @param listA 第一个列表
     * @param listB 第二个列表
     * @return 包含两个列表所有元素的新列表
     */
    public static List<String> listAddList(List<String> listA, List<String> listB) {
        listA = fixedNullList(listA);
        listB = fixedNullList(listB);

        Set<String> uniqueSet = new LinkedHashSet<>(listA); // 创建 LinkedHashSet 并添加第一个列表的所有元素
        uniqueSet.addAll(listB); // 添加第二个列表的所有元素，重复项会被自动过滤
        return new ArrayList<>(uniqueSet); // 将 Set 转换回 List 并返回
    }


    /**
     * 格式化Json数据为可输出的状态
     * @param jsonArrayString
     * @return
     */
    public static String infoJsonArrayFormatHtml(String jsonArrayString) {
        if (jsonArrayString == null || jsonArrayString.length()<=2 )
            return "";

        JSONArray jsonArray = JSONArray.parseArray(jsonArrayString);
        StringBuilder formattedResult = new StringBuilder();

        for (Object obj : jsonArray) {
            if (obj instanceof JSONObject) {
                JSONObject jsonObject = (JSONObject) obj;

                // 使用String.format进行格式化
                String formattedItem = String.format(
                        "############# type: %s #############<br>" +
                                "describe: <span style='color: $color$};'>%s</span><br>" +
                                "value: <span style='color: $color$};'>%s</span><br>" +
                                "accuracy: %s<br>" +
                                "important: %s<br>"
                        ,
                        jsonObject.getString("type"),
                        jsonObject.getString("describe"),
                        UiUtils.encodeForHTML(jsonObject.getString("value")),
                        jsonObject.getString("accuracy"),
                        jsonObject.getString("important")
                );

                //进行颜色标记
                String color = jsonObject.getBoolean("important") ? "red" : "blue";
                formattedItem = formattedItem.replace("$color$",color);
                formattedResult.append(formattedItem);
            }
        }

        return formattedResult.toString();
    }

    /**
     * 字符串转 CRC32
     */
    public static String calcCRC32(String string) {
        // 使用 UTF-8 编码将字符串转换为字节数组
        byte[] inputBytes = string.getBytes(StandardCharsets.UTF_8);
        // 初始化CRC32对象
        CRC32 crc32 = new CRC32();
        // 更新CRC值
        crc32.update(inputBytes, 0, inputBytes.length);
        // 将计算后的CRC32值转换为十六进制字符串并返回
        return Long.toHexString(crc32.getValue()).toLowerCase();
    }


    /**
     * 字符串转列表
     * @param text
     * @return
     */
    public static List<String> getUniqueLines(String text, String split) {
        if (text == null || text.isEmpty()) {
            return Collections.emptyList();
        }
        // 分割字符串
        String[] lines = text.split(split);
        // 转换为Set以去除重复项
        Set<String> uniqueSet = new LinkedHashSet<>(Arrays.asList(lines));
        // 转换回List并返回
        return new ArrayList<>(uniqueSet);
    }
}
