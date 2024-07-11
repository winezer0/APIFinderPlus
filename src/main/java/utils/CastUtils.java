package utils;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;

import java.util.*;

public class CastUtils {
    /**
     * 将任意类型的List转为Json字符串
     * @param list
     * @return
     */
    public static String toJson(List<?> list){
        return com.alibaba.fastjson2.JSON.toJSONString(list);
    }

    /**
     * List<String> list 元素去重
     */
    public static List<String> deduplicateStringList(List<String> list) {
        return new ArrayList<>(new HashSet<>(list));
    }

    /**
     * 去除List<JSONObject>中的重复项。
     *
     * @param originalList 需要去重的原始列表。
     * @return 去重后的列表。
     */
    public static List<JSONObject> deduplicateJsonList(List<JSONObject> originalList) {
        if (originalList.isEmpty()) return originalList;

        // 使用LinkedHashMap来保持插入顺序并去除重复
        Map<String, JSONObject> map = new LinkedHashMap<>();

        for (JSONObject jsonObject : originalList) {
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
        if (listA.isEmpty() || listB.isEmpty()) return listA;

        Set<String> result = new HashSet<>(listA);
        result.removeAll(listB);
        return new ArrayList<>(result);
    }

    public static  List<String> listReduceList(JSONArray jsonArray, List<String> listB) {
        return listReduceList(jsonArray.toList(String.class), listB);
    }
}
