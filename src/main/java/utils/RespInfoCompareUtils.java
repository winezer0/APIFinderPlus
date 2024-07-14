package utils;

import test.RespInfoCompareModel;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RespInfoCompareUtils {

    /**
     * 实际用来对比的模型数据
     * @param responses
     * @return
     */
    public static Map<String, Object> findCommonFieldValues(List<RespInfoCompareModel> responses) {
        if (responses == null || responses.size() <= 1) {
            return Collections.emptyMap();
        }

        // 获取第一个对象的字段映射，用于参考
        Map<String, Object> referenceFields = responses.get(0).getAllFieldsAsMap();
        Map<String, Object> commonFields = new HashMap<>();

        // 遍历所有字段
        for (Map.Entry<String, Object> entry : referenceFields.entrySet()) {
            String fieldName = entry.getKey();
            Object fieldValue = entry.getValue();

            // 检查所有对象的该字段是否具有相同的值
            boolean allMatch = responses.stream()
                    .allMatch(response -> fieldValue.equals(response.getAllFieldsAsMap().get(fieldName)));

            if (allMatch) {
                commonFields.put(fieldName, fieldValue);
            }
        }

        return commonFields;
    }

    /**
     * 生成随机字符串
     * @param length
     * @return
     */
    public static String getRandomStr(int length) {
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            int randomCharType = random.nextInt(3); // 0 - uppercase, 1 - lowercase, 2 - digit
            switch (randomCharType) {
                case 0:
                    sb.append((char) ('A' + random.nextInt(26))); // A-Z
                    break;
                case 1:
                    sb.append((char) ('a' + random.nextInt(26))); // a-z
                    break;
                case 2:
                    sb.append((char) ('0' + random.nextInt(10))); // 0-9
                    break;
            }
        }

        return sb.toString();
    }

    /**
     * 用筛选条件和当前响应对象进行对比
     * @param currRespJson
     * @param filterRespJson
     * @return
     */
    public static boolean respJsonIsNotAllow(RespInfoCompareModel currRespJson, Map filterRespJson) {
        return true;
    }
}
