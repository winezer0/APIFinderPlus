package utils;

import model.HttpUrlInfo;

import java.security.SecureRandom;
import java.util.*;

import static utils.CastUtils.isEmptyObj;
import static utils.CastUtils.isNotEmptyObj;

public class RespFieldCompareutils {

    /**
     * 实际用来对比的模型数据
     */
    public static Map<String, Object> findMapsSameFieldValue(List<Map<String, Object>> FieldValuesMapList) {
        if (FieldValuesMapList == null || FieldValuesMapList.size() <= 1) {
            return Collections.emptyMap();
        }

        // 获取第一个对象的字段映射，用于参考
        Map<String, Object> referenceFields = FieldValuesMapList.get(0);
        Map<String, Object> commonFields = new HashMap<>();

        // 遍历所有字段
        for (Map.Entry<String, Object> entry : referenceFields.entrySet()) {
            String fieldName = entry.getKey();
            Object fieldValue = entry.getValue();
            if (isNotEmptyObj(fieldValue)) {
                // 检查所有对象的该字段是否具有相同的值 //忽略空字段
                boolean allMatch = true;
                for (Map<String, Object> FieldValuesMap : FieldValuesMapList) {
                    Object currentFieldValue = FieldValuesMap.get(fieldName);
                    if (isEmptyObj(currentFieldValue) || !fieldValue.equals(currentFieldValue)) {
                        allMatch = false;
                        break; // 一旦发现本字段值不匹配，立即退出循环, 比较下一个字段
                    }
                }
                if (allMatch) {
                    commonFields.put(fieldName, fieldValue);
                }
            }
        }
        return commonFields;
    }

    /**
     * 用 当前响应对象 和 筛选条件 进行对比
     * @param currentCommonFields 当前响应对象
     * @param filterCommonFields 筛选条件
     * @return
     */
    public static boolean sameFieldValueIsEquals(Map currentCommonFields, Map filterCommonFields, boolean equalsAllFields) {
        boolean allValuesEquals = equalsAllFields
                ? mapSameFieldAsAllValuesEquals(currentCommonFields, filterCommonFields)
                : mapSameFieldOneValuesEquals(currentCommonFields, filterCommonFields);
        return allValuesEquals;
    }

    /**
     * 实际用来对比的Map数据 所有相同键都相等
     */
    public static boolean mapSameFieldAsAllValuesEquals(Map<String, Object> currRespCommonFields, Map<String, Object> filterRespCommonFields) {
        // 遍历所有字段
        boolean allMatch = true;
        for (Map.Entry<String, Object> entry : filterRespCommonFields.entrySet()) {
            String fieldName = entry.getKey();
            Object fieldValue = entry.getValue();
            System.out.println(String.format("正在检查 fieldName:%s -> %s", fieldName, fieldValue));
            if (isNotEmptyObj(fieldValue)) {
                // 检查所有对象的该字段是否具有相同的值
                Object currentFieldValue = currRespCommonFields.get(fieldName);
                if (isEmptyObj(currentFieldValue) || !fieldValue.equals(currentFieldValue)) {
                    allMatch = false;
                }
            }
        }
        System.out.println("结束 findCommonFieldValues");
        return allMatch;
    }

    /**
     * 实际用来对比的Map数据 有一个相同键相等
     */
    public static boolean mapSameFieldOneValuesEquals(Map<String, Object> currRespCommonFields, Map<String, Object> filterRespCommonFields) {
        // 遍历所有字段
        boolean allMatch = false;
        for (Map.Entry<String, Object> entry : filterRespCommonFields.entrySet()) {
            String fieldName = entry.getKey();
            Object fieldValue = entry.getValue();
            System.out.println(String.format("正在检查 fieldName:%s -> %s", fieldName, fieldValue));
            if (isNotEmptyObj(fieldValue)) {
                //检查所有对象的该字段是否 有一个是 具有相同的值
                Object currentFieldValue = currRespCommonFields.get(fieldName);
                if (isNotEmptyObj(currentFieldValue) && fieldValue.equals(currentFieldValue)) {
                    allMatch = true;
                    break;
                }
            }
        }
        System.out.println("结束 findCommonFieldValues");
        return allMatch;
    }

    /**
     * 基于当前请求信息生成URL
     */
    public static List<String> generateTestUrls(HttpUrlInfo urlInfo) {
        //获取当前的URL 生成几个测试URL
        String rootUrlSimple = urlInfo.getRootUrlSimple();   //当前请求 http://xxx.com
        String pathToFile = urlInfo.getPathToFile();   //当前请求文件路径  /user/login.php
        String pathToDir = urlInfo.getPathToDir();  //当前请求目录  /user/
        String suffix = urlInfo.getSuffixUsual();   //当前请求后缀  .php
        String file = urlInfo.getFile();  //当前请求文件 login.php
        String SLASH = "/";

        List<String> testUrls;
        testUrls = (SLASH.equals(pathToDir) || isEmptyObj(file)) ?
                generateTestUrls(rootUrlSimple, SLASH): generateTestUrls(rootUrlSimple, pathToFile, pathToDir, suffix, SLASH);
        return testUrls;
    }


    /**
     * 生成随机字符串
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
     * 基于当前请求信息生成URL
     */
    private static List<String> generateTestUrls(String rootUrl, String pathToFile, String pathToDir, String suffix, String SLASH) {
        List<String> urls = new ArrayList<>();
        String random1 = getRandomStr(8);
        String random2 = getRandomStr(8);

        // 1. 随机目录随机文件当前后缀
        urls.add(rootUrl + SLASH + random1 + SLASH + random2 + (isEmptyObj(suffix) ? "" : suffix));
        // 2. 当前目录随机文件
        urls.add(rootUrl + pathToDir + random1 + (isEmptyObj(suffix) ? "" : suffix));
        // 3. 随机目录当前路径
        urls.add(rootUrl + SLASH + random1 + pathToFile);
        return urls;
    }

    /**
     * 完全随机生成URL
     */
    private static List<String> generateTestUrls(String rootUrl, String SLASH) {
        List<String> urls = new ArrayList<>();
        String rand1 = getRandomStr(8);
        String rand2 = getRandomStr(8);
        String suffix = getRandomStr(3);
        //2、rootUrl/dir1/dir2/file1
        urls.add(rootUrl + SLASH + rand1 + SLASH + rand2 + SLASH + rand2+ "." + suffix);
        //1、rootUrl/dir1/file1.suffix
        urls.add(rootUrl + SLASH + rand1 + SLASH + rand2);
        //3、rootUrl/file1.suffix
        urls.add(rootUrl + SLASH + rand2 + "." + suffix);
        return urls;
    }
}
