package utils;

import java.util.*;

import static utils.CastUtils.isEmptyObj;

public class ElementUtils {
    private static List<String> formatElementList(List<String> elements) {
        List<String> list = new ArrayList<>();
        for (String element : elements) {
            list.add(format(element));
        }
        return list;
    }

    private static boolean isContainOneKey(String stringFormat, List<String> elementsFormat) {
//        for (String element : elementsFormat) {
//            if (stringFormat.contains(element)){
//                return true;
//            }
//        }
//        return false;

        // 使用 Stream API anyMatch 检查是否包含任意一個元素
        return elementsFormat.stream().anyMatch(stringFormat::contains);
    }

    private static boolean isEqualsOneKey(String stringFormat, List<String> elementsFormat) {
//        //进行判断
//        for (String element : elementsFormat) {
//            if (stringFormat.equals(element)) {
//                return true;
//            }
//        }
//        return false;

        // 使用 Stream API anyMatch 检查是否 equals 任意一個元素
        return elementsFormat.stream().anyMatch(stringFormat::equals);
    }

    private static boolean isContainAllKey(String stringFormat, List<String> elementsFormat) {
//        for (String element : elementsFormat) {
//            if (!stringFormat.contains(element)){
//                return false;
//            }
//        }
//        return true;

        // 使用 Stream API allMatch 检查 stringFormat 是否包含 elementsFormat 中的所有元素
        return elementsFormat.stream().allMatch(stringFormat::contains);
    }

    /**
     * 小写和去两端字符
     * @param string
     * @return
     */
    private static String format(String string){
        return string.toLowerCase();
    }

    /**
     * 判断字符串 是否 等于 元素列表中的任意元素 忽略大小写
     *
     * @param string 单个字符串。
     * @param elementsString 允许的字符串，用'|'分隔。
     * @param defaultBool 当 elementsString 为空时应该返回的响应码
     * @return 如果 string 在 elementsString 范围内则返回 true，否则返回false。
     */
    public static boolean isEqualsOneKey(String string, String elementsString, boolean defaultBool) {
        //当元素为空时,返回默认值
        if (isEmptyObj(string) || isEmptyObj(elementsString)) return defaultBool;

        //预先格式化处理
        String stringFormat = format(string);
        String[] elementsFormat = format(elementsString).split("\\|");

        return isEqualsOneKey(stringFormat, Arrays.asList(elementsFormat));
    }

    /**
     * 判断字符串 是否 等于 元素列表中的任意元素 忽略大小写
     *
     * @param stringA 单个字符串。
     * @param elements 允许的字符串列表
     * @param defaultBool 当 elements 为空时应该返回的响应码
     * @return 如果 string 在 elements 范围内则返回 true，否则返回false。
     */
    public static boolean isEqualsOneKey(Object stringA, List<String> elements, boolean defaultBool) {
        String string = String.valueOf(stringA);
        //当元素为空时,返回默认值
        if (isEmptyObj(string) || isEmptyObj(elements)) return defaultBool;

        String stringFormat = format(string);
        List<String> elementsFormat = formatElementList(elements);

        return isEqualsOneKey(stringFormat, elementsFormat);
    }

    /**
     * 判断字符串 是否 包含 列表中的任意元素
     *
     * @param string 单个字符串。
     * @param elementsString 允许的字符串，用'|'分隔。
     * @param defaultBool 当 elementsString 为空时应该返回的响应码
     * @return 如果 elementStrings 的任意子元素 在 string 内 则返回true，否则返回false。
     */
    public static boolean isContainOneKey(String string, String elementsString, boolean defaultBool) {
        //当元素为空时,返回默认值
        if (isEmptyObj(string) || isEmptyObj(elementsString)) return defaultBool;

        //预先格式化处理
        String stringFormat = format(string);
        String[] elementsFormat = format(elementsString).split("\\|");

        return isContainOneKey(stringFormat, Arrays.asList(elementsFormat));
    }

    /**
     * 判断字符串 是否 包含 列表中的任意元素
     *
     * @param string 单个字符串。
     * @param elements 允许的字符串，用'|'分隔。
     * @param defaultBool 当 elementsString 为空时应该返回的响应码
     * @return 如果 elementStrings 的任意子元素 在 string 内 则返回true，否则返回false。
     */
    public static boolean isContainOneKey(String string, List<String> elements, boolean defaultBool) {
        //当元素为空时,返回默认值
        if (isEmptyObj(string) || isEmptyObj(elements)) return defaultBool;

        String stringFormat = format(string);
        List<String> elementsFormat = formatElementList(elements);

        return isContainOneKey(stringFormat, elementsFormat);
    }

    /**
     * 判断字符串 是否 包含 列表中的任意元素
     *
     * @param string 单个字符串。
     * @param elements 允许的字符串，用'|'分隔。
     * @param defaultBool 当 elementsString 为空时应该返回的响应码
     * @return 如果 elementStrings 的任意子元素 在 string 内 则返回true，否则返回false。
     */
    public static boolean isContainAllKey(String string, List<String> elements, boolean defaultBool) {
        //当元素为空时,返回默认值
        if (isEmptyObj(string) || isEmptyObj(elements)) return defaultBool;

        String stringFormat = format(string);
        List<String> elementsFormat = formatElementList(elements);

        return isContainAllKey(stringFormat, elementsFormat);
    }

    /**
     * 判断字符串 是否 包含 列表中的任意元素
     *
     * @param string 单个字符串。
     * @param elementsString 允许的字符串，用'|'分隔。
     * @param defaultBool 当 elementsString 为空时应该返回的响应码
     * @return 如果 elementStrings 的任意子元素 在 string 内 则返回true，否则返回false。
     */
    public static boolean isContainAllKey(String string, String elementsString, boolean defaultBool) {
        //当元素为空时,返回默认值
        if (isEmptyObj(string) || isEmptyObj(elementsString)) return defaultBool;

        String stringFormat = format(string);
        String[] elementsFormat = format(elementsString).split("\\|");

        return isContainAllKey(stringFormat, Arrays.asList(elementsFormat));
    }
}
