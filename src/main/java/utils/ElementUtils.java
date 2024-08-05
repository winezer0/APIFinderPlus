package utils;

import java.util.List;

import static utils.CastUtils.isEmptyObj;

public class ElementUtils {
    /**
     * 判断字符串 是否 等于 元素列表中的任意元素 忽略大小写
     *
     * @param string 单个字符串。
     * @param elementsString 允许的字符串，用'|'分隔。
     * @param bool 当 elementsString 为空时应该返回的响应码
     * @return 如果 string 在 elementsString 范围内则返回 true，否则返回false。
     */
    public static boolean isEqualsOneKey(String string, String elementsString, boolean bool) {
        //当元素为空时,返回默认值
        if (isEmptyObj(string) || isEmptyObj(elementsString)) return bool;

        String[] elements = elementsString.split("\\|");
        for (String element : elements) {
            if (format(string).equals(format(element))) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断字符串 是否 包含 列表中的任意元素
     *
     * @param string 单个字符串。
     * @param elementsString 允许的字符串，用'|'分隔。
     * @param bool 当 elementsString 为空时应该返回的响应码
     * @return 如果 elementStrings 的任意子元素 在 string 内 则返回true，否则返回false。
     */
    public static boolean isContainOneKey(String string, String elementsString, boolean bool) {
        //当元素为空时,返回默认值
        if (isEmptyObj(string) || isEmptyObj(elementsString)) return bool;

        String[] elements = elementsString.split("\\|");
        for (String element : elements) {
            if (format(string).contains(format(element))){
                return true;
            }
        }
        return false;
    }

    /**
     * 判断字符串 是否 等于 元素列表中的任意元素 忽略大小写
     *
     * @param stringA 单个字符串。
     * @param elements 允许的字符串列表
     * @param bool 当 elements 为空时应该返回的响应码
     * @return 如果 string 在 elements 范围内则返回 true，否则返回false。
     */
    public static boolean isEqualsOneKey(Object stringA, List<String> elements, boolean bool) {
        String string = String.valueOf(stringA);
        //当元素为空时,返回默认值
        if (isEmptyObj(string) || isEmptyObj(elements)) return bool;

        for (String element : elements) {
            if (format(string).equals(format(element))) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断字符串 是否 包含 列表中的任意元素
     *
     * @param string 单个字符串。
     * @param elements 允许的字符串，用'|'分隔。
     * @param bool 当 elementsString 为空时应该返回的响应码
     * @return 如果 elementStrings 的任意子元素 在 string 内 则返回true，否则返回false。
     */
    public static boolean isContainOneKey(String string, List<String> elements, boolean bool) {
        //当元素为空时,返回默认值
        if (isEmptyObj(string) || isEmptyObj(elements)) return bool;

        for (String element : elements) {
            if (format(string).contains(format(element))){
                return true;
            }
        }
        return false;
    }

    /**
     * 判断字符串 是否 包含 列表中的任意元素
     *
     * @param string 单个字符串。
     * @param elements 允许的字符串，用'|'分隔。
     * @param bool 当 elementsString 为空时应该返回的响应码
     * @return 如果 elementStrings 的任意子元素 在 string 内 则返回true，否则返回false。
     */
    public static boolean isContainAllKey(String string, List<String> elements, boolean bool) {
        //当元素为空时,返回默认值
        if (isEmptyObj(string) || isEmptyObj(elements)) return bool;

        for (String element : elements) {
            if (!format(string).contains(format(element))){
                return false;
            }
        }
        return true;
    }

    /**
     * 小写和去两端字符
     * @param string
     * @return
     */
    private static String format(String string){
        return string.toLowerCase();
    }

}
