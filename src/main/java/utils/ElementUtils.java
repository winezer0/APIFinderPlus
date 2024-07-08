package utils;

import burp.*;

import java.io.PrintWriter;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
        if (string == null || string.trim().isEmpty() || elementsString == null || elementsString.trim().isEmpty()) return bool;

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
        if (string == null || string.trim().isEmpty() || elementsString == null || elementsString.trim().isEmpty()) return bool;

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
     * @param string 单个字符串。
     * @param elements 允许的字符串列表
     * @param bool 当 elements 为空时应该返回的响应码
     * @return 如果 string 在 elements 范围内则返回 true，否则返回false。
     */
    public static boolean isEqualsOneKey(String string, List<String> elements, boolean bool) {
        //当元素为空时,返回默认值
        if (string == null || string.trim().isEmpty() ||elements==null || elements.isEmpty()) return bool;

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
        if (string == null || string.trim().isEmpty() ||elements==null || elements.isEmpty()) return bool;

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
        if (string == null || string.trim().isEmpty() ||elements==null || elements.isEmpty()) return bool;

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
        return string.toLowerCase().trim();
    }


    /**
     * 返回两个集合的差集。 该集合包含在setA中但不在setB中的所有元素。
     * @param setA 第一个集合
     * @param setB 第二个集合
     * @return 差集
     */
    public static <T> Set<T> differenceSet(Set<T> setA, Set<T> setB) {
        Set<T> result = new HashSet<>(setA);
        result.removeAll(setB);
        return result;
    }

}
