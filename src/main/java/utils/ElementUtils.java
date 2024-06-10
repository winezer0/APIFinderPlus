package utils;

import burp.*;

import java.io.PrintWriter;
import java.util.List;

public class ElementUtils {
    private static PrintWriter stdout = BurpExtender.getStdout();
    private static PrintWriter stderr = BurpExtender.getStderr();
    private static IExtensionHelpers helpers = BurpExtender.getHelpers();;


    /**
     * 判断字符串是否在元素列表中
     *
     * @param string 单个字符串。
     * @param elementsString 允许的字符串，用'|'分隔。
     * @param bool 当 elementsString 为空时应该返回的响应码
     * @return 如果 string 在 elementsString 范围内则返回 true，否则返回false。
     */
    public static boolean isContainInElements(String string, String elementsString, boolean bool) {
        string = string.toLowerCase().trim();
        elementsString = elementsString.toLowerCase().trim();

        //当元素为空时,返回默认值
        if (string == null || string.trim().isEmpty() || elementsString == null || elementsString.trim().isEmpty()) return bool;

        String[] elements = elementsString.split("\\|");
        for (String element : elements) {
            if (string.equals(element.trim())) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断字符串是否包含任意一个列表元素
     *
     * @param string 单个字符串。
     * @param elementsString 允许的字符串，用'|'分隔。
     * @param bool 当 elementsString 为空时应该返回的响应码
     * @return 如果 elementStrings 的任意子元素 在 string 内 则返回true，否则返回false。
     */
    public static boolean isContainElements(String string, String elementsString, boolean bool) {
        string = string.toLowerCase().trim();
        elementsString = elementsString.toLowerCase().trim();

        //当元素为空时,返回默认值
        if (string == null || string.trim().isEmpty() || elementsString == null || elementsString.trim().isEmpty()) return bool;

        String[] elements = elementsString.split("\\|");
        for (String element : elements) {
            if (string.contains(element.trim())){
                return true;
            }
        }
        return false;
    }

    /**
     * 判断字符串是否在元素列表中
     *
     * @param string 单个字符串。
     * @param elements 允许的字符串列表
     * @param bool 当 elements 为空时应该返回的响应码
     * @return 如果 string 在 elements 范围内则返回 true，否则返回false。
     */
    public static boolean isContainInElements(String string, List<String> elements, boolean bool) {
        string = string.toLowerCase().trim();

        //当元素为空时,返回默认值
        if (string == null || string.trim().isEmpty() ||elements==null || elements.isEmpty()) return bool;

        for (String element : elements) {
            if (string.equals(element.toLowerCase().trim())) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断字符串是否包含任意一个列表元素
     *
     * @param string 单个字符串。
     * @param elements 允许的字符串，用'|'分隔。
     * @param bool 当 elementsString 为空时应该返回的响应码
     * @return 如果 elementStrings 的任意子元素 在 string 内 则返回true，否则返回false。
     */
    public static boolean isContainElements(String string, List<String> elements, boolean bool) {
        string = string.toLowerCase().trim();

        //当元素为空时,返回默认值
        if (string == null || string.trim().isEmpty() ||elements==null || elements.isEmpty()) return bool;

        for (String element : elements) {
            if (string.contains(element.toLowerCase().trim())){
                return true;
            }
        }
        return false;
    }
}
