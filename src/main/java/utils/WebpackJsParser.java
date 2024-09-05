package utils;


import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WebpackJsParser {


    //aaaaaaa.aaaa.js //0.690fe1e4ceaf45313632.js
    //private static final String WEBPACK_JS_PATTERN_CHECK = "\"([\\w-]+)\":\"(\\w+)\"\\}\\[\\w\\]\\+\".js\"";  //字符型
    private static final String WEBPACK_JS_PATTERN_CHECK = "[\"]?([\\d\\w-]+)[\"]?:\"(\\w+)\"\\}\\[\\w\\]\\+\".js\""; //字符+数字
    private static final String WEBPACK_JS_PATTERN_EXTRACT_JS = "([^{^+}]+\\}[\\[\\]\\w\\+\\\"]{5}.js\")";
    //private static final String WEBPACK_JS_PATTERN_EXTRACT_KV = "\"([\\w-]+)\":\"(\\w+)\"";  //字符型
    private static final String WEBPACK_JS_PATTERN_EXTRACT_KV = "[\"]?([\\d\\w-]+)[\"]?:\"(\\w+)\""; //字符+数字
    private static final Pattern patternCheck = Pattern.compile(WEBPACK_JS_PATTERN_CHECK);
    private static final Pattern patternExtractJS = Pattern.compile(WEBPACK_JS_PATTERN_EXTRACT_JS);
    private static final Pattern patternExtractKV = Pattern.compile(WEBPACK_JS_PATTERN_EXTRACT_KV);

    public static Set<String> parseWebpackSimple(String text) {
        Set<String> matches = new LinkedHashSet<>();
        Matcher matcherCheck = patternCheck.matcher(text);
        if (matcherCheck.find()) {
            Matcher matcherJs = patternExtractJS.matcher(text);
            while (matcherJs.find()) {
                String extract = matcherJs.group(1);
                Matcher matcherKV = patternExtractKV.matcher(extract);
                while (matcherKV.find()) {
                    String key = matcherKV.group(1);
                    String value = matcherKV.group(2);
                    if (!value.isEmpty()) {
                        matches.add(key + "." + value + ".js");
                    }
                }
            }
        }
        return matches;
    }

    /**
     * 最新实现的分块正则匹配常规版本
     */
    public static Set<String> parseWebpackSimpleChunk(String text, int chunkSize) {
        Set<String> matches = new HashSet<>();
        int textLength = text.length();
        for (int start = 0; start < textLength; start += chunkSize) {
            int end = Math.min(start + chunkSize, textLength);
            String jsChunk = text.substring(start, end);
            matches.addAll(parseWebpackSimple(jsChunk));
        }
        return matches;
    }

    public static void main(String[] args) {
        String jsFile = "C:\\Users\\WINDOWS\\Desktop\\testdata\\数字型.js";
        try (BufferedReader reader = new BufferedReader(new FileReader(jsFile))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            String data = sb.toString();

            System.out.println(data.length());
            Set<String> results = parseWebpackSimple(data);
            for (String result : results) {
                System.out.println(result);
            }

        } catch (IOException e) {
            System.err.println("错误：文件 '" + jsFile + "' 未找到。请检查文件名是否正确以及文件是否存在。");
        } catch (Exception e) {
            System.err.println("发生了一个错误：" + e.getMessage());
        }
    }
}