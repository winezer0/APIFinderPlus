package utils;


import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WebpackJsParser {

    private static final String WEBPACK_JS_PATTERN_CHECK = "\"([\\w-]+)\":\"(\\w+)\"\\}\\[\\w\\]\\+\".js\"";
    private static final String WEBPACK_JS_PATTERN_EXTRACT_JS = "([^{^+}]+\\}[\\[\\]\\w\\+\\\"]{5}.js\")";
    private static final String WEBPACK_JS_PATTERN_EXTRACT_KV = "\"([\\w-]+)\":\"(\\w+)\"";
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
}