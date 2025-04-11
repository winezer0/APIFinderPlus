package utils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RespTitleUtils {
    /**
     * 从HTML文档中提取<title>标签的内容。
     */
    public static String parseTextTitle(byte[] bodyBytes) {
        String title = null;
        if (bodyBytes.length>0){
            byte[] bytesToParse = bodyBytes;
            // 如果bodyBytes长度大于10000，仅取前10000字节
            if (bodyBytes.length > 10000) {
                bytesToParse = Arrays.copyOfRange(bodyBytes, 0, 10000);
            }
            // 将字节数组转换为字符串
            String htmlContent = new String(bytesToParse, StandardCharsets.UTF_8);
            // 定义一个正则表达式来匹配<title>标签内的内容
            Pattern pattern = Pattern.compile("<title>(.*?)</title>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
            // 创建一个Matcher对象
            Matcher matcher = pattern.matcher(htmlContent);
            // 检查是否找到了匹配项
            if (matcher.find()) {
                title = matcher.group(1).trim();
            }
        }

        return title;
    }

    /**
     * 获取 HTML 中 <title> 标签的内容，支持分块匹配。
     *
     * @param responseBody 响应体内容
     * @param chunkSize    每次处理的块大小（字符数）
     * @return 匹配到的 <title> 标签内容，如果没有匹配到则返回空字符串
     */
    public static String getTitle(String responseBody, int chunkSize) {
        if (responseBody == null || responseBody.isEmpty()) {
            return "";
        }

        // 定义正则表达式，匹配 <title> 标签内容
        Pattern pattern = Pattern.compile("<title>(.*?)</title>", Pattern.CASE_INSENSITIVE);

        // 分块处理 responseBody
        int length = responseBody.length();
        for (int start = 0; start < length; start += chunkSize) {
            // 计算当前块的结束位置
            int end = Math.min(start + chunkSize, length);
            String chunk = responseBody.substring(start, end);

            // 使用正则表达式匹配当前块
            Matcher matcher = pattern.matcher(chunk);
            if (matcher.find()) {
                return matcher.group(1); // 返回第一个匹配到的 <title> 内容
            }
        }

        // 如果没有匹配到，返回空字符串
        return "";
    }

}
