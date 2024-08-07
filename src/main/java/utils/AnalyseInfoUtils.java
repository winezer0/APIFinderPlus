package utils;

import burp.BurpExtender;
import org.apache.commons.text.StringEscapeUtils;

import java.net.URI;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static utils.BurpPrintUtils.LOG_DEBUG;
import static utils.BurpPrintUtils.stderr_println;
import static utils.CastUtils.isNotEmptyObj;
import static utils.ElementUtils.isContainOneKey;

public class AnalyseInfoUtils {

    private static final int RESULT_SIZE = 1024;

    /**
     * 支持自动截断的正则提取文本中的内容
     * @param text
     * @param patter
     * @return
     */
    public static Set<String> extractInfoWithChunk(String text, String patter, int chunkSize) {
        Set<String> groups = new HashSet<>();
        try{
            for (int start = 0; start < text.length(); start += chunkSize) {
                int end = Math.min(start + chunkSize, text.length());
                String beFindContentChunk = text.substring(start, end);

                Pattern pattern = Pattern.compile(patter, Pattern.CASE_INSENSITIVE);
                Matcher matcher = pattern.matcher(beFindContentChunk);
                while (matcher.find()) {
                    int groupCount = matcher.groupCount();

                    String group;
                    // 检查是否有至少一个捕获组
                    if (groupCount > 0) {
                        // 如果有多个捕获组，处理多个捕获组
                        List<String> groupList = new ArrayList<>();
                        for (int i = 1; i <= groupCount; i++) {
                            groupList.add(matcher.group(i));
                        }
                        group = String.join("|", groupList);
                        // 处理 group
                    } else {
                        // 如果没有捕获组，处理整个匹配
                        group = matcher.group();
                        // 处理 group
                    }

                    //格式化响应
                    group = formatSensitiveInfo(group);

                    //响应超过长度时 截断
                    if (group.length() > RESULT_SIZE)
                        group = group.substring(0, RESULT_SIZE);

                    //判断group是否存在价值
                    if (isUsefulValue(group))
                        groups.add(group);
                }
            }
        } catch (PatternSyntaxException e) {
            stderr_println("[!] 正则表达式语法错误: " + patter);
        } catch (NullPointerException e) {
            stderr_println("[!] 正则表达式传入null: " + patter);
        } catch (Exception e){
            stderr_println("[!] 匹配出现其他报错: " + e.getMessage());
            e.printStackTrace();
        }
        return groups;
    }


    /**
     * 判断提取的信息是否是有效的 需要持续更新
     * @param group
     * @return
     */
    private static boolean isUsefulValue(String group) {
        //配置文件增加 CONF_BLACK_EXTRACT_INFO_KEYS , 指定忽略无价值的项
        //String BlackValues = "admin@admin.com";
        if (isContainOneKey(group, BurpExtender.CONF_BLACK_EXTRACT_INFO_KEYS, false)){
            //stderr_println(LOG_DEBUG, String.format("[-] 提取结果 [%s] 忽略保存", group));
            return false;
        }

        if (group.contains(":")){
            if (group.split(":", 2)[1].trim()==""){
                //stderr_println(LOG_DEBUG, String.format("[-] 提取结果 [%s] 没有价值", group));
                return false;
            }
        }

        return true;
    }


    /**
     * 从文本中截取指定长度的响应
     * @param text
     * @param maxSize
     * @return
     */
    public static String SubString(String text, int maxSize) {
        if (text != null && text.length() > maxSize){
            text = text.substring(0, maxSize);
        }
        return text;
    }

    /**
     * 最新实现的分块正则匹配常规版本
     */
    public static Set<String> extractUriMode1(String text, Pattern pattern, int chunkSize) {
        Set<String> matches = new HashSet<>();
        int textLength = text.length();
        for (int start = 0; start < textLength; start += chunkSize) {
            int end = Math.min(start + chunkSize, textLength);
            String jsChunk = text.substring(start, end);
            Matcher matcher = pattern.matcher(jsChunk);

            while (matcher.find()) {
                if (matcher.groupCount() > 0) {
                    for (int i = 1; i <= matcher.groupCount(); i++) {
                        String match = matcher.group(i);
                        if (match != null) { // Check for non-null value before adding
                            matches.add(match);
                        }
                    }
                } else {
                    String match = matcher.group();
                    if (match != null) { // Check for non-null value before adding
                        matches.add(match);
                    }
                }
            }
        }
        return matches;
    }

    public static Set<String> extractUriMode1(String text, String regex, int chunkSize) {
        Pattern pattern = Pattern.compile(regex);
        return  extractUriMode1(text , pattern, chunkSize);
    }

    /**
     * 对提取的信息进行简单的格式处理
     * @param extractUri
     * @return
     */
    public static String formatSensitiveInfo(String extractUri){
        extractUri = removeSymbol(extractUri);
        extractUri = decodeHtml(extractUri);
        return extractUri;
    }

    /**
     * 对提取的信息去除有影响的字符
     * @param extractUri
     * @return
     */
    public static String removeSymbol(String extractUri){
        if (isNotEmptyObj(extractUri))
            extractUri = extractUri
//                    .replace("<", "")
//                    .replace(">", "")
//                    .replace(": ", "")
//                    .replace("：", "")
                    .replace("\"", "")
                    .replace("'", "")
                    .replace("\\", "")
                    .replaceAll("\n", "")
                    .replaceAll("\t", "")
                    .trim();
        return extractUri;
    }

    /**
     * 解码HTML字符串。
     *
     * @param htmlEncodedString 要解码的HTML编码字符串
     * @return 解码后的字符串
     */
    public static String decodeHtml(String htmlEncodedString) {
        if (isNotEmptyObj(htmlEncodedString))
            htmlEncodedString = StringEscapeUtils.unescapeHtml4(htmlEncodedString);
        return htmlEncodedString;
    }

    /**
     * 计算URl和路径拼接
     * @param reqUrl
     * @param path
     * @return
     */
    public static String concatUrlAddPath(String reqUrl, String path){
        String newUrl;
        try {
            //使用当前请求的reqUrl创建URI对象
            URI baseUrl = new URI(reqUrl);
            //计算出新的绝对URL//如果baseUrl是http://example.com/，而url是/about 计算结果就是 http://example.com/about。
            newUrl = baseUrl.resolve(path).toString();
            //stdout_println(LOG_DEBUG, String.format("[+] Path: %s -> New Url: %s", path, newUrl));
        } catch (Exception e) {
            //stderr_println(LOG_DEBUG, String.format("[!] Concat URL:[%s] + PATH:[%s] -> Error: %s", reqUrl, path, e.getMessage()));
            // 在发生异常时，尝试简单的字符串拼接
            newUrl = reqUrl.endsWith("/") && path.startsWith("/")
                    ? reqUrl + path.substring(1)
                    : reqUrl + "/" + path;
            newUrl = newUrl.replace("\\","");
            stderr_println(LOG_DEBUG, String.format("[!] Concat URL:[%s] + PATH:[%s] -> Error: %s, using fallback method.", reqUrl, path, e.getMessage()));
        }
        return newUrl;
    }

    /**
     * 计算URl和路径拼接
     * @param reqUrl
     * @param pathList
     * @return
     */
    public static List<String> concatUrlAddPath(String reqUrl, List<String> pathList){
        List<String> urlList = new ArrayList<>();
        for(String path : pathList){
            String newUrl = concatUrlAddPath(reqUrl, path);
            if (isNotEmptyObj(newUrl))
                urlList.add(newUrl);
        }
        return urlList;
    }

    public static void main(String[] args) {
        List<String> urlList = Arrays.asList("https://34.96.228.184:8888/club/forum.php",
                "https://34.96.228.184:8888/club/",
                "https://34.96.228.184:8888/bbs"
        );
        List<String> pathList = Arrays.asList("forum.php?mod=list&amp;type=lastpost&amp;page=1&amp;fid=75\",\"/promotions/jackpot2023\",\"data/cache/style_1_forum_index.css?lo9\",\"static/image/k8-2.png\",\"static/image/jackpot_prize_pool/2-pc2.png\",\"static/js/common.js?lo9\",\"plugin.php?id=qidou_assign\",\"/bbs/login\",\"forum.php?mod=list&amp;type=lastpost&amp;page=1&amp;fid=81\",\"search.php?searchsubmit=yes\",\"forum.php?mod=list&amp;type=lastpost&amp;page=1&amp;fid=83\",\"forum.php?mod=list&amp;type=lastpost&amp;page=1&amp;fid=82\",\"data/cache/style_1_widthauto.css?lo9\",\"static/image/home/k8logo.png\",\"static/image/jackpot_prize_pool/3-pc.png\",\"/bbs/register\",\"static/image/jackpot_prize_pool/arrow.webp\",\"member.php?mod=logging&amp;action=login&amp;loginsubmit=yes&amp;infloat=yes&amp;lssubmit=yes\",\"member.php?mod=register\",\"forum.php?mod=list&amp;type=lastpost&amp;page=1&amp;fid=74\",\"static/image/money-icon.png\",\"static/image/dialognew.png\",\"static/image/k8-app-icon.png\",\"template/default/css/use_common.css\",\"static/image/jackpot_prize_pool/2-image.png\",\"static/image/home/home.png\",\"data/cache/style_1_common.css?lo9\",\"/club/forum.php?mod=viewthread&tid=8153&fid=82\",\"static/image/home/activity.png\",\"static/image/home/game.png\",\"/club/forum.php?mod=viewthread&tid=8265&fid=82\",\"static/js/forum.js?lo9\",\"template/default/css/use_forum_viewthread.css?lo9\",\"template/default/css/nice-select.css?lo9\",\"/club/forum.php?mod=viewthread&tid=8264&fid=82\",\"static/js/logging.js?lo9\",\"/club/forum.php?mod=viewthread&tid=8266&fid=82\",\"static/image/common/favicon.ico\",\"static/image/home/xuetang.png\",\"template/default/css/dialog.css?lo9\",\"/club/forum.php?mod=viewthread&tid=8302fid=83\",\"static/image/money_circle.png\",\"member.php?mod=logging&action=login\",\"static/image/K8.png\",\"template/default/css/use_common.css?lo9\",\"forum.php?mod=ajax&action=notices\",\"plugin.php?id=jyjbwl:index\",\"static/image/k8.png\",\"static/image/k8_icon_0112.png\",\"static/image/jackpot_prize_pool/DINAlternateBold.ttf".split(","));
        for (String url : urlList)
            for (String path : pathList){
                path = formatSensitiveInfo(path);
                System.out.println(String.format("%s <--> %s %s", concatUrlAddPath(url,path), url, path));
            }
    }



}
