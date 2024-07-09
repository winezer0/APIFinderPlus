package utils;

import org.apache.commons.text.StringEscapeUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static utils.BurpPrintUtils.*;
import static utils.ElementUtils.isEqualsOneKey;

public class InfoAnalyseUtils {

    static final int CHUNK_SIZE = 20000; // 分割大小
    private static final int RESULT_SIZE = 1024;

    private static final Pattern FIND_URL_FROM_HTML_PATTERN = Pattern.compile("(http|https)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?");
    private static final Pattern FIND_PATH_FROM_JS_PATTERN = Pattern.compile("(?:\"|')(((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})|((?:/|\\.\\./|\\./)[^\"'><,;|*()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,})|([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|/|;][^\"|']{0,}|))|([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\\?[^\"|']{0,}|)))(?:\"|')");
    private static final Pattern FIND_PATH_FROM_JS_PATTERN2 = Pattern.compile("\"(/[^\"\\s,@\\[\\]\\(\\)<>{}，%\\+：:/-]*)\"|'(/[^'\\\\s,@\\[\\]\\(\\)<>{}，%\\+：:/-]*?)'");


    /**
     * 支持自动截断的正则提取文本中的内容
     * @param text
     * @param patter
     * @return
     */
    public static Set<String> extractInfoWithChunk(String text, String patter) {
        Set<String> groups = new HashSet<>();
        try{
            for (int start = 0; start < text.length(); start += CHUNK_SIZE) {
                int end = Math.min(start + CHUNK_SIZE, text.length());
                String beFindContentChunk = text.substring(start, end);

                Pattern pattern = Pattern.compile(patter, Pattern.CASE_INSENSITIVE);
                Matcher matcher = pattern.matcher(beFindContentChunk);
                while (matcher.find()) {
                    String group = matcher.group();
                    //格式化响应
                    group = formatUri(group);

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
        String BlackValues = "admin@admin.com";
        if (isEqualsOneKey(group, BlackValues, false)){
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
     * 从html内容中提取url信息
     * @param reqUrl
     * @param htmlText
     * @return
     */
    public static Set<String> extractDirectUrls(String reqUrl, String htmlText) {
        // 使用正则表达式提取文本内容中的 URL
        Set<String> urlSet = new HashSet<>();

        //直接跳过没有http关键字的场景
        if (!htmlText.contains("http")){
            return urlSet;
        }

        // html文件内容长度
        int htmlLength = htmlText.length();

        // 处理每个 CHUNK_SIZE 大小的片段
        for (int start = 0; start < htmlLength; start += CHUNK_SIZE) {
            int end = Math.min(start + CHUNK_SIZE, htmlLength);
            String htmlChunk = htmlText.substring(start, end);

            htmlChunk = htmlChunk.replace("\\/","/");
            Matcher matcher = FIND_URL_FROM_HTML_PATTERN.matcher(htmlChunk);
            while (matcher.find()) {
                String matchUri = formatUri(matcher.group());
                //识别相对于网站根目录的URL路径 //不包含http 并且以/开头的（可能是一个相对URL）
                if (!matchUri.contains("http") && matchUri.startsWith("/")) {
                    try {
                        //使用当前请求的reqUrl创建URI对象
                        URI baseUrl = new URI(reqUrl);
                        //计算出新的绝对URL//如果baseUrl是http://example.com/，而url是/about 计算结果就是 http://example.com/about。
                        matchUri = baseUrl.resolve(matchUri).toString();
                    } catch (URISyntaxException e) {
                        stderr_println(LOG_DEBUG, String.format("[!] new URL(%s) -> Error: %s", matchUri, e.getMessage()));
                        continue;
                    }
                }
                urlSet.add(matchUri);
            }
        }
        return urlSet;
    }


    /**
     * 从Js内容中提取uri/url信息
     * @param jsText
     * @return
     */
    public static Set<String> extractUriFromJs(String jsText){
        // 方式一：原有的正则提取js中的url的逻辑
        int jsLength = jsText.length(); // JavaScript 文件内容长度
        Set<String> findUris = new LinkedHashSet<>();

        // 处理每个 CHUNK_SIZE 大小的片段
        for (int start = 0; start < jsLength; start += CHUNK_SIZE) {
            int end = Math.min(start + CHUNK_SIZE, jsLength);
            String jsChunk = jsText.substring(start, end);
            Matcher m = FIND_PATH_FROM_JS_PATTERN.matcher(jsChunk);
            int matcher_start = 0;
            while (m.find(matcher_start)){
                String matchGroup = m.group(1);
                if (matchGroup != null){
                    findUris.add(formatUri(matchGroup));
                }
                matcher_start = m.end();
            }

            // 方式二：
            Matcher matcher_result = FIND_PATH_FROM_JS_PATTERN2.matcher(jsChunk);
            while (matcher_result.find()){
                // 检查第一个捕获组
                String group1 = matcher_result.group(1);
                if (group1 != null) {
                    findUris.add(formatUri(group1));
                }
                // 检查第二个捕获组
                String group2 = matcher_result.group(2);
                if (group2 != null) {
                    findUris.add(formatUri(group2));
                }
            }
        }

        return findUris;
    }

    /**
     * 对提取的信息进行简单的格式处理
     * @param extractUri
     * @return
     */
    public static String formatUri(String extractUri){
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
        if (extractUri != null || extractUri != "")
            extractUri = extractUri
                    .replaceAll("\"", "")
                    .replaceAll("'", "")
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
        if (htmlEncodedString != null || htmlEncodedString != "")
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
        } catch (URISyntaxException e) {
            stderr_println(LOG_DEBUG, String.format("[!] Concat URL:[%s] + PATH:[%s] -> Error: %s", reqUrl, path, e.getMessage()));
            return null;
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
            if (newUrl != null && newUrl.trim() != "")
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
                path = formatUri(path);
                System.out.println(String.format("%s <--> %s %s", concatUrlAddPath(url,path), url, path));
            }
    }



}
