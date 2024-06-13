package utils;

import model.HttpMsgInfo;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static utils.BurpPrintUtils.*;
import static utils.ElementUtils.isEqualsOneKey;

public class InfoAnalyseUtils {
    public static final String URL_KEY = "URL_KEY";
    public static final String PATH_KEY = "PATH_KEY";
    public static final String INFO_KEY = "INFO_KEY";
    static final int CHUNK_SIZE = 20000; // 分割大小
    private static final int RESULT_SIZE = 1024;

    private static final Pattern CHINESE_PATTERN = Pattern.compile("[\u4E00-\u9FA5]");
    private static final Pattern FIND_URL_FROM_HTML_PATTERN = Pattern.compile("(http|https)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?");
    private static final Pattern FIND_PATH_FROM_JS_PATTERN = Pattern.compile("(?:\"|')(((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})|((?:/|\\.\\./|\\./)[^\"'><,;|*()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,})|([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|/|;][^\"|']{0,}|))|([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\\?[^\"|']{0,}|)))(?:\"|')");
    private static final Pattern FIND_PATH_FROM_JS_PATTERN2 = Pattern.compile("\"(/[^\"\\s,@\\[\\]\\(\\)<>{}，%\\+：:/-]*)\"|'(/[^'\\\\s,@\\[\\]\\(\\)<>{}，%\\+：:/-]*?)'");


    /**
     * 过滤无用的提取路径 通过判断和指定的路径相等
     * @param matchList
     * @return
     */
    public static List<String> filterPathByEqualUselessPath(List<String> matchList, List<String>  blackPathEquals) {
        List<String> newList = new ArrayList<>();
        for (String path : matchList){
            if(!isEqualsOneKey(path, blackPathEquals, false)){
                newList.add(path);
            }
        }
        return newList;
    }


    /**
     * 过滤无用的提取路径 通过判断是否包含无用关键字
     * @param matchList
     * @return
     */
    public static List<String> filterPathByContainUselessKey(List<String> matchList, List<String> blackPathKeys) {
        if (matchList == null || matchList.isEmpty()) return matchList;

        List<String> newList = new ArrayList<>();
        for (String s : matchList){
            if(!ElementUtils.isContainOneKey(s, blackPathKeys, false)){
                newList.add(s);
            }
        }
        return newList;
    }


    /**
     * 过滤无用的提取路径 通过判断是否包含中文路径
     * @param matchList
     * @return
     */
    public static List<String> filterPathByContainChinese(List<String> matchList) {
        if (matchList == null || matchList.isEmpty()) return matchList;

        List<String> newList = new ArrayList<>();
        for (String s : matchList){
            if(!CHINESE_PATTERN.matcher(s).find()){
                newList.add(s);
            }
        }
        return newList;
    }


    /**
     * 过滤黑名单HOST域名
     * @param urls
     * @param blackHosts
     * @return
     */
    public static List<String> filterBlackHosts(List<String> urls, List<String> blackHosts) {
        if (blackHosts==null || blackHosts.isEmpty()||urls==null||urls.isEmpty()) return urls;

        List<String> list = new ArrayList<>();
        for (String urlStr : urls) {
            try {
                URL url = new URL(urlStr);
                String host = url.getHost();
                if (!ElementUtils.isContainOneKey(host, blackHosts, false)) {
                    list.add(urlStr);
                }else {
                    stdout_println(LOG_DEBUG, String.format("[*] Black Hosts Filter %s", urlStr));
                }
            } catch (MalformedURLException e) {
                stderr_println(String.format("[!] new URL(%s) -> Error: %s", urlStr, e.getMessage()));
            }
        }
        return list;
    }


    /**
     * 过滤黑名单后缀名 图片后缀之类的不需要提取请求信息
     * @param urls
     * @param blackSuffixes
     * @return
     */
    public static List<String> filterBlackSuffixes(List<String> urls, List<String> blackSuffixes) {
        if (blackSuffixes==null || blackSuffixes.isEmpty()||urls==null||urls.isEmpty()) return urls;

        List<String> list = new ArrayList<>();
        for (String urlStr : urls) {
            String suffix = HttpMsgInfo.parseUrlExt(urlStr);
            if (!isEqualsOneKey(suffix, blackSuffixes, false)) {
                list.add(urlStr);
            }else {
                stdout_println(LOG_DEBUG, String.format("[*] Black Suffix Filter %s", urlStr));
            }
        }
        return list;
    }


    /**
     * 过滤黑名单路径 /jquery.js 之类的不需要提取信息
     * @param urls
     * @param blackPaths
     * @return
     */
    public static List<String> filterBlackPaths(List<String> urls, List<String> blackPaths) {
        if (urls == null || urls.isEmpty()) return urls;

        List<String> list = new ArrayList<>();
        for (String urlStr : urls) {
            try {
                URL url = new URL(urlStr);
                String path = url.getPath();
                if (!ElementUtils.isContainOneKey(path, blackPaths, false)) {
                    list.add(urlStr);
                }else {
                    stdout_println(LOG_DEBUG, String.format("[*] Black Paths Filter %s", urlStr));
                }
            } catch (MalformedURLException e) {
                stderr_println(String.format("[!] new URL(%s) -> Error: %s", urlStr, e.getMessage()));
            }
        }
        return list;
    }


    /**
     * 过滤提取的值 在请求字符串内的项
     * @param baseUri
     * @param matchUriList
     * @return
     */
    public static List<String> filterUriBySelfContain(String baseUri, List<String> matchUriList) {
        if (baseUri == null || baseUri == "" || matchUriList == null || matchUriList.isEmpty()) return matchUriList;

        List<String> list = new ArrayList<>();
        for (String uri : matchUriList){
            if (!baseUri.contains(uri))  {
                system_println(String.format("%s 不包含 %s", baseUri, uri));
                list.add(uri);}
        }
        return list;
    }


    /**
     * 过滤提取出的URL列表 仅保留自身域名的
     * @param baseHost
     * @param matchUrlList
     * @return
     */
    public static List<String> filterUrlByMainHost(String baseHost, List<String> matchUrlList){
        if (baseHost == null || baseHost == "" || matchUrlList == null || matchUrlList.isEmpty()) return matchUrlList;

        List<String> newUrlList = new ArrayList<>();
        for (String matchUrl : matchUrlList){
            //对比提取出来的URL和请求URL的域名部分是否相同，不相同的一般不是
            try {
                String newHost = (new URL(matchUrl)).getHost();
                if (!newHost.contains(baseHost))
                    continue;
            } catch (Exception e) {
                stderr_println(String.format("[!] new URL(%s) -> Error: %s", matchUrl, e.getMessage()));
                continue;
            }
            newUrlList.add(matchUrl);
        }
        return newUrlList;
    }


    /**
     * List<String> list 元素去重
     */
    public static List<String> removeDuplicates(List<String> list) {
        return new ArrayList<>(new HashSet<>(list));
    }


    /**
     * 拆分提取出来的Url集合中的URl和Path
     * @param matchUriSet
     * @return
     */
    public static Map<String, List> SeparateUrlOrPath(Set<String> matchUriSet) {
        Map<String, List> setMap = new HashMap<>();
        ArrayList<String> urlList = new ArrayList<>();
        ArrayList<String> pathList = new ArrayList<>();

        for (String uri : matchUriSet){
            if (uri.contains("https://") || uri.contains("http://")){
                urlList.add(uri);
            }else {
                pathList.add(uri);
            }
        }

        setMap.put(URL_KEY,  urlList);
        setMap.put(PATH_KEY, pathList);
        return setMap;
    }


    /**
     * 正则提取文本中的内容
     * @param willFindText
     * @param patter
     * @return
     */
    public static Set<String> regularMatchInfo(String willFindText, String patter) {
        Set<String> groups = new HashSet<>();
        try{
            for (int start = 0; start < willFindText.length(); start += CHUNK_SIZE) {
                int end = Math.min(start + CHUNK_SIZE, willFindText.length());
                String beFindContentChunk = willFindText.substring(start, end);

                Pattern pattern = Pattern.compile(patter, Pattern.CASE_INSENSITIVE);
                Matcher matcher = pattern.matcher(beFindContentChunk);
                while (matcher.find()) {
                    String group = matcher.group();
                    //格式化响应
                    group = removeSymbol(group);
                    
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

    private static boolean isUsefulValue(String group) {
        String BlackValues = "admin@admin.com";
        if (isEqualsOneKey(group, BlackValues, false)){
            stderr_println(LOG_DEBUG, String.format("提取结果 [%s] 禁止保存", group));
            return false;
        }

        if (group.contains(":")){
            if (group.split(":", 2)[1].trim()==""){
                stderr_println(LOG_DEBUG, String.format("提取结果 [%s] 没有价值", group));
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
    public static List<String> extractDirectUrls(String reqUrl, String htmlText) {
        // 使用正则表达式提取文本内容中的 URL
        List<String> urlList = new ArrayList<>();

        //直接跳过没有http关键字的场景
        if (!htmlText.contains("http")){
            return urlList;
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
                String matchUrl = matcher.group();
                //识别相对于网站根目录的URL路径 //不包含http 并且以/开头的（可能是一个相对URL）
                if (!matchUrl.contains("http") && matchUrl.startsWith("/")) {
                    try {
                        //使用当前请求的reqUrl创建URI对象
                        URI baseUrl = new URI(reqUrl);
                        //计算出新的绝对URL//如果baseUrl是http://example.com/，而url是/about 计算结果就是 http://example.com/about。
                        matchUrl = baseUrl.resolve(matchUrl).toString();
                    } catch (URISyntaxException e) {
                        continue;
                    }
                }
                urlList.add(matchUrl);
            }
        }
        return urlList;
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
                    findUris.add(removeSymbol(matchGroup));
                }
                matcher_start = m.end();
            }

            // 方式二：
            Matcher matcher_result = FIND_PATH_FROM_JS_PATTERN2.matcher(jsChunk);
            while (matcher_result.find()){
                // 检查第一个捕获组
                String group1 = matcher_result.group(1);
                if (group1 != null) {
                    findUris.add(removeSymbol(group1));
                }
                // 检查第二个捕获组
                String group2 = matcher_result.group(2);
                if (group2 != null) {
                    findUris.add(removeSymbol(group2));
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
}
