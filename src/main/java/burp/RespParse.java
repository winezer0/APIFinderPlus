package burp;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import model.FingerPrintRule;
import model.HttpMsgInfo;
import utils.ElementUtils;

import java.io.PrintWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static burp.BurpExtender.*;


public class RespParse {
    private static PrintWriter stdout = BurpExtender.getStdout();
    private static PrintWriter stderr = BurpExtender.getStderr();
    private static IExtensionHelpers helpers = BurpExtender.getHelpers();;

    static final int CHUNK_SIZE = 20000; // 分割大小
    private static final Pattern FIND_URL_FROM_HTML_PATTERN = Pattern.compile("(http|https)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?");

    private static final Pattern CHINESE_PATTERN = Pattern.compile("[\u4E00-\u9FA5]");
    private static final Pattern FIND_PAHT_FROM_JS_PATTERN = Pattern.compile("(?:\"|')(((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})|((?:/|\\.\\./|\\./)[^\"'><,;|*()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,})|([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|/|;][^\"|']{0,}|))|([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\\?[^\"|']{0,}|)))(?:\"|')");
    private static final Pattern FIND_PATH_FROM_JS_PATTERN2 = Pattern.compile("\"(/[^\"\\s,@\\[\\]\\(\\)<>{}，%\\+：:/-]*)\"|'(/[^'\\\\s,@\\[\\]\\(\\)<>{}，%\\+：:/-]*?)'");

    public static final String URL_KEY = "url";
    public static final String PATH_KEY = "path";

    private static final int MAX_SIZE = 50000; //如果数组超过 50000 个字节，则截断
    private static final int RESULT_SIZE = 1024;

    public static void analysisReqData(HttpMsgInfo msgInfo) {
        //存储所有提取的URL/URI
        Set<String> uriSet = new HashSet<>();

        //转换响应体,后续可能需要解决编码问题
        String respBody = new String(
                HttpMsgInfo.getBodyBytes(msgInfo.getRespBytes(), msgInfo.getRespBodyOffset()),
                StandardCharsets.UTF_8);

        // 针对html页面提取 直接的URL 已完成
        List<String> extractUrlsFromHtml = extractDirectUrls(msgInfo.getReqUrl(), respBody);
        stdout.println(String.format("[*] 初步提取的URL数量: %s -> %s", msgInfo.getReqUrl(), extractUrlsFromHtml.size()));
        uriSet.addAll(extractUrlsFromHtml);

        // 针对JS页面提取
        if (ElementUtils.isEqualsOneKey(msgInfo.getReqPathExt(), CONF_EXTRACT_SUFFIX, true)
                || msgInfo.getInferredMimeType().contains("script")) {
            Set<String> extractUriFromJs = extractUriFromJs(respBody);
            stdout.println(String.format("[*] 初步提取的URI数量: %s -> %s", msgInfo.getReqUrl(), extractUriFromJs.size()));
            uriSet.addAll(extractUriFromJs);
        }

        //拆分提取的URL和PATH为两个set 用于进一步处理操作
        Map<String, Set> setMap = SplitExtractUrlOrPath(uriSet);
        Set<String> urlSet = setMap.get(URL_KEY);
        Set<String> pathSet = setMap.get(PATH_KEY);

        //过滤无用的请求URL
        //根据用户配置文件信息过滤其他无用的URL
        urlSet = filterUrlByConfig(urlSet);
        //保留本域名的URL,会检测格式 Todo: 优化思路 可选择关闭|改为主域名 增加攻击面
        urlSet = filterUrlByHost(msgInfo.getReqHost(),  urlSet);
        if (urlSet.size() > 0)
            stdout.println(String.format("[+] 有效URL数量: %s -> %s", msgInfo.getReqUrl(), urlSet.size()));
            for (String s : urlSet)
                stdout.println(String.format("[*] INFO URL: %s", s));

        //过滤无用的PATH内容
        pathSet = filterUselessPathsByKey(pathSet);
        pathSet = filterUselessPathsByEqual(pathSet);
        if (pathSet.size() > 0)
            stdout.println(String.format("[+] 有效URL数量: %s -> %s", msgInfo.getReqUrl(), pathSet.size()));
            for (String s : pathSet)
                stdout.println(String.format("[*] INFO PATH: %s", s));


        // 实现响应敏感信息提取
        JSONArray findInfoArray = findInfoByConfig(msgInfo);
        stdout.println(String.format("[+] 提取敏感信息数量:%s -> %s", findInfoArray.size(), findInfoArray.toJSONString()));

        //TODO: 必须：输出已提取的信息
        //Todo: 必须：对PATH进行计算,计算出真实的URL路径

        //TODO: 扩展：递归探测已提取的URL (使用burp内置的库,流量需要在logger在logger中显示)
        //TODO: 扩展：实现UI显示

        //TODO: 扩展：增加通过响应关键字排除 404或者错误页面的功能
        //TODO: 扩展：排除已经访问的URL  (可选|非必要, 再次访问时都会过滤掉的,不会加入进程列表)
        //TODO: 扩展：初始化时,给已提取URL PATH和 已添加URL赋值 (可选|非必要,不会加入进程列表)

    }

    /**
     * 根据规则提取敏感信息
     * @param msgInfo
     * @return
     */
    private static JSONArray findInfoByConfig(HttpMsgInfo msgInfo) {
        // 使用HashSet进行去重，基于equals和hashCode方法判断对象是否相同
        Set<JSONObject> findInfosSet = new HashSet<>();

        //遍历规则进行提取
        for (FingerPrintRule rule : BurpExtender.fingerprintRules){
            // 过滤掉配置选项
            if (rule.getType().contains("CONF_")) {
                continue;
            }
            //忽略关闭的选项
            if (!rule.getIsOpen()){
                continue;
            }

            // 定位查找范围
            String beFindContent = "";
            if ("body".equalsIgnoreCase(rule.getLocation())) {
                beFindContent = new String(msgInfo.getRespBytes(), StandardCharsets.UTF_8);
            } else if ("urlPath".equalsIgnoreCase(rule.getLocation())) {
                beFindContent = msgInfo.getReqPath();
            } else {
                stderr.println("[!] 未知指纹位置：" + rule.getLocation());
                continue;
            }

            // 开始提取操作
            //多个关键字匹配
            if (rule.getMatch().equals("keyword"))
                if(ElementUtils.isContainAllKey(beFindContent, rule.getKeyword(), false)){
                    //匹配关键字模式成功,应该标记敏感信息
                    JSONObject findInfo = getFindInfoJsonObj(rule, String.valueOf(rule.getKeyword()));
                    stdout.println(String.format("[+] 关键字匹配敏感信息:%s", findInfo.toJSONString()));
                    findInfosSet.add(findInfo);
                }

            //多个正则匹配
            if (rule.getMatch().equals("regular")){
                for (String patter : rule.getKeyword()){
                    try{
                        for (int start = 0; start < beFindContent.length(); start += CHUNK_SIZE) {
                            int end = Math.min(start + CHUNK_SIZE, beFindContent.length());
                            String beFindContentChunk = beFindContent.substring(start, end);

                            Pattern pattern = Pattern.compile(patter, Pattern.CASE_INSENSITIVE);
                            Matcher matcher = pattern.matcher(beFindContentChunk);
                            while (matcher.find()) {
                                String group = matcher.group();
                                //响应超过长度时 截断
                                if (group.length() > RESULT_SIZE) {
                                    group = group.substring(0, RESULT_SIZE);
                                }

                                JSONObject findInfo = getFindInfoJsonObj(rule, group);
                                stdout.println(String.format("[+] 正则匹配敏感信息:%s", findInfo.toJSONString()));
                                findInfosSet.add(findInfo);
                            }
                        }
                    } catch (PatternSyntaxException e) {
                        stderr.println("[!] 正则表达式语法错误: " + patter);
                    } catch (NullPointerException e) {
                        stderr.println("[!] 正则表达式传入null: " + patter);
                    } catch (Exception e){
                        stderr.println("[!] 匹配出现其他报错: " + e.getMessage());
                        e.printStackTrace();
                    }
                }
            }
        }

        return new JSONArray(findInfosSet);
    }

    /**
     * 基于规则和结果生成格式化的信息
     * @param rule
     * @param group
     * @return
     */
    private static JSONObject getFindInfoJsonObj(FingerPrintRule rule, String group) {
        JSONObject findInfo = new JSONObject();
        findInfo.put("type", rule.getType());
        findInfo.put("important", rule.getIsImportant());
        findInfo.put("describe", rule.getDescribe());
        findInfo.put("value", group);
        return findInfo;
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
                //stdout.println(String.format("[*] 初步提取信息:%s", matchUrl));
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
            Matcher m = FIND_PAHT_FROM_JS_PATTERN.matcher(jsChunk);
            int matcher_start = 0;
            while (m.find(matcher_start)){
                String matchGroup = m.group(1);
                if (matchGroup != null){
                    findUris.add(formatExtractUri(matchGroup));
                }
                matcher_start = m.end();
            }

            // 方式二：
            Matcher matcher_result = FIND_PATH_FROM_JS_PATTERN2.matcher(jsChunk);
            while (matcher_result.find()){
                // 检查第一个捕获组
                String group1 = matcher_result.group(1);
                if (group1 != null) {
                    findUris.add(formatExtractUri(group1));
                }
                // 检查第二个捕获组
                String group2 = matcher_result.group(2);
                if (group2 != null) {
                    findUris.add(formatExtractUri(group2));
                }
            }
        }

        //需要排除非本域名的URL  已实现
        //需要排除非黑名单域名、黑名单路径、黑名单的API

        return findUris;
    }

    /**
     * 对提取的URL进行简单的格式处理
     * @param extractUri
     * @return
     */
    public static String formatExtractUri(String extractUri){
        return  extractUri
                .replaceAll("\"", "")
                .replaceAll("'", "")
                .replaceAll("\n", "")
                .replaceAll("\t", "")
                .trim();
    }

    /**
     * 通过new Url功能过滤提取出来的URl
     * @param matchUrlSet
     * @return
     */
    public static Set<String> filterUrlByNew(Set<String> matchUrlSet){
        if (matchUrlSet == null || matchUrlSet.isEmpty()) return matchUrlSet;

        Set<String> newUrlSet = new HashSet<>();
        for (String matchUrl : matchUrlSet){
            try {
                URL url = new URL(matchUrl);
                newUrlSet.add(url.toString());
            } catch (Exception e) {
                stderr.println(String.format("[!] new URL(%s) -> Error: %s", matchUrl, e.getMessage()));
                continue;
            }
        }
        return newUrlSet;
    }

    /**
     * 过滤提取出的URL列表 仅保留指定域名的
     * @param rawDomain
     * @param matchUrlSet
     * @return
     */
    public static Set<String> filterUrlByHost(String rawDomain,  Set<String> matchUrlSet){
        if (rawDomain == null || rawDomain == "" || matchUrlSet == null || matchUrlSet.isEmpty()) return matchUrlSet;

        Set<String> newUrlSet = new HashSet<>();
        for (String matchUrl : matchUrlSet){
            //对比提取出来的URL和请求URL的域名部分是否相同，不相同的一般不是
            try {
                String newDomain = (new URL(matchUrl)).getHost();
                if (!rawDomain.equalsIgnoreCase(newDomain)) {
                    continue;
                }
            } catch (Exception e) {
                stderr.println(String.format("[!] new URL(%s) -> Error: %s", matchUrl, e.getMessage()));
                continue;
            }
            newUrlSet.add(matchUrl);
        }
        return newUrlSet;
    }

    /**
     * 拆分提取出来的Url集合中的URl和Path
     * @param matchUrlSet
     * @return
     */
    public static Map<String, Set> SplitExtractUrlOrPath(Set<String> matchUrlSet) {
        Map<String, Set> setMap = new HashMap<>();
        Set<String> urlSet = new HashSet<>();
        Set<String> pathSet = new HashSet<>();

        for (String matchUrl : matchUrlSet){
            if (matchUrl.contains("://")){
                urlSet.add(matchUrl);
            }else {
                pathSet.add(matchUrl);
            }
        }

        setMap.put(URL_KEY, urlSet);
        setMap.put(PATH_KEY, pathSet);
        return setMap;
    }

    /**
     * 过滤无用的提取路径 通过判断和指定的路径相等
     * @param matchPathSet
     * @return
     */
    private static Set<String> filterUselessPathsByEqual(Set<String> matchPathSet) {
        Set<String> newPathSet = new HashSet<>();
        for (String path : matchPathSet){
            if(!ElementUtils.isEqualsOneKey(path, CONF_BLACK_PATH_EQUALS, false)){
                newPathSet.add(path);
            }
        }
        return newPathSet;
    }

    /**
     * 过滤无用的提取路径 通过判断是否包含无用关键字
     * @param matchPathSet
     * @return
     */
    private static Set<String> filterUselessPathsByKey(Set<String> matchPathSet) {
        Set<String> newPathSet = new HashSet<>();
        for (String path : matchPathSet){
            if(!ElementUtils.isContainOneKey(path, CONF_BLACK_PATH_KEYS, false)){
                newPathSet.add(path);
            }
        }
        return newPathSet;
    }

    /**
     * 基于配置信息过滤提取的请求URL
     * @param matchUrlSet
     * @return
     */
    private static Set<String> filterUrlByConfig(Set<String> matchUrlSet) {
        if (matchUrlSet == null || matchUrlSet.isEmpty()) return matchUrlSet;

        Set<String> newUrlSet = new HashSet<>();
        for (String matchUrl : matchUrlSet){
            try {
                URL url = new URL(matchUrl);
                //匹配黑名单域名 //排除被禁止的域名URL, baidu.com等常被应用的域名, 这些js是一般是没用的, 为空时不操作
                if(ElementUtils.isContainOneKey(url.getHost(), CONF_BLACK_URL_DOMAIN, false)){
                    continue;
                }

                // 排除黑名单后缀 jpg、mp3等等
                if(ElementUtils.isEqualsOneKey(HttpMsgInfo.parseUrlExt(matchUrl), CONF_BLACK_URL_EXT, false)){
                    continue;
                }

                //排除黑名单路径 这些JS文件是通用的、无价值的、
                if(ElementUtils.isContainOneKey(url.getPath(), CONF_BLACK_URL_PATH, false)){
                    continue;
                }

                newUrlSet.add(matchUrl);
            } catch (Exception e) {
                stderr.println(String.format("[!] new URL(%s) -> Error: %s", matchUrl, e.getMessage()));
                continue;
            }


            newUrlSet.add(matchUrl);
        }
        return newUrlSet;
    }
}
