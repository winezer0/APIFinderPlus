package burp;

import burp.BurpExtender;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import model.FingerPrintRule;
import model.HttpMsgInfo;
import model.RespInfo;
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


public class MsgDataAnalysis {
    private static final PrintWriter stdout = BurpExtender.getStdout();
    private static final PrintWriter stderr = BurpExtender.getStderr();

    static final int CHUNK_SIZE = 20000; // 分割大小
    private static final Pattern FIND_URL_FROM_HTML_PATTERN = Pattern.compile("(http|https)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?");

    private static final Pattern CHINESE_PATTERN = Pattern.compile("[\u4E00-\u9FA5]");
    private static final Pattern FIND_PATH_FROM_JS_PATTERN = Pattern.compile("(?:\"|')(((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})|((?:/|\\.\\./|\\./)[^\"'><,;|*()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,})|([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|/|;][^\"|']{0,}|))|([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\\?[^\"|']{0,}|)))(?:\"|')");
    private static final Pattern FIND_PATH_FROM_JS_PATTERN2 = Pattern.compile("\"(/[^\"\\s,@\\[\\]\\(\\)<>{}，%\\+：:/-]*)\"|'(/[^'\\\\s,@\\[\\]\\(\\)<>{}，%\\+：:/-]*?)'");

    public static final String URL_KEY = "url";
    public static final String PATH_KEY = "path";

    public static final String type = "type";
    public static final String describe = "describe";
    public static final String accuracy = "accuracy";
    public static final String important = "important";
    public static final String value = "value";

    private static final int MAX_SIZE = 50000; //如果数组超过 50000 个字节，则截断
    private static final int RESULT_SIZE = 1024;

    public static RespInfo analysisMsgInfo(HttpMsgInfo msgInfo) {
        //提取URL和PATH信息
        Set<String> uriSet = findUriInfo(msgInfo);
        //拆分提取的URL和PATH为两个set 用于进一步处理操作
        Map<String, List> map = SeparateUrlOrPath(uriSet);
        List<String> urlList = map.get(URL_KEY);
        List<String> pathList = map.get(PATH_KEY);

        //过滤无用的请求URL
        urlList = filterUrlByConfig(urlList); //根据用户配置的黑名单域名|路径|后缀 信息过滤无用的URL
        urlList = filterUrlByHost(msgInfo.getReqHost(),  urlList); //仅保留本域名的URL // Todo: 优化思路 可选择关闭|改为主域名 增加攻击面
        stdout.println(String.format("[+] 有效URL数量: %s -> %s", msgInfo.getReqUrl(), urlList.size()));
        for (String s : urlList)
            stdout.println(String.format("[*] INFO URL: %s", s));

        //过滤无用的PATH内容
        pathList = filterPathByContainUselessKey(pathList); //过滤包含禁止关键字的PATH
        pathList = filterPathByEqualUselessPath(pathList); //过滤等于禁止PATH的PATH
        pathList = filterPathByContainChinese(pathList); //过滤包含中文的PATH

        stdout.println(String.format("[+] 有效PATH数量: %s -> %s", msgInfo.getReqUrl(), pathList.size()));
        for (String s : pathList)
            stdout.println(String.format("[*] INFO PATH: %s", s));

        // 实现响应敏感信息提取
        JSONArray findInfoArray = findSensitiveInfoByConfig(msgInfo);
        stdout.println(String.format("[+] 敏感信息数量:%s -> %s", findInfoArray.size(), findInfoArray.toJSONString()));

        //返回敏感信息内容
        RespInfo respInfo = new RespInfo();
        respInfo.setUrlList(urlList);
        respInfo.setPathList(pathList);
        respInfo.setInfoArray(findInfoArray);
        return respInfo;
    }

    /**
     * 提取响应体中的URL和PATH
     * @param msgInfo
     * @return
     */
    public static Set<String> findUriInfo(HttpMsgInfo msgInfo) {
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

        return uriSet;
    }

    /**
     * 根据规则提取敏感信息
     * @param msgInfo
     * @return
     */
    public static JSONArray findSensitiveInfoByConfig(HttpMsgInfo msgInfo) {
        // 使用HashSet进行去重，基于equals和hashCode方法判断对象是否相同
        Set<JSONObject> findInfosSet = new HashSet<>();

        //遍历规则进行提取
        for (FingerPrintRule rule : BurpExtender.fingerprintRules){
            //忽略关闭的选项 // 过滤掉配置选项
            if (!rule.getIsOpen() || rule.getType().contains("CONF_")){
                continue;
            }

            // 定位查找范围
            String willFindText;
            if ("body".equalsIgnoreCase(rule.getLocation())) {
                willFindText = new String(msgInfo.getRespBytes(), StandardCharsets.UTF_8);
            } else if ("urlPath".equalsIgnoreCase(rule.getLocation())) {
                willFindText = msgInfo.getReqPath();
            } else {
                stderr.println("[!] 未知指纹位置：" + rule.getLocation());
                continue;
            }

            // 开始提取操作
            //多个关键字匹配
            if (rule.getMatch().equals("keyword"))
                if(ElementUtils.isContainAllKey(willFindText, rule.getKeyword(), false)){
                    //匹配关键字模式成功,应该标记敏感信息
                    JSONObject findInfo = initInfoJsonObj(rule, String.valueOf(rule.getKeyword()));
                    stdout.println(String.format("[+] 关键字匹配敏感信息:%s", findInfo.toJSONString()));
                    findInfosSet.add(findInfo);
                }

            //多个正则匹配
            if (rule.getMatch().equals("regular")){
                for (String patter : rule.getKeyword()){
                    try{
                        for (int start = 0; start < willFindText.length(); start += CHUNK_SIZE) {
                            int end = Math.min(start + CHUNK_SIZE, willFindText.length());
                            String beFindContentChunk = willFindText.substring(start, end);

                            Pattern pattern = Pattern.compile(patter, Pattern.CASE_INSENSITIVE);
                            Matcher matcher = pattern.matcher(beFindContentChunk);
                            while (matcher.find()) {
                                String group = matcher.group();
                                //响应超过长度时 截断
                                if (group.length() > RESULT_SIZE) {
                                    group = group.substring(0, RESULT_SIZE);
                                }

                                JSONObject findInfo = initInfoJsonObj(rule, group);
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
    private static JSONObject initInfoJsonObj(FingerPrintRule rule, String group) {
        JSONObject findInfo = new JSONObject();
        findInfo.put(type, rule.getType()); // "type": "敏感内容",
        findInfo.put(describe, rule.getDescribe()); //"describe": "身份证",
        findInfo.put(accuracy, rule.getAccuracy()); //"accuracy": "high"
        findInfo.put(important, rule.getIsImportant()); //"isImportant": true,
        findInfo.put(value, group);
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
            Matcher m = FIND_PATH_FROM_JS_PATTERN.matcher(jsChunk);
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
     * 过滤提取出的URL列表 仅保留指定域名的
     * @param rawDomain
     * @param matchUrlList
     * @return
     */
    public static List<String> filterUrlByHost(String rawDomain,  List<String> matchUrlList){
        if (rawDomain == null || rawDomain == "" || matchUrlList == null || matchUrlList.isEmpty()) return matchUrlList;

        List<String> newUrlList = new ArrayList<>();
        for (String matchUrl : matchUrlList){
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
            newUrlList.add(matchUrl);
        }
        return newUrlList;
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
            if (uri.contains("://")){
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
     * 过滤无用的提取路径 通过判断和指定的路径相等
     * @param matchList
     * @return
     */
    public static List<String> filterPathByEqualUselessPath(List<String> matchList) {
        List<String> newList = new ArrayList<>();
        for (String s : matchList){
            if(!ElementUtils.isEqualsOneKey(s, CONF_BLACK_PATH_EQUALS, false)){
                newList.add(s);
            }
        }
        return newList;
    }

    /**
     * 过滤无用的提取路径 通过判断是否包含无用关键字
     * @param matchList
     * @return
     */
    public static List<String> filterPathByContainUselessKey(List<String> matchList) {
        if (matchList == null || matchList.isEmpty()) return matchList;

        List<String> newList = new ArrayList<>();
        for (String s : matchList){
            if(!ElementUtils.isContainOneKey(s, CONF_BLACK_PATH_KEYS, false)){
                newList.add(s);
            }
        }
        return newList;
    }

    /**
     * 基于配置信息过滤提取的请求URL
     * @param matchList
     * @return
     */
    private static List<String> filterUrlByConfig(List<String> matchList) {
        if (matchList == null || matchList.isEmpty()) return matchList;

        List<String> newList = new ArrayList<>();
        for (String s : matchList){
            try {
                URL url = new URL(s);
                //匹配黑名单域名 //排除被禁止的域名URL, baidu.com等常被应用的域名, 这些js是一般是没用的, 为空时不操作
                if(ElementUtils.isContainOneKey(url.getHost(), CONF_BLACK_URL_DOMAIN, false)){
                    continue;
                }

                // 排除黑名单后缀 jpg、mp3等等
                if(ElementUtils.isEqualsOneKey(HttpMsgInfo.parseUrlExt(s), CONF_BLACK_URL_EXT, false)){
                    continue;
                }

                //排除黑名单路径 这些JS文件是通用的、无价值的、
                if(ElementUtils.isContainOneKey(url.getPath(), CONF_BLACK_URL_PATH, false)){
                    continue;
                }

                newList.add(s);
            } catch (Exception e) {
                stderr.println(String.format("[!] new URL(%s) -> Error: %s", s, e.getMessage()));
                continue;
            }


            newList.add(s);
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

}
