package utils;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import model.HttpMsgInfo;

import java.io.PrintWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RespParseUtils {
    private static PrintWriter stdout = BurpExtender.getStdout();
    private static PrintWriter stderr = BurpExtender.getStderr();
    private static IExtensionHelpers helpers = BurpExtender.getHelpers();;

    static final int CHUNK_SIZE = 20000; // 分割大小
    private static final Pattern FIND_URL_FROM_HTML_PATTERN = Pattern.compile("(http|https)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?");

    private static final Pattern CHINESE_PATTERN = Pattern.compile("[\u4E00-\u9FA5]");
    private static final Pattern FIND_PAHT_FROM_JS_PATTERN = Pattern.compile("(?:\"|')(((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})|((?:/|\\.\\./|\\./)[^\"'><,;|*()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,})|([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|/|;][^\"|']{0,}|))|([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\\?[^\"|']{0,}|)))(?:\"|')");
    private static final Pattern FIND_PATH_FROM_JS_PATTERN2 = Pattern.compile("\"(/[^\"\\s,@\\[\\]\\(\\)<>{}，%\\+：:/-]*)\"|'(/[^'\\\\s,@\\[\\]\\(\\)<>{}，%\\+：:/-]*?)'");

    public static void analysisReqData(HttpMsgInfo msgInfo) {
        List<String> urlSet = null;

        // 针对html页面提取
        List<String> getUrlsFromHtml = extractUrlsFromHtml(msgInfo.getReqUrl(), new String(msgInfo.getRespBytes()));
        urlSet.addAll(getUrlsFromHtml);

        stdout.println(String.format("Html Extract Counts: %s -> %s", msgInfo.getReqUrl(), getUrlsFromHtml.size()));
        if (getUrlsFromHtml.size()>0)
            for (String s : getUrlsFromHtml)
                stdout.println(String.format("Html Extract Url: %s", s));

//        // 针对JS页面提取
//        if (mime.equalsIgnoreCase("script") || mime.equalsIgnoreCase("html") || url.contains(".htm") || Utils.isNeedCheckExt(url)) {
//            List<String> getUrlsFromJS = findUrlFromJs(url, port, host, protocol, respText);
//            urlSet.addAll(getUrlsFromJS);
//
//            stdout.println(String.format("Js Extract Counts: %s From Url %s", getUrlsFromJS.size(), url));
//            if (getUrlsFromJS.size()>0) for (String s : getUrlsFromJS) stdout.println(String.format("[*] JS Extract Url: %s", s));
//        }

    }

    public static List<String> extractUrlsFromHtml(String uri, String htmlText) {
        // 使用正则表达式提取文本内容中的 URL
        List<String> urlList = new ArrayList<String>();
        if (!htmlText.contains("http")){
            return urlList;
        }
        int htmlLength = htmlText.length(); // html文件内容长度

        // 处理每个 CHUNK_SIZE 大小的片段
        for (int start = 0; start < htmlLength; start += CHUNK_SIZE) {
            int end = Math.min(start + CHUNK_SIZE, htmlLength);
            String htmlChunk = htmlText.substring(start, end);

            htmlChunk = htmlChunk.replace("\\/","/");
            Matcher matcher = FIND_URL_FROM_HTML_PATTERN.matcher(htmlChunk);
            while (matcher.find()) {
                String url = matcher.group();
                if (!url.contains("http") && url.startsWith("/")) {
                    try {
                        URI baseUri = new URI(uri);
                        url = baseUri.resolve(url).toString();
                    } catch (URISyntaxException e) {
                        continue;
                    }
                }
                try {
                    String subdomain = (new URL(uri)).getHost();
                    String domain = (new URL(url)).getHost();
                    if (!subdomain.equalsIgnoreCase(domain)) {
                        continue;
                    }
                } catch (Exception e) {
                    continue;
                }
//                //忽略静态文件后缀 OK
//                if (!isStaticFile(url) && !isStaticPathByPath(getPathFromUrl(url)) && !isWhiteDomain(url)) {
//                    urlList.add(url);
//                }
            }
        }
        return urlList;
    }

//    public static List<String> findUrlFromJs(String url, int port, String host, String protocol, String jsText){
//        // 方式一：原有的正则提取js中的url的逻辑
//        int jsLength = jsText.length(); // JavaScript 文件内容长度
//        Set<String> findUris = new LinkedHashSet<>();
//
//        // 处理每个 CHUNK_SIZE 大小的片段
//        for (int start = 0; start < jsLength; start += CHUNK_SIZE) {
//            int end = Math.min(start + CHUNK_SIZE, jsLength);
//            String jsChunk = jsText.substring(start, end);
//            Matcher m = FIND_PAHT_FROM_JS_PATTERN.matcher(jsChunk);
//            int matcher_start = 0;
//            while (m.find(matcher_start)){
//                String matchGroup = m.group(1);
//                if (matchGroup != null){
//                    if (!isStaticPathByPath(matchGroup)){
//                        findUris.add(matchGroup.replaceAll("\"","").replaceAll("'","").replaceAll("\n","").replaceAll("\t","").trim());
//                    }
//                }
//                matcher_start = m.end();
//            }
//            // 方式二：
//            Matcher matcher_result = FIND_PATH_FROM_JS_PATTERN2.matcher(jsChunk);
//            while (matcher_result.find()){
//                // 检查第一个捕获组
//                String group1 = matcher_result.group(1);
//                if (group1 != null) {
//                    if (!isStaticPathByPath(group1)){
//                        findUris.add(group1.trim());
//                    }
//                }
//                // 检查第二个捕获组
//                String group2 = matcher_result.group(2);
//                if (group2 != null) {
//                    if (!isStaticPathByPath(group2)){
//                        findUris.add(group2.trim());
//                    }
//                }
//            }
//        }
//
//
//        //常规补全提取到API
//        List<String> findUrls = new ArrayList<>();
//        for(String tempUrl:findUris){
//            findUrls.add(process_url(url, port, host, protocol, tempUrl));
//        }
//
//        //仅保留 本域名的 非白名单 的 URL
//        List<String> result = new ArrayList<String>();
//        for(String findUrl : findUrls){
//            try {
//                URL subURL = new URL(findUrl);
//                String subdomain = subURL.getHost();
//                if(subdomain.equalsIgnoreCase(host) && !isStaticFile(findUrl)){
//                    result.add(findUrl);
//                }
//
//            } catch (Exception e) {
//                BurpExtender.getStderr().println("findUrl error: " + findUrl);
//                e.printStackTrace(BurpExtender.getStderr());
//            }
//
//        }
//        return  result;
//    }

}
