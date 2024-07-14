package utils;

import model.HttpUrlInfo;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.regex.Pattern;

import static utils.BurpPrintUtils.*;
import static utils.ElementUtils.isEqualsOneKey;

public class AnalyseUriFilter {
    private static final Pattern CHINESE_PATTERN = Pattern.compile("[\u4E00-\u9FA5]");

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
        for (String path : matchList){
            if(!ElementUtils.isContainOneKey(path, blackPathKeys, false)){
                newList.add(path);
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
        for (String url : urls) {
            HttpUrlInfo urlInfo = new HttpUrlInfo(url);
            if (!ElementUtils.isContainOneKey(urlInfo.getRootUrlUsual(), blackHosts, false)) {
                list.add(url);
            }
        }
        return list;
    }

    /**
     * 过滤黑名单后缀名 图片后缀之类的不需要提取请求信息
     * @param uris
     * @param blackSuffixes
     * @return
     */
    public static List<String> filterBlackSuffixes(List<String> uris, List<String> blackSuffixes) {
        if (blackSuffixes==null || blackSuffixes.isEmpty()||uris==null||uris.isEmpty()) return uris;

        List<String> list = new ArrayList<>();
        for (String urlStr : uris) {
            String suffix = parseUrlExt(urlStr);
            if (!isEqualsOneKey(suffix, blackSuffixes, false))
                list.add(urlStr);
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
                stderr_println(LOG_DEBUG, String.format("[!] new URL(%s) -> Error: %s", urlStr, e.getMessage()));
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
        if (baseUri == null || baseUri == "" || baseUri == "/" ) return matchUriList;
        if (matchUriList == null || matchUriList.isEmpty()) return matchUriList;

        List<String> list = new ArrayList<>();
        for (String uri : matchUriList){
            if (!baseUri.contains(uri))  {
                // system_println(String.format("%s 不包含 %s", baseUri, uri));
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
                stderr_println(LOG_DEBUG, String.format("[!] new URL(%s) -> Error: %s", matchUrl, e.getMessage()));
                continue;
            }
            newUrlList.add(matchUrl);
        }
        return newUrlList;
    }

    /**
     * 粗略获取一个URI的后缀 支持PATH 忽略 # 号
     * @param uri
     * @return
     */
    private static String parseUrlExt(String uri) {
        String pureUrl = uri.substring(0, uri.contains("?") ? uri.indexOf("?") : uri.length());
        return (pureUrl.lastIndexOf(".") > -1 ? pureUrl.substring(pureUrl.lastIndexOf(".") + 1) : "").toLowerCase();
    }


    /**
     * 格式化所有URL 以HttpUrlInfo 内部为基准 统一带端口或不带默认端口
     * @param urls
     * @return
     */
    public static List<String> formatUrls(List<String> urls) {
        if (urls == null || urls.isEmpty()) return urls;

        List<String> list = new ArrayList<>();
        for (String urlStr : urls) {
            String url = new HttpUrlInfo(urlStr).getRawUrlUsual();
            list.add(url);
        }
        return list;
    }
}
