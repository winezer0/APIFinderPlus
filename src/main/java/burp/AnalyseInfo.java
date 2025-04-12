package burp;

import EnumType.LocationType;
import EnumType.MatchType;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import database.Constants;
import model.AnalyseUrlResultModel;
import model.FingerPrintRule;
import model.HttpMsgInfo;
import model.HttpUrlInfo;
import utilbox.TextUtils;
import utils.*;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

import static utils.BurpPrintUtils.*;
import static utils.CastUtils.isEmptyObj;
import static utils.CastUtils.isNotEmptyObj;
import static utils.ElementUtils.isContainAllKey;

public class AnalyseInfo {

    public static final String type = "type";
    public static final String describe = "describe";
    public static final String accuracy = "accuracy";
    public static final String important = "important";
    public static final String value = "value";
    public static final String matchType = "matchType";

    public static final String URL_KEY = "URL_KEY";
    public static final String PATH_KEY = "PATH_KEY";

    public static AnalyseUrlResultModel analyseMsgInfo(HttpMsgInfo msgInfo) {
        //1、实现响应敏感信息提取
        JSONArray findInfoJsonArray = findSensitiveInfoByRules(msgInfo);
        findInfoJsonArray = CastUtils.deduplicateJsonArray(findInfoJsonArray); //去重提取结果
        //stdout_println(LOG_DEBUG, String.format("[+] 敏感信息数量:%s -> %s", reqUrl, findInfoList.size()));

        //2、实现响应中的 URL 和 PATH 提取
        Set<String> findUriSet = findUriInfoByRegular(msgInfo);
        //进行HTML解码
        findUriSet = AnalyseInfoUtils.decodeHtml(findUriSet);
        //去除不可打印内容
        findUriSet = AnalyseInfoUtils.keepAsciiPrintableChars(findUriSet);
        Map<String, List> urlOrPathMap = SeparateUrlOrPath(findUriSet);

        String reqUrl = msgInfo.getUrlInfo().getRawUrlUsual();
        String reqPath = msgInfo.getUrlInfo().getPathToFile();

        //采集 URL 处理
        List<String> findUrlList = urlOrPathMap.get(URL_KEY);
        //stdout_println(LOG_DEBUG, String.format("[*] 初步采集URL数量:%s -> %s", reqUrl, findUrlList.size()));
        //实现响应url过滤
        findUrlList = filterFindUrls(reqUrl, findUrlList, BurpExtender.onlyScopeDomain);
        //stdout_println(LOG_DEBUG, String.format("[*] 过滤重复URL内容:%s -> %s", reqUrl, findUrlList.size()));

        //采集 path 处理
        List<String> findPathList = urlOrPathMap.get(PATH_KEY);
        //stdout_println(LOG_DEBUG, String.format("[*] 初步采集PATH数量:%s -> %s", reqUrl, findUrlList.size()));
        //实现响应Path过滤
        findPathList = filterFindPaths(reqPath, findPathList, false);
        //stdout_println(LOG_DEBUG, String.format("[*] 过滤重复PATH内容:%s -> %s", reqUrl, findPathList.size()));

        //基于Path和请求URL组合简单的URL 已验证，常规网站采集的PATH生成的URL基本都是正确的
        List<String> findApiList = AnalyseInfoUtils.concatUrlAddPath(reqUrl, findPathList);
        //stdout_println(LOG_DEBUG, String.format("[+] 简单计算API数量: %s -> %s", reqUrl, findApiList.size()));
        //实现 初步计算API的过滤
        findApiList = filterFindUrls(reqUrl, findApiList, BurpExtender.onlyScopeDomain);
        //stdout_println(LOG_DEBUG, String.format("[*] 过滤重复API内容:%s -> %s", reqUrl, findApiList.size()));

        //判断是否有敏感信息
        boolean hasImportant = isHasImportant(findInfoJsonArray);

        //返回 AnalyseInfoResultModel 结果数据
        AnalyseUrlResultModel analyseResult = new AnalyseUrlResultModel(
                msgInfo.getUrlInfo().getRawUrlUsual(),
                findInfoJsonArray,
                findUrlList,
                findPathList,
                findApiList,
                hasImportant
        );
        return analyseResult;
    }

    private static boolean isHasImportant(JSONArray findInfoJsonArray) {
        boolean hasImportant = false;
        if (findInfoJsonArray != null && findInfoJsonArray.size() > 0){
            for (int i = 0; i < findInfoJsonArray.size(); i++) {
                Object item = findInfoJsonArray.get(i);
                if (item instanceof JSONObject) {
                    JSONObject findInfo = (JSONObject) item;
                    if (findInfo.getBoolean(important)){
                        hasImportant = true;
                        stdout_println(LOG_DEBUG, String.format("[!] 发现重要敏感信息: %s", findInfo.toJSONString()));
                        break;
                    }
                } else {
                    // 处理非 JSONObject 元素的情况
                    stdout_println(LOG_ERROR, "[!] 非 JSONObject 元素被发现: " + item.toString());
                }
            }
        }
        return hasImportant;
    }

    /**
     * 整合过滤分析出来的URL列表
     * @param reqPath
     * @param findUriList
     * @param filterChinese
     * @return
     */
    private static List<String> filterFindPaths(String reqPath, List<String> findUriList, boolean filterChinese) {
        //跳过空列表的情况
        if (isEmptyObj(findUriList)) return findUriList;

        //过滤重复内容
        findUriList = CastUtils.deduplicateStringList(findUriList);
        //stdout_println(LOG_DEBUG, String.format("[*] 过滤重复PATH内容:%s", findUriList.size()));

        //过滤自身包含的Path (包含说明相同)
        findUriList = AnalyseUriFilter.filterUriBySelfContain(reqPath, findUriList);
        //stdout_println(LOG_DEBUG, String.format("[*] 过滤自身包含的PATH:%s", findUriList.size()));

        //过滤包含禁止关键字的PATH
        findUriList = AnalyseUriFilter.filterPathByContainUselessKey(findUriList, BurpExtender.CONF_BLACK_URI_PATH_KEYS);
        //stdout_println(LOG_DEBUG, String.format("[*] 过滤包含禁止关键字的PATH:%s", findUriList.size()));

        //过滤等于禁止PATH的PATH
        findUriList = AnalyseUriFilter.filterPathByEqualUselessPath(findUriList, BurpExtender.CONF_BLACK_EXTRACT_PATH_EQUAL);
        //stdout_println(LOG_DEBUG, String.format("[*] 过滤等于被禁止的PATH:%s", findUriList.size()));

        //过滤黑名单suffix
        findUriList = AnalyseUriFilter.filterBlackSuffixes(findUriList, BurpExtender.CONF_BLACK_URI_EXT_EQUAL);
        //stdout_println(LOG_DEBUG, String.format("[*] 过滤黑名单后缀:%s", findUriList.size()));

        //过滤包含中文的PATH
        if (filterChinese){
            findUriList = AnalyseUriFilter.filterPathByContainChinese(findUriList);
            //stdout_println(LOG_DEBUG, String.format("[*] 过滤中文PATH内容:%s", findUriList.size()));
        }

        return findUriList;
    }

    /**
     * 整合过滤分析出来的 Path 列表
     * @param reqUrl
     * @param urlList
     * @param onlyScopeDomain
     * @return
     */
    public static List<String> filterFindUrls(String reqUrl, List<String> urlList, boolean onlyScopeDomain) {
        //跳过空列表的情况
        if (isEmptyObj(urlList)) return urlList;

        //过滤重复内容
        urlList = CastUtils.deduplicateStringList(urlList);
        //stdout_println(LOG_DEBUG, String.format("[*] 过滤重复URL内容:%s", urlList.size()));

        //对所有URL进行格式化
        urlList = AnalyseUriFilter.formatUrls(urlList);

        //过滤黑名单host
        urlList = AnalyseUriFilter.filterBlackHosts(urlList, BurpExtender.CONF_BLACK_ROOT_URL);
        //stdout_println(LOG_DEBUG, String.format("[*] 过滤黑名单主机:%s", urlList.size()));

        //过滤黑名单Path
        urlList = AnalyseUriFilter.filterBlackPaths(urlList, BurpExtender.CONF_BLACK_URI_PATH_KEYS);
        //stdout_println(LOG_DEBUG, String.format("[*] 过滤黑名单路径:%s", urlList.size()));

        //过滤黑名单suffix
        urlList = AnalyseUriFilter.filterBlackSuffixes(urlList, BurpExtender.CONF_BLACK_URI_EXT_EQUAL);
        //stdout_println(LOG_DEBUG, String.format("[*] 过滤黑名单后缀:%s", urlList.size()));

        if (isNotEmptyObj(reqUrl)){
            //格式化为URL对象进行操作
            HttpUrlInfo urlInfo = new HttpUrlInfo(reqUrl);

            //过滤自身包含的URL (包含说明相同) //功能测试通过
            urlList = AnalyseUriFilter.filterUriBySelfContain(urlInfo.getRawUrlUsual(), urlList);
            //stdout_println(LOG_DEBUG, String.format("[*] 过滤自身包含的URL:%s", urlList.size()));

            //仅保留主域名相关URL
            if (onlyScopeDomain){
                urlList = AnalyseUriFilter.filterUrlByMainHost(urlInfo.getRootDomain(), urlList);
                //stdout_println(LOG_DEBUG, String.format("[*] 过滤非主域名URL:%s", urlList.size()));
            }
        }

        return urlList;
    }

    /**
     * 根据规则提取敏感信息
     * @param msgInfo
     * @return
     */
    public static JSONArray findSensitiveInfoByRules(HttpMsgInfo msgInfo) {
        // 使用HashSet进行去重，基于equals和hashCode方法判断对象是否相同
        JSONArray findInfoJsonList = new JSONArray();

        //预获取匹配位置
        String reqPath = msgInfo.getUrlInfo().getPathToFile();
        String respBody = new String(msgInfo.getRespInfo().getBodyBytes(), StandardCharsets.UTF_8);
        String respHeaders = new String(msgInfo.getRespInfo().getHeaderBytes(), StandardCharsets.UTF_8);
        String respContent = new String(msgInfo.getRespBytes(), StandardCharsets.UTF_8);
        String respTitle = msgInfo.getRespTitle(); //提前获取Title数据, 防止匹配次数过多
        String respIconHash = msgInfo.getRespInfo().getIconHash(); //获取IconHash数据

        //进行JSON解码
        if( msgInfo.getRespInfo().getInferredMimeType().contains("JSON")|| IProxyScanner.forceDecodeUnicode){
            respBody = TextUtils.decodeAll(respBody);
            respContent = TextUtils.decodeAll(respContent);
        }

        //遍历规则进行提取
        for (FingerPrintRule rule : BurpExtender.fingerprintRules){
            //忽略关闭的选项 // 过滤掉配置选项
            if (!rule.getIsOpen()
                    || rule.getType().contains(Constants.RULE_CONF_PREFIX)
                    || rule.getLocation().equals(LocationType.CONFIG.getValue())){
                continue;
            }

            // 根据不同的规则 配置 查找范围
            String locationText;

            LocationType locationType;
            try {
                locationType = LocationType.fromValue(rule.getLocation());
            } catch (IllegalArgumentException e) {
                // 处理未知位置类型，默认为 RESPONSE
                stderr_println(String.format("Error locationType was found!!! %s", e.getMessage()));
                locationType = LocationType.RESPONSE;
            }

            switch (locationType) {
                case PATH:
                    locationText = reqPath;
                    break;
                case TITLE:
                    locationText = respTitle;
                    break;
                case ICON_HASH:
                    locationText = respIconHash;
                    break;
                case BODY:
                    locationText = respBody;
                    break;
                case HEADER:
                    locationText = respHeaders;
                    break;
                case RESPONSE:
                default:
                    locationText = respContent;
                    break;
            }

            //当存在字符串不为空时进行匹配
            if (locationText != null && locationText.length() > 0) {
                String currMatchType = rule.getMatchType();
                List<String> currMatchKeys = rule.getMatchKeys();

                //多个关键字任意匹配 当把多个关键字用|分割时可以使用
                if (currMatchType.equals(MatchType.ANY_KEYWORD.getValue()))
                    for (String matchKey : currMatchKeys){
                        if(isContainAllKey(locationText, matchKey, false)){
                            JSONObject findInfo = formatMatchInfoToJson(rule, matchKey);
                            findInfoJsonList.add(findInfo);
                        }
                    }

                //多个关键字全部需要匹配
                else if (currMatchType.equals(MatchType.ALL_KEYWORD.getValue())) {
                    boolean allMatched = true; // 标志位，用于判断是否所有正则都匹配成功
                    for (String matchKey : currMatchKeys){
                        if(!isContainAllKey(locationText, matchKey, false)){
                            allMatched = false;
                            break;
                        }
                    }
                    if (allMatched) {
                        JSONObject findInfo = formatMatchInfoToJson(rule, CastUtils.listToString(currMatchKeys));
                        findInfoJsonList.add(findInfo);
                    }
                }

                //多个正则匹配任意一个
                else if (currMatchType.equals(MatchType.ANY_REGULAR.getValue())){
                    for (String matchPatter : currMatchKeys){
                        Set<String> groups = AnalyseInfoUtils.extractInfoWithChunk(locationText, matchPatter, IProxyScanner.maxPatterChunkSize);
                        if (isNotEmptyObj(groups)){
                            JSONObject findInfo = formatMatchInfoToJson(rule, String.valueOf(new ArrayList<>(groups)));
                            findInfoJsonList.add(findInfo);
                        }
                    }
                }

                // 如果匹配类型是 "ALL"，需要所有正则都匹配成功
                else if (currMatchType.equals(MatchType.ALL_REGULAR.getValue())) {
                    boolean allMatched = true;
                    Set<String> allGroups = new HashSet<>(); //存储所有匹配结果
                    for (String pattern : currMatchKeys) {
                        Set<String> groups = AnalyseInfoUtils.extractInfoWithChunk(locationText, pattern, IProxyScanner.maxPatterChunkSize);
                        if (isNotEmptyObj(groups)) {
                            allGroups.addAll(groups);
                        } else {
                            allMatched = false; // 如果有一个正则没有匹配成功，则标志位置为 false
                            break; // 提前退出循环
                        }
                    }
                    // 如果所有正则都匹配成功 就保存所有匹配的信息
                    if (allMatched) {
                        JSONObject findInfo = formatMatchInfoToJson(rule, CastUtils.setToString(allGroups));
                        findInfoJsonList.add(findInfo);
                    }
                }
            }
        }
        return findInfoJsonList;
    }

    /**
     * 基于规则和结果生成格式化的敏感信息存储结构
     * @param rule
     * @param group
     * @return
     */
    private static JSONObject formatMatchInfoToJson(FingerPrintRule rule, String group) {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put(type, rule.getType()); // "type": "敏感内容",
        jsonObject.put(describe, rule.getDescribe()); //"describe": "身份证",
        jsonObject.put(accuracy, rule.getAccuracy()); //"accuracy": "high"
        jsonObject.put(important, rule.getIsImportant()); //"isImportant": true,
        jsonObject.put(matchType, rule.getMatchType()); //匹配位置
        jsonObject.put(value, group);
        return jsonObject;
    }

    /**
     * 提取响应体中的URL和PATH
     * @param msgInfo
     * @return
     */
    public static Set<String> findUriInfoByRegular(HttpMsgInfo msgInfo) {
        //存储所有提取的URL/URI
        Set<String> allExtractUriSet = new HashSet<>();

        //转换响应体,后续可能需要解决编码问题
        String respBody = new String(msgInfo.getRespInfo().getBodyBytes(), StandardCharsets.UTF_8);
        String rawUrlUsual = msgInfo.getUrlInfo().getRawUrlUsual();

        if (isNotEmptyObj(respBody) && respBody.trim().length() > 5 ){
            //进行Json解码
            if(msgInfo.getRespInfo().getInferredMimeType().contains("JSON")||IProxyScanner.forceDecodeUnicode){
                respBody = TextUtils.decodeAll(respBody);
            }

            // 针对通用的页面提取
            for (Pattern pattern:BurpExtender.URI_MATCH_REGULAR_COMPILE){
                Set<String> extractUri = AnalyseInfoUtils.extractUriMode1(respBody, pattern, IProxyScanner.maxPatterChunkSize);
                allExtractUriSet.addAll(extractUri);
                stdout_println(LOG_DEBUG, String.format("[*] 常规模式提取URI: %s -> %s", rawUrlUsual, extractUri.size()));
            }

            // 针对webpack js页面的提取 判断文件名是否是JS后缀
            if ("js".equals(msgInfo.getUrlInfo().getSuffix())){
                Set<String> extractUri = respBody.length() > 30000 ? RespWebpackJsParser.parseWebpackSimpleChunk(respBody, IProxyScanner.maxPatterChunkSize) : RespWebpackJsParser.parseWebpackSimple(respBody);
                allExtractUriSet.addAll(extractUri);
                stdout_println(LOG_DEBUG, String.format("[*] Webpack提取URI: %s -> %s", rawUrlUsual, extractUri.size()));
            }
        }
        return allExtractUriSet;
    }

    /**
     * 拆分提取出来的Uri集合中的URl和Path
     * @param matchUriSet
     * @return
     */
    public static Map<String, List> SeparateUrlOrPath(Set<String> matchUriSet) {
        Map<String, List> hashMap = new HashMap<>();
        ArrayList<String> urlList = new ArrayList<>();
        ArrayList<String> pathList = new ArrayList<>();

        for (String uri : matchUriSet){
            if (uri.contains("https://") || uri.contains("http://")){
                urlList.add(uri);
            }else {
                pathList.add(uri);
            }
        }

        hashMap.put(URL_KEY,  urlList);
        hashMap.put(PATH_KEY, pathList);
        return hashMap;
    }
}
