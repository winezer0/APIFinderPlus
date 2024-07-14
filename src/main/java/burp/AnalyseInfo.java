package burp;

import com.alibaba.fastjson2.JSONObject;
import database.Constants;
import model.AnalyseResultModel;
import model.FingerPrintRule;
import model.HttpMsgInfo;
import model.HttpUrlInfo;
import utils.AnalyseInfoUtils;
import utils.AnalyseUriFilter;
import utils.CastUtils;

import java.nio.charset.StandardCharsets;
import java.util.*;

import static utils.ElementUtils.isContainAllKey;
import static utils.ElementUtils.isEqualsOneKey;

public class AnalyseInfo {

    public static final String type = "type";
    public static final String describe = "describe";
    public static final String accuracy = "accuracy";
    public static final String important = "important";
    public static final String value = "value";

    public static final String URL_KEY = "URL_KEY";
    public static final String PATH_KEY = "PATH_KEY";

    private static final int MAX_HANDLE_SIZE = 50000; //如果数组超过 50000 个字符，则截断

    public static AnalyseResultModel analyseMsgInfo(HttpMsgInfo msgInfo) {
        //1、实现响应敏感信息提取
        List<JSONObject> findInfoList = findSensitiveInfoByRules(msgInfo);
        findInfoList = CastUtils.deduplicateJsonList(findInfoList); //去重提取结果
        //stdout_println(LOG_DEBUG, String.format("[+] 敏感信息数量:%s -> %s", reqUrl, findInfoList.size()));

        //2、实现响应中的 URL 和 PATH 提取
        Set<String> findUriSet = findUriInfoByRegular(msgInfo);
        Map<String, List> urlOrPathMap = SeparateUrlOrPath(findUriSet);

        String reqUrl = msgInfo.getUrlInfo().getRawUrlUsual();
        String reqPath = msgInfo.getUrlInfo().getPath();

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

        //返回 AnalyseInfoResultModel 结果数据
        AnalyseResultModel analyseResult = new AnalyseResultModel(
                findInfoList,
                findUrlList,
                findPathList,
                findApiList
        );
        return analyseResult;
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
        if (findUriList.isEmpty()) return findUriList;

        //过滤重复内容
        findUriList = CastUtils.deduplicateStringList(findUriList);
        //stdout_println(LOG_DEBUG, String.format("[*] 过滤重复PATH内容:%s", findUriList.size()));

        //过滤自身包含的Path (包含说明相同)
        findUriList = AnalyseUriFilter.filterUriBySelfContain(reqPath, findUriList);
        //stdout_println(LOG_DEBUG, String.format("[*] 过滤自身包含的PATH:%s", findUriList.size()));

        //过滤包含禁止关键字的PATH
        findUriList = AnalyseUriFilter.filterPathByContainUselessKey(findUriList, BurpExtender.CONF_BLACK_PATH_KEYS);
        //stdout_println(LOG_DEBUG, String.format("[*] 过滤包含禁止关键字的PATH:%s", findUriList.size()));

        //过滤等于禁止PATH的PATH
        findUriList = AnalyseUriFilter.filterPathByEqualUselessPath(findUriList, BurpExtender.CONF_BLACK_PATH_EQUALS);
        //stdout_println(LOG_DEBUG, String.format("[*] 过滤等于被禁止的PATH:%s", findUriList.size()));

        //过滤黑名单suffix
        findUriList = AnalyseUriFilter.filterBlackSuffixes(findUriList, BurpExtender.CONF_BLACK_URL_EXT);
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
        if (urlList.isEmpty()) return urlList;

        //过滤重复内容
        urlList = CastUtils.deduplicateStringList(urlList);
        //stdout_println(LOG_DEBUG, String.format("[*] 过滤重复URL内容:%s", urlList.size()));

        //对所有URL进行格式化
        urlList = AnalyseUriFilter.formatUrls(urlList);

        //过滤黑名单host
        urlList = AnalyseUriFilter.filterBlackHosts(urlList, BurpExtender.CONF_BLACK_URL_ROOT);
        //stdout_println(LOG_DEBUG, String.format("[*] 过滤黑名单主机:%s", urlList.size()));

        //过滤黑名单Path
        urlList = AnalyseUriFilter.filterBlackPaths(urlList, BurpExtender.CONF_BLACK_URL_PATH);
        //stdout_println(LOG_DEBUG, String.format("[*] 过滤黑名单路径:%s", urlList.size()));

        //过滤黑名单suffix
        urlList = AnalyseUriFilter.filterBlackSuffixes(urlList, BurpExtender.CONF_BLACK_URL_EXT);
        //stdout_println(LOG_DEBUG, String.format("[*] 过滤黑名单后缀:%s", urlList.size()));

        if (reqUrl != null && reqUrl.trim().length() > 0){
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
    public static List<JSONObject> findSensitiveInfoByRules(HttpMsgInfo msgInfo) {
        // 使用HashSet进行去重，基于equals和hashCode方法判断对象是否相同
        List<JSONObject> findInfoJsonList = new ArrayList<>();

        //遍历规则进行提取
        for (FingerPrintRule rule : BurpExtender.fingerprintRules){
            //忽略关闭的选项 // 过滤掉配置选项
            if (!rule.getIsOpen() || rule.getType().contains(Constants.RULE_CONF_PREFIX)){
                continue;
            }

            // 根据不同的规则 配置 查找范围
            String locationText;
            switch (rule.getLocation()) {
                case "urlPath":
                    locationText = msgInfo.getUrlInfo().getPath();
                    break;
                case "body":
                    locationText = new String(msgInfo.getRespInfo().getBodyBytes(), StandardCharsets.UTF_8);
                    break;
                case "header":
                    locationText = new String(msgInfo.getRespInfo().getHeaderBytes(), StandardCharsets.UTF_8);
                    break;
                default:
                    locationText = new String(msgInfo.getRespBytes(), StandardCharsets.UTF_8);
                    break;
            }

            //当存在字符串不为空时进行匹配
            if (locationText.length() > 0) {
                locationText = AnalyseInfoUtils.SubString(locationText, MAX_HANDLE_SIZE);

                //多个关键字匹配
                if (rule.getMatch().equals("keyword"))
                    if(isContainAllKey(locationText, rule.getKeyword(), false)){
                        //匹配关键字模式成功,应该标记敏感信息 关键字匹配的有效信息就是关键字
                        JSONObject findInfo = formatMatchInfoToJson(rule, String.valueOf(rule.getKeyword()));
                        //stdout_println(LOG_DEBUG, String.format("[+] 关键字匹配敏感信息:%s", findInfo.toJSONString()));
                        findInfoJsonList.add(findInfo);
                    }

                //多个正则匹配
                if (rule.getMatch().equals("regular")){
                    for (String patter : rule.getKeyword()){
                        Set<String> groups = AnalyseInfoUtils.extractInfoWithChunk(locationText, patter);
                        if (!groups.isEmpty()){
                            JSONObject findInfo = formatMatchInfoToJson(rule, String.valueOf(new ArrayList<>(groups)));
                            //stdout_println(LOG_DEBUG, String.format("[+] 正则匹配敏感信息:%s", findInfo.toJSONString()));
                            findInfoJsonList.add(findInfo);
                        }
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
        Set<String> allUriSet = new HashSet<>();

        //转换响应体,后续可能需要解决编码问题
        String respBody = new String(msgInfo.getRespInfo().getBodyBytes(), StandardCharsets.UTF_8);

        //截取最大响应体长度
        respBody = AnalyseInfoUtils.SubString(respBody, MAX_HANDLE_SIZE);

        // 针对html页面提取 直接的URL 已完成
        Set<String> extractUrl = AnalyseInfoUtils.extractDirectUrls(msgInfo.getUrlInfo().getRawUrlUsual(), respBody);
        //stdout_println(LOG_DEBUG, String.format("[*] 初步提取URL: %s -> %s", msgInfo.getUrlInfo().getReqUrl(), extractUrl.size()));
        allUriSet.addAll(extractUrl);

        // 针对JS页面提取 当属于 CONF_EXTRACT_SUFFIX 后缀（含后缀为空）的时候 、是脚本类型的时候
        if (isEqualsOneKey(msgInfo.getUrlInfo().getSuffix(), BurpExtender.CONF_EXTRACT_SUFFIX, true)
                || msgInfo.getRespInfo().getInferredMimeType().contains("script")) {
            Set<String> extractUri = AnalyseInfoUtils.extractUriFromJs(respBody);
            //stdout_println(LOG_DEBUG, String.format("[*] 初步提取URI: %s -> %s", msgInfo.getUrlInfo().getReqUrl(), extractUri.size()));
            allUriSet.addAll(extractUri);
        }
        return allUriSet;
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
