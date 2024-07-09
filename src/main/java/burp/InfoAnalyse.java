package burp;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import model.FingerPrintRule;
import model.HttpMsgInfo;

import java.nio.charset.StandardCharsets;
import java.util.*;

import static burp.BurpExtender.*;
import static utils.BurpPrintUtils.LOG_DEBUG;
import static utils.BurpPrintUtils.stdout_println;
import static utils.ElementUtils.isContainAllKey;
import static utils.ElementUtils.isEqualsOneKey;
import static utils.InfoAnalyseUtils.*;
import static utils.InfoUriFilterUtils.*;

public class InfoAnalyse {

    public static final String type = "type";
    public static final String describe = "describe";
    public static final String accuracy = "accuracy";
    public static final String important = "important";
    public static final String value = "value";

    public static final String URL_KEY = "URL_KEY";
    public static final String PATH_KEY = "PATH_KEY";
    public static final String INFO_KEY = "INFO_KEY";
    public static final String API_KEY = "API_KEY";

    private static final int MAX_HANDLE_SIZE = 50000; //如果数组超过 50000 个字符，则截断

    public static JSONObject analysisMsgInfo(HttpMsgInfo msgInfo) {
        //实现响应敏感信息提取
        JSONArray analysedInfoArray = findSensitiveInfoByRules(msgInfo);
        stdout_println(LOG_DEBUG, String.format("[+] 敏感信息数量:%s", analysedInfoArray.size()));

        //提取URL和PATH信息
        Set<String> analysedUriSet = findUriInfo(msgInfo);
        stdout_println(LOG_DEBUG, String.format("[*] 采集URL|PATH数量:%s", analysedUriSet.size()));

        //拆分提取的URL和PATH为两个 List 用于进一步处理操作
        Map<String, List> separateUrlOrPathMap = SeparateUrlOrPath(analysedUriSet);

        //采集 URL 处理
        List<String> analysedUrlList = separateUrlOrPathMap.get(URL_KEY);
        stdout_println(LOG_DEBUG, String.format("[*] 初步采集URL数量:%s", analysedUrlList.size()));

        //实现响应url过滤
        if (!analysedUrlList.isEmpty()){
            //过滤重复内容
            analysedUrlList = deduplicateStringList(analysedUrlList);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤重复URL内容:%s", analysedUrlList.size()));

            //仅保留主域名相关URL
            analysedUrlList = filterUrlByMainHost(msgInfo.getUrlInfo().getReqRootDomain(), analysedUrlList);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤非主域名URL:%s", analysedUrlList.size()));

            //过滤自身包含的URL (包含说明相同) //功能测试通过
            analysedUrlList = filterUriBySelfContain(msgInfo.getReqUrl(), analysedUrlList);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤自身包含的URL:%s", analysedUrlList.size()));

            //过滤黑名单host
            analysedUrlList = filterBlackHosts(analysedUrlList, CONF_BLACK_URL_HOSTS);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤黑名单主机:%s", analysedUrlList.size()));

            //过滤黑名单Path
            analysedUrlList = filterBlackPaths(analysedUrlList, CONF_BLACK_URL_PATH);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤黑名单路径:%s", analysedUrlList.size()));

            //过滤黑名单suffix
            analysedUrlList = filterBlackSuffixes(analysedUrlList, CONF_BLACK_URL_EXT);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤黑名单后缀:%s", analysedUrlList.size()));
        }

        //采集 path 处理
        List<String> analysedPathList = separateUrlOrPathMap.get(PATH_KEY);
        stdout_println(LOG_DEBUG, String.format("[*] 初步采集PATH数量:%s -> %s", analysedUrlList.size(), analysedUrlList));

        //实现响应Path过滤
        if (!analysedPathList.isEmpty()){
            //过滤重复内容
            analysedPathList = deduplicateStringList(analysedPathList);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤重复PATH内容:%s", analysedPathList.size()));

            //过滤自身包含的Path (包含说明相同)
            analysedPathList = filterUriBySelfContain(msgInfo.getUrlInfo().getReqPath(), analysedPathList);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤自身包含的PATH:%s", analysedPathList.size()));

            //过滤包含禁止关键字的PATH
            analysedPathList = filterPathByContainUselessKey(analysedPathList, CONF_BLACK_PATH_KEYS);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤包含禁止关键字的PATH:%s", analysedPathList.size()));

            //过滤包含中文的PATH
            analysedPathList = filterPathByContainChinese(analysedPathList);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤中文PATH内容:%s", analysedPathList.size()));

            //过滤等于禁止PATH的PATH
            analysedPathList = filterPathByEqualUselessPath(analysedPathList, CONF_BLACK_PATH_EQUALS);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤等于被禁止的PATH:%s", analysedPathList.size()));

        }

        //基于Path简单计算URL 已验证，常规网站采集的PATH生成的URL基本都是正确的
        List<String> analysedApiList = UrlAddPath(msgInfo.getReqUrl(), analysedPathList);
        stdout_println(LOG_DEBUG, String.format("[+] 简单计算API数量: %s -> %s", msgInfo.getReqUrl(), analysedApiList.size()));

        //实现 初步计算API的过滤
        if (!analysedApiList.isEmpty()){
            analysedApiList = deduplicateStringList(analysedApiList);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤重复API内容:%s", analysedApiList.size()));
        }

        //返回最终分析结果
        JSONObject analyseInfoJsonObj = new JSONObject();
        analyseInfoJsonObj.put(URL_KEY, analysedUrlList);
        analyseInfoJsonObj.put(PATH_KEY, analysedPathList);
        analyseInfoJsonObj.put(API_KEY, analysedApiList);
        analyseInfoJsonObj.put(INFO_KEY, analysedInfoArray);
        //stdout_println(LOG_DEBUG, String.format("[+] 最终解析结果:%s", analyseInfoJsonObj.toJSONString()));
        return analyseInfoJsonObj;
    }

    /**
     * 根据规则提取敏感信息
     * @param msgInfo
     * @return
     */
    public static JSONArray findSensitiveInfoByRules(HttpMsgInfo msgInfo) {
        // 使用HashSet进行去重，基于equals和hashCode方法判断对象是否相同
        Set<JSONObject> findInfosSet = new HashSet<>();

        //遍历规则进行提取
        for (FingerPrintRule rule : BurpExtender.fingerprintRules){
            //忽略关闭的选项 // 过滤掉配置选项
            if (!rule.getIsOpen() || rule.getType().contains("CONF_")){
                continue;
            }

            // 根据不同的规则 配置 查找范围
            String locationText;
            switch (rule.getLocation()) {
                case "urlPath":
                    locationText = msgInfo.getUrlInfo().getReqPath();
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
                locationText = SubString(locationText, MAX_HANDLE_SIZE);

                //多个关键字匹配
                if (rule.getMatch().equals("keyword"))
                    if(isContainAllKey(locationText, rule.getKeyword(), false)){
                        //匹配关键字模式成功,应该标记敏感信息 关键字匹配的有效信息就是关键字
                        JSONObject findInfo = formatMatchInfoToJson(rule, String.valueOf(rule.getKeyword()));
                        stdout_println(LOG_DEBUG, String.format("[+] 关键字匹配敏感信息:%s", findInfo.toJSONString()));
                        findInfosSet.add(findInfo);
                    }

                //多个正则匹配
                if (rule.getMatch().equals("regular")){
                    for (String patter : rule.getKeyword()){
                        Set<String> groups = extractInfoWithChunk(locationText, patter);
                        if (!groups.isEmpty()){
                            JSONObject findInfo = formatMatchInfoToJson(rule, String.valueOf(new ArrayList<>(groups)));
                            stdout_println(LOG_DEBUG, String.format("[+] 正则匹配敏感信息:%s", findInfo.toJSONString()));
                            findInfosSet.add(findInfo);
                        }
                    }
                }
            }
        }

        return new JSONArray(findInfosSet);
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
    public static Set<String> findUriInfo(HttpMsgInfo msgInfo) {
        //存储所有提取的URL/URI
        Set<String> uriSet = new HashSet<>();

        //转换响应体,后续可能需要解决编码问题
        String respBody = new String(msgInfo.getRespInfo().getBodyBytes(), StandardCharsets.UTF_8);

        //截取最大响应体长度
        respBody = SubString(respBody, MAX_HANDLE_SIZE);

        // 针对html页面提取 直接的URL 已完成
        Set<String> extractUrlsFromHtml = extractDirectUrls(msgInfo.getReqUrl(), respBody);
        uriSet.addAll(extractUrlsFromHtml);
        stdout_println(LOG_DEBUG, String.format("[*] 初步提取URL: %s -> %s", msgInfo.getReqUrl(), extractUrlsFromHtml.size()));

        // 针对JS页面提取 当属于 CONF_EXTRACT_SUFFIX 后缀（含后缀为空）的时候 、是脚本类型的时候
        if (isEqualsOneKey(msgInfo.getUrlInfo().getReqPathExt(), CONF_EXTRACT_SUFFIX, true)
                || msgInfo.getRespInfo().getInferredMimeType().contains("script")) {
            Set<String> extractUriFromJs = extractUriFromJs(respBody);
            stdout_println(LOG_DEBUG, String.format("[*] 初步提取URI: %s -> %s", msgInfo.getReqUrl(), extractUriFromJs.size()));
            uriSet.addAll(extractUriFromJs);
        }

        return uriSet;
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

    /**
     * 判断提取的敏感信息（URL|PATH|INFO）是否都为空值
     * @param analyseInfo
     */
    public static boolean analyseInfoIsNotEmpty(JSONObject analyseInfo) {
        return !analyseInfo.getJSONArray(URL_KEY).isEmpty()
                || !analyseInfo.getJSONArray(PATH_KEY).isEmpty()
                || !analyseInfo.getJSONArray(INFO_KEY).isEmpty();
    }
}
