package utils;

import burp.BurpExtender;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import model.FingerPrintRule;
import model.HttpMsgInfo;

import java.nio.charset.StandardCharsets;
import java.util.*;

import static burp.BurpExtender.*;
import static utils.BurpPrintUtils.*;
import static utils.ElementUtils.isContainAllKey;
import static utils.ElementUtils.isEqualsOneKey;
import static utils.InfoAnalyseUtils.*;

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
        JSONArray analysedInfoArray = findSensitiveInfoByConfig(msgInfo);
        stdout_println(LOG_DEBUG, String.format("[+] 敏感信息数量:%s -> %s", analysedInfoArray.size(), analysedInfoArray.toJSONString()));

        //提取URL和PATH信息
        Set<String> analysedUriSet = findUriInfo(msgInfo);
        stdout_println(LOG_DEBUG, String.format("[*] 采集URL|PATH数量:%s", analysedUriSet.size()));

        //拆分提取的URL和PATH为两个 List 用于进一步处理操作
        Map<String, List> separateUrlOrPathMap = SeparateUrlOrPath(analysedUriSet);

        //采集 URL 处理
        List<String> analysedUrlList = separateUrlOrPathMap.get(URL_KEY);
        stdout_println(LOG_DEBUG, String.format("[*] 初步采集URL数量:%s -> %s", analysedUrlList.size(), analysedUrlList));

        //实现响应url过滤
        if (analysedUrlList.size() > 0){
            //过滤重复内容
            analysedUrlList = InfoUriFilterUtils.removeDuplicates(analysedUrlList);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤重复URL内容:%s -> %s", analysedUrlList.size(), analysedUrlList));

            //仅保留主域名相关URL
            analysedUrlList = InfoUriFilterUtils.filterUrlByMainHost(msgInfo.getReqRootDomain(), analysedUrlList);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤非主域名URL:%s -> %s", analysedUrlList.size(), analysedUrlList));

            //过滤自身包含的URL (包含说明相同) //功能测试通过
            analysedUrlList = InfoUriFilterUtils.filterUriBySelfContain(msgInfo.getReqUrl(), analysedUrlList);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤自身包含的URL:%s -> %s", analysedUrlList.size(), analysedUrlList));

            //过滤黑名单host
            analysedUrlList = InfoUriFilterUtils.filterBlackHosts(analysedUrlList, CONF_BLACK_URL_HOSTS);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤黑名单主机:%s -> %s", analysedUrlList.size(), analysedUrlList));

            //过滤黑名单Path
            analysedUrlList = InfoUriFilterUtils.filterBlackPaths(analysedUrlList, CONF_BLACK_URL_PATH);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤黑名单路径:%s -> %s", analysedUrlList.size(), analysedUrlList));

            //过滤黑名单suffix
            analysedUrlList = InfoUriFilterUtils.filterBlackSuffixes(analysedUrlList, CONF_BLACK_URL_EXT);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤黑名单后缀:%s -> %s", analysedUrlList.size(), analysedUrlList));
        }

        //采集 path 处理
        List<String> analysedPathList = separateUrlOrPathMap.get(PATH_KEY);
        stdout_println(LOG_DEBUG, String.format("[*] 初步采集PATH数量:%s -> %s", analysedUrlList.size(), analysedUrlList));

        //实现响应Path过滤
        if (analysedPathList.size()>0){
            //过滤重复内容
            analysedPathList = InfoUriFilterUtils.removeDuplicates(analysedPathList);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤重复PATH内容:%s -> %s", analysedPathList.size(), analysedPathList));

            //过滤自身包含的Path (包含说明相同)
            analysedPathList = InfoUriFilterUtils.filterUriBySelfContain(msgInfo.getReqPath(), analysedPathList);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤自身包含的PATH:%s -> %s", analysedPathList.size(), analysedPathList));

            //过滤包含禁止关键字的PATH
            analysedPathList = InfoUriFilterUtils.filterPathByContainUselessKey(analysedPathList, CONF_BLACK_PATH_KEYS);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤包含禁止关键字的PATH:%s -> %s", analysedPathList.size(), analysedPathList));

            //过滤包含中文的PATH
            analysedPathList = InfoUriFilterUtils.filterPathByContainChinese(analysedPathList);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤中文PATH内容:%s -> %s", analysedPathList.size(), analysedPathList));

            //过滤等于禁止PATH的PATH
            analysedPathList = InfoUriFilterUtils.filterPathByEqualUselessPath(analysedPathList, CONF_BLACK_PATH_EQUALS);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤等于禁止PATH的PATH:%s -> %s", analysedPathList.size(), analysedPathList));
        }

        //基于Path简单计算URL 已验证，常规网站采集的PATH生成的URL基本都是正确的
        List<String> analysedApiList = UrlAddPath(msgInfo.getReqUrl(), analysedPathList);
        stdout_println(LOG_DEBUG, String.format("[+] 简单计算API数量: %s -> %s", msgInfo.getReqUrl(), analysedApiList.size()));

        //实现 初步计算API的过滤
        if (analysedApiList.size()>0){
            analysedApiList = InfoUriFilterUtils.removeDuplicates(analysedApiList);
            stdout_println(LOG_DEBUG, String.format("[*] 过滤重复API内容:%s -> %s", analysedApiList.size(), analysedApiList));
        }

        ///////////////////////////返回最终结果///////////////////////////
        JSONObject analyseInfo = new JSONObject();
        analyseInfo.put(URL_KEY, analysedUrlList);
        analyseInfo.put(PATH_KEY, analysedPathList);
        analyseInfo.put(API_KEY, analysedApiList);
        analyseInfo.put(INFO_KEY, analysedInfoArray);
        stdout_println(LOG_DEBUG, String.format("[+] 最终解析结果:%s", analyseInfo.toJSONString()));
        return analyseInfo;
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
            if ("urlPath".equalsIgnoreCase(rule.getLocation())) {
                willFindText = msgInfo.getReqPath();
            }
//            else if ("body".equalsIgnoreCase(rule.getLocation())) {
//                willFindText = new String(HttpMsgInfo.getBodyBytes(msgInfo.getRespBytes(), msgInfo.getRespBodyOffset()),  StandardCharsets.UTF_8);
//                willFindText = SubString(willFindText, MAX_HANDLE_SIZE);
//            }
            else {
                willFindText = new String(msgInfo.getRespBytes(), StandardCharsets.UTF_8);
                willFindText = SubString(willFindText, MAX_HANDLE_SIZE);
            }


            //多个关键字匹配
            if (rule.getMatch().equals("keyword"))
                if(isContainAllKey(willFindText, rule.getKeyword(), false)){
                    //匹配关键字模式成功,应该标记敏感信息
                    JSONObject findInfo = generateInfoJson(rule, String.valueOf(rule.getKeyword()));
                    stdout_println(LOG_DEBUG, String.format("[+] 关键字匹配敏感信息:%s", findInfo.toJSONString()));
                    findInfosSet.add(findInfo);
                }

            //多个正则匹配
            if (rule.getMatch().equals("regular")){
                for (String patter : rule.getKeyword()){
                    Set<String> groups = regularMatchInfo(willFindText, patter);
                    if (groups.size() > 0){
                        JSONObject findInfo = generateInfoJson(rule, String.valueOf(new ArrayList<>(groups)));
                        stdout_println(LOG_DEBUG, String.format("[+] 正则匹配敏感信息:%s", findInfo.toJSONString()));
                        findInfosSet.add(findInfo);
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
    private static JSONObject generateInfoJson(FingerPrintRule rule, String group) {
        JSONObject findInfo = new JSONObject();
        findInfo.put(type, rule.getType()); // "type": "敏感内容",
        findInfo.put(describe, rule.getDescribe()); //"describe": "身份证",
        findInfo.put(accuracy, rule.getAccuracy()); //"accuracy": "high"
        findInfo.put(important, rule.getIsImportant()); //"isImportant": true,
        findInfo.put(value, group);
        return findInfo;
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

        //截取最大响应体长度
        respBody = SubString(respBody, MAX_HANDLE_SIZE);

        // 针对html页面提取 直接的URL 已完成
        Set<String> extractUrlsFromHtml = extractDirectUrls(msgInfo.getReqUrl(), respBody);
        uriSet.addAll(extractUrlsFromHtml);
        stdout_println(LOG_DEBUG, String.format("[*] 初步提取URL: %s -> %s", msgInfo.getReqUrl(), extractUrlsFromHtml.size()));

        // 针对JS页面提取 当属于 CONF_EXTRACT_SUFFIX 后缀（含后缀为空）的时候 、是脚本类型的时候
        if (isEqualsOneKey(msgInfo.getReqPathExt(), CONF_EXTRACT_SUFFIX, true) || msgInfo.getInferredMimeType().contains("script")) {
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
     * 判断提取的敏感信息（URL|PATH|INFO）是否都为空值
     * @param analyseInfo
     */
    public static boolean analyseInfoIsNotEmpty(JSONObject analyseInfo) {
        return analyseInfo.getJSONArray(URL_KEY).size()>0 ||
                analyseInfo.getJSONArray(PATH_KEY).size()>0  ||
                analyseInfo.getJSONArray(InfoAnalyse.INFO_KEY).size()>0;
    }
}
