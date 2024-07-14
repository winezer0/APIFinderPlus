package utils;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import com.alibaba.fastjson2.JSONObject;
import database.Constants;
import database.PathTreeTable;
import database.RecordPathTable;
import database.RecordUrlTable;
import model.HttpMsgInfo;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static burp.BurpExtender.CONF_BLACK_URL_EXT;
import static burp.BurpExtender.CONF_NEED_RECORD_STATUS;
import static utils.BurpPrintUtils.*;
import static utils.ElementUtils.isEqualsOneKey;



public class BurpSitemapUtils {
    /**
     * 添加 SiteMap 中 所有有关的URL到 RecordPath 或 RecordUrl 表
     */
    public static void addSiteMapUrlsToRecord(boolean isRecordUrl){
        // 1、获取所有有关的 urlPrefix
        Set<String> urlPrefixes = PathTreeTable.fetchAllRecordPathUrlPrefix();
        for (String urlPrefix:urlPrefixes){
            //获取URL相关的前缀
            IHttpRequestResponse[] httpRequestResponses = BurpExtender.getCallbacks().getSiteMap(urlPrefix);
            Set<String> JsonStringSet = extractSitemapUrlPaths(httpRequestResponses);
            List<String> JsonStringList = new ArrayList<>(JsonStringSet);

            //判断是否存在添加的价值
            if (JsonStringList.size() > 0){
                String jsonString0 = JsonStringList.get(0);
                JSONObject jsonObject0 = CastUtils.toJsonObject(jsonString0);

                //插入一个标记,表明这个主机已经插入过滤
                String insertedFlag = isRecordUrl ? urlPrefix + "/RecordUrl" : urlPrefix + "/RecordPath";
                if (RecordUrlTable.insertOrUpdateAccessedUrl(insertedFlag, jsonObject0.getString(Constants.REQ_HOST_PORT), 999) > 0){
                    //没有被添加过,可以继续添加
                    // 遍历 JsonStringSet 进行添加
                    for (String JsonString : JsonStringSet){
                        JSONObject jsonObject = CastUtils.toJsonObject(JsonString);
                        String reqBaseUrl = jsonObject.getString(Constants.REQ_BASE_URL);
                        String reqPathExt = jsonObject.getString(Constants.REQ_PATH_EXT);
                        String reqHostPort =  jsonObject.getString(Constants.REQ_HOST_PORT);
                        Integer respStatusCode = jsonObject.getInteger(Constants.RESP_STATUS_CODE);

                        try {
                            if (isRecordUrl){
                                //插入 reqBaseUrl 排除黑名单后缀、 忽略参数
                                if(!isEqualsOneKey(reqPathExt, CONF_BLACK_URL_EXT, false)){
                                    RecordUrlTable.insertOrUpdateAccessedUrl(reqBaseUrl,reqHostPort,respStatusCode);
                                }
                            } else {
                                //插入路径 仅保留200 403等有效目录
                                if(isEqualsOneKey(String.valueOf(respStatusCode), CONF_NEED_RECORD_STATUS, false)){
                                    RecordPathTable.insertOrUpdateRecordPath(reqBaseUrl, respStatusCode);
                                    stdout_println(LOG_DEBUG, String.format("Record reqBaseUrl: %s", reqBaseUrl));
                                }
                            }
                        } catch (Exception e){
                            stderr_println(String.format("Record SiteMap Urls (isRecordUrl:%s) reqBaseUrl:%s -> Error: %s", isRecordUrl, reqBaseUrl, e.getMessage()));
                        }

                    }
                }
            }
        }
    }

    /**
     * 从sitemap中提取path部分
     */
    private static Set<String> extractSitemapUrlPaths(IHttpRequestResponse[] httpRequestResponses) {
        //创建一个hashSet存储
        Set<String> JsonStringSet = new HashSet<>();
        for (IHttpRequestResponse requestResponse : httpRequestResponses) {
            HttpMsgInfo msgInfo = new HttpMsgInfo(requestResponse);

            if (msgInfo.getUrlInfo().getHostPort().contains("-1")){
                stderr_println(String.format("重大错误!!! URL %s 获取的 reqHostPort 没有合法的端口号 %s",msgInfo.getUrlInfo().getNoParamUrlUsual(), msgInfo.getUrlInfo().getHostPort()));
            }

            JSONObject jsonObject = new JSONObject();
            jsonObject.put(Constants.REQ_BASE_URL, msgInfo.getUrlInfo().getNoParamUrlUsual());
            jsonObject.put(Constants.REQ_HOST_PORT, msgInfo.getUrlInfo().getHostPort());
            jsonObject.put(Constants.REQ_PATH_EXT, msgInfo.getUrlInfo().getSuffix());
            jsonObject.put(Constants.RESP_STATUS_CODE, msgInfo.getRespStatusCode());
            JsonStringSet.add(jsonObject.toJSONString());
        }
        return JsonStringSet;
    }

}
