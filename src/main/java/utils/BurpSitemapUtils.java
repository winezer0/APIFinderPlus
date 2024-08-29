package utils;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IProxyScanner;
import database.PathTreeTable;
import database.RecordUrlTable;
import model.HttpMsgInfo;

import java.util.Set;

import static burp.BurpExtender.*;
import static utils.BurpPrintUtils.*;
import static utils.ElementUtils.isContainOneKey;
import static utils.ElementUtils.isEqualsOneKey;



public class BurpSitemapUtils {
    /**
     * 添加 SiteMap 中 所有有关的URL到 RecordPath 或 RecordUrl 表
     */
    public static void addSiteMapUrlsToRecord(boolean isRecordUrl){
        // 1、获取所有有关的 urlPrefix
        Set<String> urlPrefixes = PathTreeTable.fetchAllRecordPathRootUrls();
        for (String urlPrefix:urlPrefixes){
            //插入一个标记,表明这个主机已经插入过滤
            String insertedFlag = isRecordUrl ? urlPrefix + "/RecordUrl" : urlPrefix + "/RecordPath";
            boolean flagIsNotInsert = RecordUrlTable.insertOrUpdateAccessedUrl(insertedFlag, 999) > 0;

            //忽略导入禁止导入的主机的信息
            if (isContainOneKey(urlPrefix, CONF_BLACK_AUTO_RECORD_PATH, false) || isContainOneKey(urlPrefix, CONF_BLACK_URL_ROOT, false )){
                continue;
            }

            //获取URL相关的前缀
            if (flagIsNotInsert){
                IHttpRequestResponse[] httpRequestResponses = BurpExtender.getCallbacks().getSiteMap(urlPrefix);
                if (httpRequestResponses.length>0){
                        for (IHttpRequestResponse requestResponse: httpRequestResponses){
                        HttpMsgInfo msgInfo = new HttpMsgInfo(requestResponse);
                        String reqBaseUrl = msgInfo.getUrlInfo().getUrlToFileUsual();

                        try {
                            if (isRecordUrl){
                                //插入 reqBaseUrl 排除黑名单后缀、 忽略参数
                                if(!isEqualsOneKey(msgInfo.getUrlInfo().getSuffix(), CONF_BLACK_URL_EXT, false)){
                                    RecordUrlTable.insertOrUpdateAccessedUrl(msgInfo);
                                }
                            } else {
                                //插入路径 仅保留200 403等有效目录
                                if(isEqualsOneKey(msgInfo.getRespInfo().getStatusCode(), CONF_WHITE_RECORD_PATH_STATUS, false)
                                        && !msgInfo.getUrlInfo().getPathToDir().equals("/")
                                        && !isContainOneKey(msgInfo.getRespInfo().getRespTitle(), CONF_BLACK_RECORD_PATH_TITLE, false)
                                ){
//                                    RecordPathTable.insertOrUpdateRecordPath(reqBaseUrl, msgInfo.getRespInfo().getStatusCode());
//                                    stdout_println(LOG_DEBUG, String.format("Record reqBaseUrl: %s", reqBaseUrl));
                                    IProxyScanner.enhanceRecordPathFilter(msgInfo, IProxyScanner.dynamicPathFilterIsOpen);
                                }
                            }
                        } catch (Exception e){
                            stderr_println(String.format("Record SiteMap Urls (isRecordUrl:%s) req Base Url:%s -> Error: %s", isRecordUrl, reqBaseUrl, e.getMessage()));
                        }

                    }
                }

            }

        }
    }
}
