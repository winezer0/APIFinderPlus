package utils;

import burp.IHttpRequestResponse;
import burp.IProxyScanner;
import database.RecordPathTable;
import database.RecordUrlTable;
import model.HttpMsgInfo;

import static burp.BurpExtender.*;
import static utils.ElementUtils.isEqualsOneKey;

public class BurpSitemapUtils {


    /**
     * 添加 SiteMap 中指定前缀的URL到数据库中
     * @param urlPrefix 指定前缀的Url
     * @param addToRecordUrl 是否添加到 RecordUrl 表
     */
    public static void addSiteMapUrlsToDB(String urlPrefix, boolean addToRecordUrl){
        IHttpRequestResponse[] httpRequestResponses = getCallbacks().getSiteMap(urlPrefix);
        for (IHttpRequestResponse requestResponse : httpRequestResponses) {
            HttpMsgInfo msgInfo = new HttpMsgInfo(requestResponse);

            String reqBaseUrl = msgInfo.getUrlInfo().getReqBaseUrl();
            String reqHostPort = msgInfo.getUrlInfo().getReqHostPort();
            int respStatusCode = msgInfo.getRespStatusCode();

            //插入 reqBaseUrl 排除黑名单后缀、 忽略参数
            if(addToRecordUrl && !isEqualsOneKey(msgInfo.getUrlInfo().getReqPathExt(), CONF_BLACK_URL_EXT, false)){
                RecordUrlTable.insertOrUpdateAccessedUrl(reqBaseUrl,reqHostPort,respStatusCode);
            }

            //插入路径 仅保留200 403等有效目录
            if(IProxyScanner.urlPathRecordMap.get(msgInfo.getUrlInfo().getReqBaseDir()) <= 0
                    && isEqualsOneKey(String.valueOf(msgInfo.getRespStatusCode()), CONF_NEED_RECORD_STATUS, true)
                    && !msgInfo.getUrlInfo().getReqPath().equals("/")
            ){
                IProxyScanner.urlPathRecordMap.add(msgInfo.getUrlInfo().getReqBaseDir());
                RecordPathTable.insertOrUpdateSuccessUrl(msgInfo);
            }
        }
    }
}
