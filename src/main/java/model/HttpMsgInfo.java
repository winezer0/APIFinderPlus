package model;

import burp.*;

import java.nio.charset.StandardCharsets;
import java.util.zip.CRC32;

//创建一个类用于存储 代理 流量的解析结果
public class HttpMsgInfo {
    private static final IExtensionHelpers helpers = BurpExtender.getHelpers();;
    private HttpUrlInfo urlInfo;
    private HttpRespInfo respInfo;
    private String reqUrl;
    private String reqMethod;
    private String respStatusCode;
    private byte[] reqBytes;
    private byte[] respBytes;
    private String msgHash;

    // 构造函数
    public HttpMsgInfo(IInterceptedProxyMessage iInterceptedProxyMessage) {
        IHttpRequestResponse messageInfo = iInterceptedProxyMessage.getMessageInfo();
        reqBytes = messageInfo.getRequest();

        //请求方法
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        reqMethod = requestInfo.getMethod();

        //从请求URL解析部分信息 //直接从请求体是没有办法获取到请求URL信息的, URL此时只能从外部传入
        reqUrl = requestInfo.getUrl().toString();
        urlInfo = new HttpUrlInfo(reqUrl);

        //从响应结果解析部分信息
        respBytes = messageInfo.getResponse();
        respInfo = new HttpRespInfo(respBytes);

        //响应码时常用的
        respStatusCode =  respInfo.getStatusCode();
        //请求响应信息的简单hash值
        msgHash = calcMsgHash();
    }

    // 构造函数
    public HttpMsgInfo(String requestUrl, byte[] requestBytes, byte[] responseBytes, String msgInfoHash) {
        //请求信息
        reqBytes = requestBytes;

        //请求方法
        IRequestInfo requestInfo = helpers.analyzeRequest(reqBytes);
        reqMethod = requestInfo.getMethod();

        //从请求URL解析部分信息
        reqUrl = requestUrl;
        urlInfo = new HttpUrlInfo(reqUrl);

        //从响应结果解析部分信息
        respBytes = responseBytes;
        respInfo = new HttpRespInfo(respBytes);

        //请求响应信息的简单hash值 因为中间可能截断了超大的响应体 , 因此最好手动传入 msgHash
        msgHash = (msgInfoHash != null && !msgInfoHash.isEmpty()) ? msgInfoHash : calcMsgHash();
    }

    /**
     * 计算消息Hash
     * @return
     */
    private String calcMsgHash() {
        return calcCRC32(String.format("%s|%s|%s|%s", urlInfo.getReqBaseUrl(), reqMethod, respStatusCode, respInfo.getBodyLenVague()));
    }

    /**
     * 计算给定字符串的CRC32校验和，并以十六进制字符串形式返回。
     * @param string 要计算CRC32的字符串
     * @return 字符串的CRC32校验和的十六进制表示
     */
    private static String calcCRC32(String string) {
        // 使用 UTF-8 编码将字符串转换为字节数组
        byte[] inputBytes = string.getBytes(StandardCharsets.UTF_8);
        // 初始化CRC32对象
        CRC32 crc32 = new CRC32();
        // 更新CRC值
        crc32.update(inputBytes, 0, inputBytes.length);
        // 将计算后的CRC32值转换为十六进制字符串并返回
        return Long.toHexString(crc32.getValue()).toLowerCase();
    }

    public String getReqMethod() {
        return reqMethod;
    }

    public byte[] getRespBytes() {
        return respBytes;
    }

    public byte[] getReqBytes() {
        return reqBytes;
    }
    
    public String getMsgHash() {
        return msgHash;
    }

    public void setRespBytes(byte[] respBytes) {
        this.respBytes = respBytes;
    }

    public HttpUrlInfo getUrlInfo() {
        return urlInfo;
    }

    public HttpRespInfo getRespInfo() {
        return respInfo;
    }

    public String getReqUrl() {
        return reqUrl;
    }

    public String getRespStatusCode() {
        return respStatusCode;
    }
}
