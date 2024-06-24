package model;

import burp.*;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.zip.CRC32;

import static utilbox.DomainUtils.getRootDomain;
import static utils.BurpPrintUtils.*;

//创建一个类用于存储 代理 流量的解析结果
public class HttpMsgInfo {
    private static final IExtensionHelpers helpers = BurpExtender.getHelpers();;

    private String reqUrl = null;
    private String reqMethod = null;
    private String reqProto = null;
    private String reqHost = null;
    private String reqHostPort = null;
    private String reqRootDomain = null;
    private int reqPort = -1;
    private String reqPath = null;
    private String reqPathExt = null;
    private String reqPathDir = null;
    private String reqBaseUrl = "-";
    private String reqBaseDir = "-";
    private byte[] reqBytes = null;
    private byte[] respBytes = null;
    private String respStatusCode = null;
    private int respBodyLen = -1;
    private int respBodyLenVague = -1;

    private String msgHash = null;

    private String inferredMimeType = null;
    private String statedMimeType = null;
    private int respBodyOffset = 0;

    // 构造函数
    public HttpMsgInfo(IInterceptedProxyMessage iInterceptedProxyMessage) {
        IHttpRequestResponse messageInfo = iInterceptedProxyMessage.getMessageInfo();
        //直接从请求体是没有办法获取到请求URL信息的, URL此时只能从外部传入
        reqBytes = messageInfo.getRequest();

        //请求信息 // 从 msgInfo 分析,不需要进行
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        //请求方法
        reqMethod = requestInfo.getMethod();

        //从请求URL解析部分信息
        parseReqUrlInfo(requestInfo.getUrl().toString());

        //从响应结果解析部分信息
        parseRespBytes(messageInfo.getResponse());

        //请求响应信息的简单hash值
        msgHash = calcCRC32(String.format("%s|%s|%s|%s", reqBaseUrl, respStatusCode, reqMethod, respBodyLenVague));
    }

    // 构造函数
    public HttpMsgInfo(String requestUrl, byte[] requestBytes, byte[] responseBytes, String msgInfoHash) {
        //直接从请求体是没有办法获取到请求URL信息的, URL此时只能从外部传入
        //请求信息
        reqBytes = requestBytes;

        //请求方法
        IRequestInfo requestInfo = helpers.analyzeRequest(requestBytes);
        reqMethod = requestInfo.getMethod();

        //从请求URL解析部分信息
        parseReqUrlInfo(requestUrl);

        //从响应结果解析部分信息
        parseRespBytes(responseBytes);

        //请求响应信息的简单hash值 因为中间可能截断了超大的响应体 , 因此最好手动传入 msgHash
        msgHash = msgInfoHash;
        if (msgHash == null || "".equals(msgHash))
            msgHash = calcCRC32(String.format("%s|%s|%s|%s", reqBaseUrl, respStatusCode, reqMethod, respBodyLenVague));
    }

    /**
     * 从请求URL解析部分信息
     * @param requestUrl
     */
    private void parseReqUrlInfo(String requestUrl) {
        HttpUrlInfo urlInfo = new HttpUrlInfo(requestUrl);
        //获取请求URL
        reqUrl = urlInfo.getReqUrl();
        //获取请求协议
        reqProto = urlInfo.getReqProto();
        //从URL中获取请求host
        reqHost = urlInfo.getReqHost();
        //获取主域名
        reqRootDomain = urlInfo.getReqRootDomain();
        //从URL中获取请求Port
        reqPort = urlInfo.getReqPort();
        //添加个HostPort对象
        reqHostPort = urlInfo.getReqHostPort();
        //解析请求文件的后缀
        reqPathExt = urlInfo.getReqPathExt();
        //获取请求路径
        reqPath = urlInfo.getReqPath();
        //获取请求路径的目录部分
        reqPathDir = urlInfo.getReqPathDir();
        // 构造基本URL，不包含查询参数
        reqBaseUrl = urlInfo.getReqBaseUrl();
        //构造基本URL, 不包含请求文件
        reqBaseDir = urlInfo.getReqBaseDir();
    }

    /**
     * 从响应体解析部分响应数据
     * @param responseBytes
     */
    private void parseRespBytes(byte[] responseBytes) {
        //响应内容
        respBytes = responseBytes;
        //响应长度
        respBodyLen = responseBytes.length;
        //响应信息
        IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
        //响应状态码
        respStatusCode = String.valueOf(responseInfo.getStatusCode());
        //respBodyLenVague
        respBodyOffset = responseInfo.getBodyOffset();
        //大致的响应长度
        respBodyLenVague = calcBodyLenVague(responseBytes, respBodyOffset);
        //获取响应类型
        inferredMimeType = responseInfo.getInferredMimeType();
        statedMimeType = responseInfo.getStatedMimeType();
    }

    /**
     * 获取 请求体或响应体的body部分
     * @param respBytes
     * @param bodyOffset
     * @return
     */
    public static byte[] getBodyBytes(byte[] respBytes, int bodyOffset) {
        // 确保 bodyOffset 不会导致数组越界
        int bodyLength = Math.max(0, respBytes.length - bodyOffset);

        // 从 bytes 数组中复制 body 的部分
        byte[] body = Arrays.copyOfRange(respBytes, bodyOffset, bodyOffset + bodyLength);
        return body;
    }

    /**
     * 简单实现忽略两百字节以内的长度变化
     * @param responseBytes
     * @param bodyOffset
     * @return
     */
    public static int calcBodyLenVague(byte[] responseBytes, int bodyOffset) {
        int respBodyLength = getBodyBytes(responseBytes, bodyOffset).length;
        respBodyLength = respBodyLength/200;
        return respBodyLength;
    }

    /**
     * 计算给定字符串的CRC32校验和，并以十六进制字符串形式返回。
     * @param string 要计算CRC32的字符串
     * @return 字符串的CRC32校验和的十六进制表示
     */
    public static String calcCRC32(String string) {
        // 使用 UTF-8 编码将字符串转换为字节数组
        byte[] inputBytes = string.getBytes(StandardCharsets.UTF_8);
        // 初始化CRC32对象
        CRC32 crc32 = new CRC32();
        // 更新CRC值
        crc32.update(inputBytes, 0, inputBytes.length);
        // 将计算后的CRC32值转换为十六进制字符串并返回
        return Long.toHexString(crc32.getValue()).toLowerCase();
    }

    public String getReqUrl() {
        return reqUrl;
    }

    public String getReqMethod() {
        return reqMethod;
    }

    public String getReqBaseUrl() {
        return reqBaseUrl;
    }

    public String getReqBaseDir() {
        return reqBaseDir;
    }

    public String getReqProto() {
        return reqProto;
    }

    public String getReqHost() {
        return reqHost;
    }

    public int getReqPort() {
        return reqPort;
    }

    public String getReqPath() {
        return reqPath;
    }

    public String getReqPathExt() {
        return reqPathExt;
    }

    public byte[] getRespBytes() {
        return respBytes;
    }

    public byte[] getReqBytes() {
        return reqBytes;
    }
    
    public String getRespStatusCode() {
        return respStatusCode;
    }

    public int getRespBodyLen() {
        return respBodyLen;
    }

    public int getRespBodyLenVague() {
        return respBodyLenVague;
    }

    public String getMsgHash() {
        return msgHash;
    }

    public String getReqPathDir() {
        return reqPathDir;
    }

    public String getInferredMimeType() {
        return inferredMimeType;
    }

    public String getStatedMimeType() {
        return statedMimeType;
    }

    public int getRespBodyOffset() {
        return respBodyOffset;
    }

    public String getReqRootDomain() {
        return reqRootDomain;
    }

    public void setRespBytes(byte[] respBytes) {
        this.respBytes = respBytes;
    }

    public String getReqHostPort() {
        return reqHostPort;
    }
}
