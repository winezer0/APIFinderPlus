package model;

import burp.*;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.zip.CRC32;

//创建一个类用于存储 代理 流量的解析结果
public class HttpMsgInfo {
    private static PrintWriter stdout = BurpExtender.getStdout();
    private static PrintWriter stderr = BurpExtender.getStderr();
    private static IExtensionHelpers helpers = BurpExtender.getHelpers();;

    private String reqUrl = null;
    private String reqMethod = null;
    private String reqProto = null;
    private String reqHost = null;
    private int reqPort = -1;
    private String reqPath = null;
    private String reqPathExt = null;
    private String reqPathDir = null;
    private String reqBaseUrl = "-";
    private String reqBasePath = "-";
    private byte[] reqBytes = null;

    private byte[] respBytes = null;
    private String respStatus = null;
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
        msgHash = calcCRC32(String.format("%s|%s|%s|%s", reqBaseUrl, respStatus, reqMethod, respBodyLenVague));
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

        //请求响应信息的简单hash值
        msgHash = msgInfoHash;
        //计算新的msgHash
        if (msgHash == null || "".equals(msgHash))
            msgHash = calcCRC32(String.format("%s|%s|%s|%s", reqBaseUrl, respStatus, reqMethod, respBodyLenVague));
    }

    /**
     * 从请求URL解析部分信息
     * @param requestUrl
     */
    private void parseReqUrlInfo(String requestUrl) {
        //基于URL获取其他请求信息
        try {
            reqUrl = requestUrl;
            URL urlObj = new URL(requestUrl);
            //获取请求协议
            reqProto = urlObj.getProtocol();
            //从URL中获取请求host
            reqHost = urlObj.getHost();
            //从URL中获取请求Port
            reqPort = urlObj.getPort();
            //解析请求文件的后缀
            reqPathExt = parseUrlExt(requestUrl);
            //获取请求路径
            reqPath = urlObj.getPath();
            //获取请求路径的目录部分
            reqPathDir = parseReqPathDir(reqPath);
            // 构造基本URL，不包含查询参数
            reqBaseUrl = new URL(reqProto, reqHost, reqPort, reqPath).toString();
            //构造基本URL, 不包含请求文件
            reqBasePath = new URL(reqProto, reqHost, reqPort, reqPathDir).toString();
        } catch (MalformedURLException e) {
            stderr.println(String.format("Invalid URL: %s -> Error: %s", requestUrl, e.getMessage()));
            e.printStackTrace();
        }
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
        respStatus = String.valueOf(responseInfo.getStatusCode());
        //respBodyLenVague
        respBodyOffset = responseInfo.getBodyOffset();
        //大致的响应长度
        respBodyLenVague = calcBodyLenVague(responseBytes, respBodyOffset);
        //获取响应类型
        inferredMimeType = responseInfo.getInferredMimeType();
        statedMimeType = responseInfo.getStatedMimeType();
    }

    /**
     * 从URL解析请求后缀
     * @param url
     * @return
     */
    public static String parseUrlExt(String url) {
        String pureUrl = url.substring(0, url.contains("?") ? url.indexOf("?") : url.length());
        return (pureUrl.lastIndexOf(".") > -1 ? pureUrl.substring(pureUrl.lastIndexOf(".") + 1) : "").toLowerCase();
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

    /**
     * 从给定的URL字符串中提取请求的目录部分。
     * @param reqPath 完整的URL字符串。
     * @return 请求的目录路径，不包含最后一个路径分隔符。
     */
    public static String parseReqPathDir(String reqPath) {
        // 去除最后一个路径分隔符后面的文件名部分，如果有的话
        int lastPathSepIndex = reqPath.lastIndexOf('/');
        // 如果找到了路径分隔符（lastPathSepIndex 不等于 -1）
        if (lastPathSepIndex != -1) {
            // 从原始路径中截取出从开头到最后一个路径分隔符（包括该分隔符）的部分  +1是为了保留最后一个路径分隔符
            return reqPath.substring(0, lastPathSepIndex + 1);
        }
        return "/";
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

    public String getReqBasePath() {
        return reqBasePath;
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
    
    public String getRespStatus() {
        return respStatus;
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

    public void setRespBytes(byte[] respBytes) {
        this.respBytes = respBytes;
    }

    public void setMsgHash(String msgHash) {
        this.msgHash = msgHash;
    }

    public void setReqUrl(String reqUrl) {
        this.reqUrl = reqUrl;
    }

}
