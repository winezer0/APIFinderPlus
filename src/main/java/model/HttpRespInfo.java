package model;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IResponseInfo;

import java.util.Arrays;

public class HttpRespInfo {
    private static final IExtensionHelpers helpers = BurpExtender.getHelpers();;

    private String statusCode;

    private int respLength;
    private int bodyLength;

    private int bodyLenVague;
    private String inferredMimeType;
    private String statedMimeType;
    private int bodyOffset;

    HttpRespInfo(byte[] responseBytes) {
        //响应长度
        respLength = responseBytes.length;
        //响应信息
        IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
        //响应状态码
        statusCode = String.valueOf(responseInfo.getStatusCode());
        //获取响应类型
        inferredMimeType = responseInfo.getInferredMimeType();
        statedMimeType = responseInfo.getStatedMimeType();
        //响应体分割标记
        bodyOffset = responseInfo.getBodyOffset();
        bodyLength = getBodyBytes(responseBytes, bodyOffset).length;
        //大致的响应长度
        bodyLenVague = bodyLength /200;
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

    public String getStatusCode() {
        return statusCode;
    }

    public int getRespLength() {
        return respLength;
    }

    public int getBodyLength() {
        return bodyLength;
    }

    public int getBodyLenVague() {
        return bodyLenVague;
    }

    public String getInferredMimeType() {
        return inferredMimeType;
    }

    public String getStatedMimeType() {
        return statedMimeType;
    }

    public int getBodyOffset() {
        return bodyOffset;
    }
}
