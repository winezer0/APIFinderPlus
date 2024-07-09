package model;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IResponseInfo;

import java.util.Arrays;

public class HttpRespInfo {
    private static final IExtensionHelpers helpers = BurpExtender.getHelpers();
    private byte[] respBytes = "".getBytes();
    private int statusCode = -1;
    private int respLength = -1;
    private int bodyLength = -1;
    private int bodyLenVague = -1;
    private String inferredMimeType = "";
    private String statedMimeType = "";
    private int bodyOffset = -1;

    HttpRespInfo(byte[] responseBytes) {
        if (responseBytes == null || responseBytes.length <= 0){
            //System.out.println("Warning: That response body is empty !!!");
            return;
        }

        respBytes = responseBytes;
        //响应长度
        respLength = respBytes.length;
        //响应信息
        IResponseInfo responseInfo = helpers.analyzeResponse(respBytes);
        //响应状态码
        statusCode = responseInfo.getStatusCode();
        //获取响应类型
        inferredMimeType = responseInfo.getInferredMimeType();
        statedMimeType = responseInfo.getStatedMimeType();
        //响应体分割标记
        bodyOffset = responseInfo.getBodyOffset();
        bodyLength = getBodyBytes().length;
        //大致的响应长度
        bodyLenVague = bodyLength /200;
    }


    /**
     * 获取 请求体或响应体的body部分
     */
    public byte[] getBodyBytes() {
        // 确保 bodyOffset 不会导致数组越界
        int bodyLength = Math.max(0, respBytes.length - bodyOffset);

        // 从 bytes 数组中复制 body 的部分
        return Arrays.copyOfRange(respBytes, bodyOffset, bodyOffset + bodyLength);
    }

    public int getStatusCode() {
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
