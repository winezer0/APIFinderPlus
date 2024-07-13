package utils;

import burp.*;
import model.HttpUrlInfo;
import utilbox.HelperPlus;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.zip.GZIPInputStream;

import static utils.BurpPrintUtils.stderr_println;


public class BurpHttpUtils {
    public static int MaxResponseContentLength = 500000;
    private static IExtensionHelpers helpers = BurpExtender.getHelpers();
    private static IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();

    public static void makeHttpRequestForGet(String reqUrl, List<String> referReqHeaders) {
        HttpUrlInfo urlInfo = new HttpUrlInfo(reqUrl);

        // 创建IHttpService对象
        IHttpService iHttpService = BurpHttpUtils.getHttpService(reqUrl);

        // 构造GET请求的字节数组
        String baseRequest = "GET /%s HTTP/1.1\r\n" +
                "Host: %s\r\n" +
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36\r\n" +
                "\r\n";
        baseRequest = String.format(baseRequest, urlInfo.getReqPath(), urlInfo.getReqHostPort());
        byte[] requestBytes = baseRequest.getBytes();

        //更新请求头
        HelperPlus helperPlus = new HelperPlus(helpers);
        for (String referReqHeader : referReqHeaders){
            if (!referReqHeader.toLowerCase().contains("host: ") && !referReqHeader.contains("HTTP/1.1")){
                requestBytes = helperPlus.addOrUpdateHeader(true, requestBytes, referReqHeader);
            }
        }

        //发送HTTP请求
        IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(iHttpService, requestBytes);

        // 空检查
        if (requestResponse == null || requestResponse.getResponse() == null) {
            throw new IllegalStateException("Request failed, no response received.");
        }

        //处理响应体
        byte[] response = requestResponse.getResponse();
        if (response != null) {
            String responseStr = helpers.bytesToString(response);
            System.out.println(String.format("Request URL [%s] Received response:\n%s",
                    reqUrl, responseStr.substring(Math.min(20,responseStr.length()))));
        } else {
            System.out.println(String.format("Request URL [%s] Received response: null",
                    reqUrl));
        }
    }


    /**
     * 实现Gzip数据的解压
     * @param compressed
     * @return
     * @throws IOException
     */
    public static byte[] gzipDecompress(byte[] compressed) throws IOException {
        if (compressed == null || compressed.length == 0) {
            return null;
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        GZIPInputStream gunzip = new GZIPInputStream(new ByteArrayInputStream(compressed));

        byte[] buffer = new byte[256];
        int n;
        while ((n = gunzip.read(buffer)) >= 0) {
            out.write(buffer, 0, n);
        }

        // Close the streams
        gunzip.close();
        out.close();

        // Get the uncompressed data
        return out.toByteArray();
    }

    /**
     * 实现多个bytes数组的相加
     * @param arrays
     * @return
     */
    public static byte[] concatenateByteArrays(byte[]... arrays) {
        int length = 0;
        for (byte[] array : arrays) {
            length += array.length;
        }

        byte[] result = new byte[length];
        int offset = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }
        return result;
    }

    public static IHttpService getHttpService(String url){
        try {
            URL urlObj = new URL(url);
            //获取请求协议
            String protocol = urlObj.getProtocol();
            //从URL中获取请求host
            String host = urlObj.getHost();
            //从URL中获取请求Port
            int port = urlObj.getPort();
            return helpers.buildHttpService(host, port, protocol);
        } catch (MalformedURLException e) {
            stderr_println(String.format("URL格式不正确: %s -> %s", url, e.getMessage()));
            return null;
        }
    }

}
