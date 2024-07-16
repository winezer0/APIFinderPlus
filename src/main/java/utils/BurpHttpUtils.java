package utils;

import burp.*;
import model.HttpUrlInfo;
import utilbox.HelperPlus;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.zip.GZIPInputStream;

import static burp.BurpExtender.CONF_BLACK_URL_ROOT;
import static burp.BurpExtender.getHelpers;
import static utils.BurpPrintUtils.*;
import static utils.CastUtils.isNotEmptyObj;


public class BurpHttpUtils {
    private static IExtensionHelpers helpers = BurpExtender.getHelpers();
    private static IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();

    public static IHttpRequestResponse makeHttpRequestForGet(String reqUrl, List<String> referReqHeaders) {
        HttpUrlInfo urlInfo = new HttpUrlInfo(reqUrl);

        // 创建IHttpService对象
        IHttpService httpService = BurpHttpUtils.getHttpService(reqUrl);
        //构建HTTP请求体
        byte[] requestBytes = genGetRequestBytes(reqUrl, referReqHeaders, isNotEmptyObj(referReqHeaders));

        //分析当前创建的请求 判断生成是否一致
        HelperPlus helperPlus = HelperPlus.getInstance();
        String reqBytesHost = helperPlus.getHeaderValueOf(true, requestBytes, "HOST");
        String reqBytesUrl = helperPlus.getFullURL(httpService, requestBytes).toString();
        if (!urlInfo.getHostPort().contains(reqBytesHost)) {
            stdout_println(LOG_DEBUG, String.format(
                    "注意:实际访问的URL和目标访问的URL不一致\n" +
                            "目标HOST头:%s URL:%s -> 实际HOST头:%s URL:%s", urlInfo.getHostPort(), reqUrl, reqBytesHost, reqBytesUrl));
        }

        //发送HTTP请求
        IHttpRequestResponse requestResponse = null;
        try {
            requestResponse = callbacks.makeHttpRequest(httpService, requestBytes);
        } catch (Exception e){
            if (e.getMessage().contains("UnknownHostException")){
                //主机不存活,直接加入黑名单host 加入最短的HOST即可
                CONF_BLACK_URL_ROOT.add(urlInfo.getHostPortUsual());
                stderr_println(LOG_DEBUG, String.format("黑名单Host添加:%s ->%s", reqUrl, urlInfo.getHostPortUsual()));
            } else {
                stderr_println(LOG_DEBUG, String.format("获取HTTP响应失败:%s ->%s", reqUrl, e.getMessage()));
            }
        }
        return requestResponse;
    }

    /**
     * 输入URl 构建 GET 请求体 再修改新增请求头(忽略host替换)
     * @param reqUrl
     * @param referReqHeaders
     * @return
     */
    private static byte[] genGetRequestBytes(String reqUrl, List<String> referReqHeaders, boolean addHeader) {
        //编写函数 实现 基于请求体 替换 URL
        HttpUrlInfo urlInfo = new HttpUrlInfo(reqUrl);
        // 构造GET请求的字节数组
        String baseRequest = "GET %s HTTP/1.1\r\n" +
                "Host: %s\r\n" +
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36\r\n" +
                "\r\n";
        //补充数据
        baseRequest = String.format(baseRequest, urlInfo.getPathToEnd(), urlInfo.getHostPortUsual());
        byte[] requestBytes = baseRequest.getBytes();

        //基于请求头列表 更新 requestBytes 中的 请求头
        if (addHeader && isNotEmptyObj(referReqHeaders)){
            HelperPlus helperPlus = HelperPlus.getInstance();
            for (String referReqHeader : referReqHeaders){
                if (!referReqHeader.toLowerCase().contains("host:")){
                    // addOrUpdateHeader 不会替换首行,但是会替换 HOST 头部
                    requestBytes = helperPlus.addOrUpdateHeader(true, requestBytes, referReqHeader);
                }
            }
        }

        return requestBytes;
    }

    /**
     * 直接替换一个请求体的 URL 部分 其他部分保留
     */
    public static byte[] replaceReqBytesFirstLine(byte[] originalRequest, String newUrl) {
        IExtensionHelpers helpers = getHelpers();
        HelperPlus helperPlus = HelperPlus.getInstance();
        HttpUrlInfo urlInfo = new HttpUrlInfo(newUrl);

        //获取原始请求体的首行 第一个\r\n 的 offset
        byte[] firstLineBytes = getFirstLineBytes(originalRequest);

        //删除 originalRequest 的 0 到 offset 部分
        byte[] noFirstLineReqBytes = "\r\n".getBytes();
        int crlfIndex = firstLineBytes.length;
        try {
            // 删除旧的首行，保留请求体
            noFirstLineReqBytes = Arrays.copyOfRange(originalRequest, crlfIndex, originalRequest.length);
        }catch (Exception e){
            stderr_println(LOG_ERROR, String.format("请求体构建出错 Error:%s", e.getMessage()));
        }

        //根据 newUrl 生成新的 首行 Byte[]
        String method = helperPlus.getMethod(originalRequest);
        String newFirstLine = String.format("%s %s HTTP/1.1", method, urlInfo.getPathToEnd());
        byte[] newFirstLineBytes = helpers.stringToBytes(newFirstLine);

        //将新的首行 byte 拼接到 新的 originalRequest 上
        byte[] newReqBytes = concatenateByteArrays(newFirstLineBytes, noFirstLineReqBytes);

        //修改Host头部分
        newReqBytes = helperPlus.addOrUpdateHeader(true, newReqBytes, "Host", urlInfo.getHostPort());

        return newReqBytes;
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

    /**
     * 基于URL生成一个HTTP请求服务对象
     */
    public static IHttpService getHttpService(String url){
        HttpUrlInfo urlInfo = new HttpUrlInfo(url);
        IHttpService HttpService = helpers.buildHttpService(urlInfo.getHost(), urlInfo.getPort(), urlInfo.getProto());
        return HttpService;
    }

    /**
     * 获取HTTP请求的第一行（请求行） 没有解决第一行不是首行的问题
     * @return
     */
    public static byte[] getFirstLineBytes(byte[] request) {
        String requestStr = helpers.bytesToString(request);
        int firstLineEnd = requestStr.indexOf("\r\n");
        if (firstLineEnd == -1) firstLineEnd = requestStr.indexOf("\n");
        String firstLine = firstLineEnd != -1 ? requestStr.substring(0, firstLineEnd) : requestStr;
        byte[] firstLineBytes = helpers.stringToBytes(firstLine);
        return firstLineBytes;
    }

}
