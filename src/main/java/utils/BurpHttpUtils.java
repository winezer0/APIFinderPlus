package utils;

import burp.*;
import model.HttpUrlInfo;
import utilbox.HelperPlus;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.GZIPInputStream;

import static burp.BurpExtender.CONF_BLACK_ROOT_URL;
import static burp.BurpExtender.getHelpers;
import static utils.BurpPrintUtils.*;
import static utils.CastUtils.isNotEmptyObj;
import static utils.ElementUtils.isEqualsOneKey;


public class BurpHttpUtils {
    private static IExtensionHelpers helpers = BurpExtender.getHelpers();
    private static IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();

    public static IHttpRequestResponse makeHttpRequest(String reqUrl, List<String> referReqHeaders) {
        return makeHttpRequest("GET", reqUrl, "", referReqHeaders);
    }

    /**
     * 发起HTTP请求
     * @param reqMethod 请求方法
     * @param reqUrl 请求URL
     * @param reqParam 请求参数
     * @param referReqHeaders 请求头
     * @return 请求响应结果
     */
    public static IHttpRequestResponse makeHttpRequest(String reqMethod, String reqUrl, String reqParam, List<String> referReqHeaders) {
        HttpUrlInfo urlInfo = new HttpUrlInfo(reqUrl);
        // 创建IHttpService对象
        IHttpService httpService = BurpHttpUtils.getHttpService(reqUrl);
        //构建HTTP请求体
        byte[] requestBytes = genRequestBytes(reqMethod, reqUrl, reqParam, referReqHeaders);

/*
        //分析当前创建的请求 判断生成是否一致
        HelperPlus helperPlus = HelperPlus.getInstance();
        String reqBytesHost = helperPlus.getHeaderValueOf(true, requestBytes, "HOST");
        String reqBytesUrl = helperPlus.getFullURL(httpService, requestBytes).toString();
        if (!urlInfo.getHostPort().contains(reqBytesHost)) {
            stdout_println(LOG_DEBUG, String.format(
                    "注意:实际访问的URL和目标访问的URL不一致\n" +
                            "目标HOST头:%s URL:%s -> 实际HOST头:%s URL:%s", urlInfo.getHostPort(), reqUrl, reqBytesHost, reqBytesUrl));
        }
*/

        //发送HTTP请求
        IHttpRequestResponse requestResponse = null;
        try {
            requestResponse = callbacks.makeHttpRequest(httpService, requestBytes);
        } catch (Exception e){
            if (e.getMessage().contains("UnknownHostException")){
                //主机不存活,直接加入黑名单host 加入最短的HOST即可
                CONF_BLACK_ROOT_URL.add(urlInfo.getHostPortUsual());
                stderr_println(LOG_DEBUG, String.format("添加黑名单Host:%s ->%s", reqUrl, urlInfo.getHostPortUsual()));
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
    private static byte[] genRequestBytes(String reqMethod, String reqUrl, String reqParam, List<String> referReqHeaders) {
        //编写函数 实现 基于请求体 替换 URL
        HttpUrlInfo urlInfo = new HttpUrlInfo(reqUrl);

        // 构造请求数据包信息
        byte[] requestBytes = genBaseRequestBytes(reqMethod, urlInfo.getPathToEnd(), urlInfo.getHostPortUsual(), reqParam);

        HelperPlus helperPlus = HelperPlus.getInstance();
        //基于请求头列表 更新 requestBytes 中的 请求头
        if (isNotEmptyObj(referReqHeaders)){
            for (String referReqHeader : referReqHeaders){
                if (!referReqHeader.toLowerCase().contains("host:")){
                    // addOrUpdateHeader 不会替换首行,但是会替换 HOST 头部
                    requestBytes = helperPlus.addOrUpdateHeader(true, requestBytes, referReqHeader);
                }
            }
        }

        // 根据请求参数自动修改请求体格式
        if (isNotEmptyObj(reqParam)&&!isEqualsOneKey(reqMethod.trim(),"GET|HEAD",false)){
            requestBytes = helperPlus.addOrUpdateHeader(true, requestBytes, determineContentType(reqParam));
        }

        // 设置 Connection: close
        requestBytes = helperPlus.addOrUpdateHeader(true, requestBytes, "Connection: close");

        //输出修改后的信息 已确定修改成功 20240808
        //System.out.println(new String(requestBytes));
        return requestBytes;
    }

    /**
     * 根据请求参数自动判断请求体格式
     * @param reqParam 请求参数字符串
     * @return
     */
    private static String determineContentType(String reqParam) {
        if (reqParam.startsWith("{") || reqParam.startsWith("[")) {
            return "Content-Type: application/json";
        } else if (reqParam.startsWith("<") && reqParam.endsWith(">")) {
            return "Content-Type: application/xml";
        } else if (reqParam.contains("=") && reqParam.contains("&")) {
            return "Content-Type: application/x-www-form-urlencoded";
        } else {
            //return "Content-Type: text/plain"; // 默认情况
            return "Content-Type: application/x-www-form-urlencoded";
        }
    }

    /**
     * 根据输入的信息生成基本的请求体信息
     * @param reqMethod 请求方法
     * @param reqPath 请求路径
     * @param reqHost 请求头
     * @param reqParam 请求参数
     * @return
     */
    private static byte[] genBaseRequestBytes(String reqMethod, String reqPath, String reqHost, String reqParam) {
        byte[] requestBytes;

        //根据请求方法补充数据 //"GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH"
        String baseRequestString = "%s %s HTTP/1.1\r\n" +
                "Host: %s\r\n" +
                //设置内容类型 后续一般实际会被覆盖
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                //设置浏览器UA 后续一般实际会被覆盖
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36\r\n" +
                "\r\n";

        //补充PUT POST型的数据
        if (isEqualsOneKey(reqMethod,"GET|HEAD",false)){
            //如果请求参数不为空的话，就将参数信息添加到请求路径后面
            if (isNotEmptyObj(reqParam)) {
                String delimiter = reqPath.contains("?") || reqPath.endsWith("&") ? "&" : "?";
                reqPath += delimiter + reqParam;
            }
            //补充基础数据
            baseRequestString = String.format(baseRequestString, reqMethod, reqPath, reqHost);
            requestBytes = baseRequestString.getBytes();
        } else {
            //补充POST|PUT的基础数据
            baseRequestString = String.format(baseRequestString, reqMethod, reqPath, reqHost);
            requestBytes = baseRequestString.getBytes();

            //补充请求体数据
            if (isNotEmptyObj(reqParam)){
                requestBytes = concatenateByteArrays(requestBytes, reqParam.getBytes());
            }
        }

        return requestBytes;
    }

    /**
     * 实现Gzip数据的解压
     * @param compressed
     * @return
     * @throws IOException
     */
    private static byte[] gzipDecompress(byte[] compressed) throws IOException {
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
    private static byte[] concatenateByteArrays(byte[]... arrays) {
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
     * 新的请求体生成思路 直接替换一个请求体的 URL 部分 其他部分保留
     * @param originalRequest 原始的请求体
     * @param newUrl 新的URL信息
     * @return
     */
    private static byte[] replaceReqBytesFirstLine(byte[] originalRequest, String newUrl) {
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
     * 获取HTTP请求的第一行（请求行） 没有解决第一行不是首行的问题
     * @return
     */
    private static byte[] getFirstLineBytes(byte[] request) {
        String requestStr = helpers.bytesToString(request);
        int firstLineEnd = requestStr.indexOf("\r\n");
        if (firstLineEnd == -1) firstLineEnd = requestStr.indexOf("\n");
        String firstLine = firstLineEnd != -1 ? requestStr.substring(0, firstLineEnd) : requestStr;
        byte[] firstLineBytes = helpers.stringToBytes(firstLine);
        return firstLineBytes;
    }

    //记录已进程测试过的连接,加快测试速度
    private static ConcurrentHashMap<String, Boolean> AddressConnectStatusMap = new ConcurrentHashMap<>();

    /**
     * 判断目标是否可以正常连接
     */
    public static boolean AddressCanConnectWithCache(String host, int port) {
        String host_port = String.format("%s:%s", host, port);

        //从历史记录中查找连接分析结果
        if (AddressConnectStatusMap.containsKey(host_port)){
            return AddressConnectStatusMap.get(host_port);
        }

        try {
            // 创建一个 Socket 并设置超时时间
            Socket socket = new Socket();
            InetSocketAddress address = new InetSocketAddress(host, port);
            socket.connect(address, 3000);
            socket.close();
            AddressConnectStatusMap.put(host_port, true);
            return true;
        }catch (Exception e){
            // 错误处理
            stderr_println(LOG_ERROR, String.format("[!] Socket Connect Failed: %s -> %s", host_port, e.getMessage()));
            //记录目标不可访问,下次直接返回不可访问
            AddressConnectStatusMap.put(host_port, false);
            return false;
        }
    }

    /**
     * 判断目标是否可以正常连接
     */
    public static boolean AddressCanConnectWithCache(String reqUrl) {
        IHttpService httpService = BurpHttpUtils.getHttpService(reqUrl);
        String host = httpService.getHost();
        int port = httpService.getPort();
        port = port > 0 ? port : (httpService.getProtocol().equalsIgnoreCase("http") ? 80 : 443);
        return AddressCanConnectWithCache(host, port);
    }

    /**
     * 判断目标是否可以正常连接
     */
    public static boolean AddressCanConnectWithCache(HttpUrlInfo urlInfo) {
        return AddressCanConnectWithCache(urlInfo.getHost(), urlInfo.getPort());
    }
}
