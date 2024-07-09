package model;

import utilbox.DomainUtils;

import java.net.MalformedURLException;
import java.net.URL;

import static utils.BurpPrintUtils.stderr_println;

//创建一个类用于存储 URL解析结果的类
public class HttpUrlInfo {
    private String reqUrl;
    private String reqMethod = null;
    private String reqProto = null;
    private String reqHost = null;
    private String reqHostPort = null;
    private String reqPrefix = null;
    private String reqRootDomain = null;
    private int reqPort = -1;
    private String reqPath = null;
    private String reqPathDir = null;

    private String reqPathExt = null;
    private String reqBaseUrl = "-";
    private String reqBaseDir = "-";

    public HttpUrlInfo(String requestUrl){
        reqUrl = requestUrl;
        //基于URL获取其他请求信息
        try {
            URL urlObj = new URL(reqUrl);
            //获取请求协议
            reqProto = urlObj.getProtocol();
            //从URL中获取请求host
            reqHost = urlObj.getHost();
            //从URL中获取请求Port
            reqPort = urlObj.getPort();
            //添加个HostPort对象
            reqHostPort = String.format("%s:%s", reqHost, reqPort);
            //获取前缀对象
            reqPrefix = String.format("%s://%s", reqProto, reqHostPort);
            //获取请求路径
            reqPath = urlObj.getPath();
            //解析请求文件的后缀
            reqPathExt = parseUrlExt(reqUrl);
            //获取主域名
            reqRootDomain = DomainUtils.getRootDomain(reqHost);
            //获取请求路径的目录部分
            reqPathDir = parseReqPathDir(reqPath);

            // 构造基本URL，不包含查询参数
            reqBaseUrl = new URL(reqProto, reqHost, reqPort, reqPath).toString();
            //构造基本URL, 不包含请求文件
            reqBaseDir = new URL(reqProto, reqHost, reqPort, reqPathDir).toString();
        } catch (MalformedURLException e) {
            stderr_println(String.format("Invalid URL: %s -> Error: %s", reqUrl, e.getMessage()));
            e.printStackTrace();
        }
    }

    /**
     * 从URL解析请求后缀
     * @param url
     * @return
     */
    private String parseUrlExt(String url) {
        int queryIndex = url.indexOf('?');
        int fragmentIndex = url.indexOf('#');

        // 计算有效部分的结束索引
        int endIndex = Math.min(url.length(), Math.max(queryIndex, fragmentIndex));

        // 如果查询参数或片段标识符存在，截取有效部分；否则使用整个URL
        String pureUrl = url.substring(0, endIndex > -1 ? endIndex : url.length());

        // 查找最后一个`.`的位置
        int lastDotIndex = pureUrl.lastIndexOf('.');

        // 如果有扩展名，提取它；否则返回空字符串
        String extension = lastDotIndex > -1 ? pureUrl.substring(lastDotIndex + 1) : "";

        // 将扩展名转换为小写
        return extension.toLowerCase();
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

    public String getReqProto() {
        return reqProto;
    }

    public String getReqHost() {
        return reqHost;
    }

    public String getReqHostPort() {
        return reqHostPort;
    }

    public String getReqPrefix() {
        return reqPrefix;
    }

    public String getReqRootDomain() {
        return reqRootDomain;
    }

    public int getReqPort() {
        return reqPort;
    }

    public String getReqPath() {
        return reqPath;
    }

    public String getReqPathDir() {
        return reqPathDir;
    }

    public String getReqPathExt() {
        return reqPathExt;
    }

    public String getReqBaseUrl() {
        return reqBaseUrl;
    }

    public String getReqBaseDir() {
        return reqBaseDir;
    }
}

