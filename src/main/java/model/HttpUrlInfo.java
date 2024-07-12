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

            //格式化URL 不显示默认端口
            reqUrl = removeUrlDefaultPort(reqUrl);
            reqBaseUrl = removeUrlDefaultPort(reqBaseUrl);
            reqBaseDir = removeUrlDefaultPort(reqBaseDir);

            //格式化URL 显示默认端口 //可能存在缺陷,无法处理那种
            //reqUrl = addUrlDefaultPort(reqUrl);
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

    /**
     * 1.remove default port(80\443) from the url
     * 2.add default path(/) to the url,if it's empty
     * 这个函数的目的是让URL的格式和通常从浏览器中复制的格式一致：
     * 在浏览器中，我们看到的是 baidu.com, 复制粘贴得到的是 https://www.baidu.com/
     * <p>
     * 比如
     * http://bit4woo.com:80/ ---> http://bit4woo.com/
     * https://bit4woo.com:443 ---> https://bit4woo.com/
     */
    private String removeUrlDefaultPort(String urlString) {
        try {
            URL url = new URL(urlString);
            String protocol = url.getProtocol();
            String host = url.getHost();
            int port = url.getPort();//不包含端口时返回-1
            String path = url.getPath();

            if ((port == 80 && protocol.equalsIgnoreCase("http")) ||
                    (port == 443 && protocol.equalsIgnoreCase("https"))) {
                String oldHost = url.getHost() + ":" + url.getPort();
                urlString = urlString.replaceFirst(oldHost, host);
            }

            if (path.equals("")) {
                urlString = urlString + "/";
            }
            return new URL(urlString).toString();
        } catch (MalformedURLException e) {
            e.printStackTrace();
            return urlString;
        }
    }

    /**
     * 1、这个函数的目的是：在【浏览器URL】的基础上，加上默认端口。
     * <p>
     * https://www.baidu.com/ ---> https://www.baidu.com:443/
     * http://www.baidu.com ---> http://www.baidu.com:80/
     * <p>
     * 在浏览器中，我们看到的是 baidu.com, 复制粘贴得到的是 https://www.baidu.com/
     * let url String contains default port(80\443) and default path(/)
     * <p>
     * burp中获取到的URL是包含默认端口的，但是平常浏览器中的URL格式都是不包含默认端口的。
     * 应该尽量和平常使用习惯保存一致！所以尽量避免使用该函数。
     *
     * @param urlStr
     * @return
     */
    private String addUrlDefaultPort(String urlStr) {
        try {
            URL url = new URL(urlStr);
            String host = url.getHost();
            int port = url.getPort();
            String path = url.getPath();

            if (port == -1) {
                String newHost = url.getHost() + ":" + url.getDefaultPort();
                urlStr = urlStr.replaceFirst(host, newHost);
            }

            if (path.equals("")) {
                urlStr = urlStr + "/";
            }
            return new URL(urlStr).toString();
        } catch (MalformedURLException e) {
            e.printStackTrace();
            return urlStr;
        }
    }
}

