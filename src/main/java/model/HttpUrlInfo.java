package model;

import utilbox.DomainUtils;
import utils.CastUtils;

import java.net.MalformedURLException;
import java.net.URL;

import static utils.BurpPrintUtils.stderr_println;
import static utils.CastUtils.isNotEmptyObj;
import static utils.CastUtils.isNotEmptyObj;

//创建一个类用于存储 URL解析结果的类
public class HttpUrlInfo {
    private String rawUrl;
    private String rawUrlUsual;
    private String proto = null;
    private String host = null;
    private int port = -1;
    private String file = null;
    private String query = null;
    private String ref = null;

    private String hostPort = null;
    private String hostPortUsual = null;

    private String pathToFile = null;
    private String pathToDir = null;
    private String pathToEnd = null;

    private String suffix = null;
    private String suffixUsual = null;
    private String rootDomain = null;

    private String rootUrl = null;
    private String rootUrlUsual = null;
    private String rootUrlSimple = null;

    private String urlToFile = null;
    private String urlToPath = null;
    private String urlToFileUsual = null;
    private String urlToPathUsual = null;

    public HttpUrlInfo(String requestUrl){
        rawUrl = requestUrl;
        //基于URL获取其他请求信息
        try {
            URL urlObj = new URL(rawUrl);
            //协议 (protocol)：如 http 或 https
            proto = urlObj.getProtocol();  //协议 (protocol)：如 http 或 https
            //主机 (host)：如 www.example.com
            host = urlObj.getHost();
            //端口 (port)：如 80 或 443（默认情况下，如果未指定，http 默认为 80，https 默认为 443） 同时 检查reqPort为-1的情况
            port = urlObj.getPort() < 0 ? urlObj.getDefaultPort() : urlObj.getPort();
            //文件 resource
            file = urlObj.getFile();
            //查询参数 (query)：如 ?key=value&anotherKey=anotherValue
            query = urlObj.getQuery();
            //片段标识符 (fragment)：如 #section1
            ref = urlObj.getRef();

            //添加个HostPort对象 www.baidu.com:80 | www.baidu.com:8080
            hostPort = String.format("%s:%s", host, port);
            //获取没有默认端口的请求头 www.baidu.com | www.baidu.com:8080
            hostPortUsual = removeHostDefaultPort(hostPort,host,port);
            //获取前缀URL // http://www.baidu.com:80/
            rootUrl = String.format("%s://%s/", proto, hostPort);
            //获取前缀URL // http://www.baidu.com/
            rootUrlUsual = String.format("%s://%s/", proto, hostPortUsual);
            //获取前缀URL // http://www.baidu.com
            rootUrlSimple = String.format("%s://%s", proto, hostPortUsual);

            //解析请求文件的后缀 php html
            suffix = parseUrlExtStrict(file); //严重错误,域名中是有.符号的,因此不能直接截断域名
            //解析请求文件的后缀 .php .html
            suffixUsual = isNotEmptyObj(suffix)? "." + suffix : suffix;

            //获取主域名 baidu.com
            rootDomain = DomainUtils.getRootDomain(host);

            //路径 (path)：如 /path/to/resource
            pathToFile = urlObj.getPath();
            // 重新构造基本URL，不包含查询参数 http://www.baidu.com/path/to/resource
            urlToFile = new URL(proto, host, port, pathToFile).toString();
            urlToFileUsual = removeUrlDefaultPort(urlToFile);
            //获取请求路径的目录部分 /path/to/
            pathToDir = parseReqPathDir(pathToFile);
            //构造基本URL, 不包含请求文件 http://www.baidu.com/path/to/
            urlToPath = new URL(proto, host, port, pathToDir).toString();
            urlToPathUsual = removeUrlDefaultPort(urlToPath);
            //获取带有参数的完整Path 不带http信息 /path/to/resource?key=value#section1
            pathToEnd = genFullPath(pathToFile, query, ref);
            //格式化URL 不显示默认端口
            rawUrlUsual = removeUrlDefaultPort(rawUrl);

        } catch (MalformedURLException e) {
            stderr_println(String.format("Invalid URL: %s -> Error: %s", rawUrl, e.getMessage()));
            e.printStackTrace();
        }
    }

    /**
     * 拼接 Path路径、?查询字符串、#索引
     */
    private String genFullPath(String pathToFile,String query,String ref) {
        StringBuilder fullPart = new StringBuilder(pathToFile);
        if (CastUtils.isNotEmptyObj(query)) {
            fullPart.append("?").append(query);
        }
        if (CastUtils.isNotEmptyObj(ref)) {
            fullPart.append("#").append(ref);
        }
        return fullPart.toString();
    }

    /**
     * 从 path 解析请求后缀 严格模式 处理 # 和 ?
     */
    private String parseUrlExtStrict(String path) {
        //忽略为空的情况
        if (!isNotEmptyObj(path)) return "";

        int queryIndex = path.indexOf('?');
        int fragmentIndex = path.indexOf('#');

        int endIndex = -1;
        // 计算有效部分的结束索引
        if (queryIndex > 0 && fragmentIndex >0){
            endIndex = Math.min(queryIndex, fragmentIndex);
        } else if (queryIndex > 0 || fragmentIndex >0){
            endIndex = Math.max(queryIndex, fragmentIndex);
        } else {
            endIndex = path.length();
        }

        // 截取有效部分；否则使用整个URL
        String pureUrl = path.substring(0, endIndex);

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

    public String getRawUrlUsual() {
        return rawUrlUsual;
    }

    public String getProto() {
        return proto;
    }

    public String getHost() {
        return host;
    }

    public String getHostPort() {
        return hostPort;
    }

    public String getRootUrlUsual() {
        return rootUrlUsual;
    }

    public String getRootUrl() {
        return rootUrl;
    }

    public String getRootDomain() {
        return rootDomain;
    }

    public int getPort() {
        return port;
    }

    public String getQuery() {
        return query;
    }

    public String getRef() {
        return ref;
    }

    public String getPathToFile() {
        return pathToFile;
    }

    public String getPathToDir() {
        return pathToDir;
    }

    public String getSuffix() {
        return suffix;
    }

    public String getSuffixUsual() {
        return suffixUsual;
    }

    public String getUrlToFileUsual() {
        return urlToFileUsual;
    }

    public String getUrlToPathUsual() {
        return urlToPathUsual;
    }

    public String getPathToEnd() {
        return pathToEnd;
    }

    public String getHostPortUsual() {
        return hostPortUsual;
    }

    public String getRawUrl() {
        return rawUrl;
    }

    public String getFile() {
        return file;
    }

    public String getUrlToFile() {
        return urlToFile;
    }

    public String getUrlToPath() {
        return urlToPath;
    }

    public String getRootUrlSimple() {
        return rootUrlSimple;
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
            String proto = url.getProtocol();
            String host = url.getHost();
            int port = url.getPort(); //不包含端口时返回-1
            String path = url.getPath();

            if (port < 0 ||
                    (port == 80 && proto.equalsIgnoreCase("http")) ||
                    (port == 443 && proto.equalsIgnoreCase("https"))
            ) {
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

    private String removeHostDefaultPort(String hostPort, String host, int port) {
            if (port < 0
                    || (port == 80 && proto.equalsIgnoreCase("http"))
                    || (port == 443 && proto.equalsIgnoreCase("https"))){
                return host;
            }
            return hostPort;
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

