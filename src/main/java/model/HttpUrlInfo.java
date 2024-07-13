package model;

import utilbox.DomainUtils;

import java.net.MalformedURLException;
import java.net.URL;

import static utils.BurpPrintUtils.stderr_println;

//创建一个类用于存储 URL解析结果的类
public class HttpUrlInfo {
    private String rawUrl;
    private String proto = null;
    private String host = null;
    private int port = -1;
    private String hostPort = null;

    private String rootDomain = null;
    private String path = null;
    private String pathDir = null;
    private String fullPath = null;
    private String query = null;
    private String ref = null;

    private String ext = null;

    private String prefixUrl = null;
    private String noParamUrl = null;
    private String noFileUrl = null;

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
            port = urlObj.getPort() == -1 ? urlObj.getDefaultPort() : urlObj.getPort();

            //路径 (path)：如 /path/to/resource
            path = urlObj.getPath();
            //查询参数 (query)：如 ?key=value&anotherKey=anotherValue
            query = urlObj.getQuery();
            //片段标识符 (fragment)：如 #section1
            ref = urlObj.getRef();
            //获取带有参数的完整Path 不带http信息 /path/to/resource?key=value#section1
            fullPath = genFullPath();
            //解析请求文件的后缀 php html
            ext = parseUrlExtStrict(rawUrl);
            //添加个HostPort对象 //www.baidu.com:8080
            hostPort = String.format("%s:%s", host, port);
            //获取前缀URL // http://www.baidu.com
            prefixUrl = String.format("%s://%s", proto, hostPort);
            //获取主域名 baidu.com
            rootDomain = DomainUtils.getRootDomain(host);
            //获取请求路径的目录部分 /path/to/
            pathDir = parseReqPathDir(path);
            // 重新构造基本URL，不包含查询参数 http://www.baidu.com/path/to/resource
            noParamUrl = new URL(proto, host, port, path).toString();
            //构造基本URL, 不包含请求文件 http://www.baidu.com/path/to/
            noFileUrl = new URL(proto, host, port, pathDir).toString();
            //格式化URL 不显示默认端口
            rawUrl = removeUrlDefaultPort(rawUrl);
            noParamUrl = removeUrlDefaultPort(noParamUrl);
            noFileUrl = removeUrlDefaultPort(noFileUrl);

            //格式化URL 显示默认端口 //可能存在缺陷,无法处理那种
            //reqUrl = addUrlDefaultPort(reqUrl);
        } catch (MalformedURLException e) {
            stderr_println(String.format("Invalid URL: %s -> Error: %s", rawUrl, e.getMessage()));
            e.printStackTrace();
        }
    }

    private String genFullPath() {
        StringBuilder fullPart = new StringBuilder(path);
        if (query != null && !query.isEmpty()) {
            fullPart.append("?").append(query);
        }
        if (ref != null && !ref.isEmpty()) {
            fullPart.append("#").append(ref);
        }
        return fullPart.toString();
    }

    /**
     * 从URL解析请求后缀 严格模式 处理 # 和 ?
     * @param url
     * @return
     */
    private String parseUrlExtStrict(String url) {
        int queryIndex = url.indexOf('?');
        int fragmentIndex = url.indexOf('#');

        int endIndex = -1;
        // 计算有效部分的结束索引
        if (queryIndex > 0 && fragmentIndex >0){
            endIndex = Math.min(queryIndex, fragmentIndex);
        } else if (queryIndex > 0 || fragmentIndex >0){
            endIndex = Math.max(queryIndex, fragmentIndex);
        } else {
            endIndex = url.length();
        }

        // 截取有效部分；否则使用整个URL
        String pureUrl = url.substring(0, endIndex);

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

    public String getRawUrl() {
        return rawUrl;
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

    public String getPrefixUrl() {
        return prefixUrl;
    }

    public String getRootDomain() {
        return rootDomain;
    }

    public int getPort() {
        return port;
    }

    public String getPath() {
        return path;
    }

    public String getPathDir() {
        return pathDir;
    }

    public String getExt() {
        return ext;
    }

    public String getNoParamUrl() {
        return noParamUrl;
    }

    public String getNoFileUrl() {
        return noFileUrl;
    }


    public String getFullPath() {
        return fullPath;
    }

    public String getQuery() {
        return query;
    }

    public String getRef() {
        return ref;
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

            if ((port == 80 && proto.equalsIgnoreCase("http")) ||
                    (port == 443 && proto.equalsIgnoreCase("https"))||
                    port == -1
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

