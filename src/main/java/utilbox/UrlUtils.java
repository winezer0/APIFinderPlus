package utilbox;


import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

public class UrlUtils {

    //在引号中的URL，如果没有引号，就匹配不到。常用语JS中提取URL路径
    //https://github.com/GerbenJavado/LinkFinder/blob/master/linkfinder.py
    private static final String REGEX_TO_GREP_URL_IN_QUOTES = "(?:\"|')"
            + "("
            + "((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})"
            + "|"
            + "((?:/|\\.\\./|\\./)[^\"'><,;| *()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,})"
            + "|"
            + "([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|/][^\"|']{0,}|))"
            + "|"
            + "([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\\?[^\"|']{0,}|))"
            + ")"
            + "(?:\"|')";

    //这个表达式的结果会包含类似o.bind、r.length、index.html的结果
    public static final String REGEX_TO_GREP_URL = RegexUtils.WEB_URL;

    public static final String REGEX_TO_GREP_URL_WITH_PROTOCOL = RegexUtils.WEB_URL_WITH_PROTOCOL;

    //处理不是/开头的urlpath
    public static final String REGEX_TO_GREP_URL_PATH_NOT_START_WITH_SLASH = "[a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-.]{1,}";

    //处理不是/开头的urlpath,内容是在引号中的
    public static final String REGEX_TO_GREP_URL_PATH_NOT_START_WITH_SLASH_IN_QUOTES = "(?:\"|')"
            + "("
            + REGEX_TO_GREP_URL_PATH_NOT_START_WITH_SLASH
            + ")"
            + "(?:\"|')";


    /**
     * 返回URL中的host，如果出错返回原始值
     *
     * @param urlStr
     * @return
     */
    public static String getHost(String urlStr) {
        try {
            return new URL(urlStr).getHost();
        } catch (MalformedURLException e) {
            e.printStackTrace();
            return urlStr;
        }
    }

    public static int getPort(String urlString) {
        try {
            URL url = new URL(urlString);
            int port = url.getPort();

            if (port == -1) {
                port = url.getDefaultPort();
            }
            return port;
        } catch (MalformedURLException e) {
            e.printStackTrace();
            return -1;
        }
    }


    public static boolean isVaildUrl(String urlString) {
        try {
            new URL(urlString);
            return true;
        } catch (Exception e) {
            return false;
        }
    }


    /**
     * URL object use equal() function to compare URL object.
     * the string contains default port or not both OK, but the path(/) is sensitive
     * URL对象可以用它自己提供的equal()函数进行对比，是否包含默认端口都是没有关系的。但最后的斜杠path却是有关系的。
     * <p>
     * result example:
     * http://bit4woo.com/ 不包含默认端口；包含默认path(/)
     * 是符合通常浏览器中使用格式的
     *
     * @return http://www.baidu.com/  不包含默认端口；包含默认path(/)
     */
    public static String getBaseUrl(String urlString) {
        String baseUrlWithPort = getBaseUrlWithDefaultPort(urlString);
        return removeUrlDefaultPort(baseUrlWithPort);
    }


    public static String getBaseUrlNoDefaultPort(String urlString) {
        String baseUrlWithPort = getBaseUrlWithDefaultPort(urlString);
        return removeUrlDefaultPort(baseUrlWithPort);
    }

    /**
     * return Type is URL,not String.
     * use equal() function to compare URL object.
     * the string contains default port or not both OK, but the path(/) is sensitive
     * URL对象可以用它自己提供的equal()函数进行对比，是否包含默认端口都是没有关系的。但最后的斜杠path却是有关系的。
     * <p>
     * result example:
     * <p>
     * eg. http://bit4woo.com:80/ 包含默认端口和默认path(/)
     *
     * @return
     */
    public static String getBaseUrlWithDefaultPort(String urlString) {
        try {
            URL url = new URL(urlString);
            int port = url.getPort();

            if (port == -1) {
                port = url.getDefaultPort();
            }
            return url.getProtocol() + "://" + url.getHost() + ":" + port + "/";
        } catch (MalformedURLException e) {
            e.printStackTrace();
            return urlString;
        }
    }


    /**
     * return Type is URL,not String.
     * use equal() function to compare URL object. the string contains default port or not both OK, but the path(/) is sensitive
     * URL对象可以用它自己提供的equal()函数进行对比，是否包含默认端口都是没有关系的。但最后的斜杠path却是有关系的。
     * <p>
     * 不包含默认端口的URL格式，符合通常浏览器中的格式
     * http://bit4woo.com/test.html#123
     */
    public static String getFullUrl(String urlStr) {
        return removeUrlDefaultPort(urlStr);
    }

    public static String getFullUrlNoDefaultPort(String urlStr) {
        return removeUrlDefaultPort(urlStr);
    }

    /**
     * return Type is URL,not String.
     * use equal() function to compare URL object. the string contains default port or not both OK, but the path(/) is sensitive
     * URL对象可以用它自己提供的equal()函数进行对比，是否包含默认端口都是没有关系的。但最后的斜杠path却是有关系的。
     * <p>
     * 这个函数的返回结果转换成字符串是包含了默认端口的。
     * http://bit4woo.com:80/test.html#123
     */
    public static String getFullUrlWithDefaultPort(String urlStr) {
        return addUrlDefaultPort(urlStr);
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
    public static String addUrlDefaultPort(String urlStr) {
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
    public static String removeUrlDefaultPort(String urlString) {
        try {
            URL url = new URL(urlString);
            String protocol = url.getProtocol();
            String host = url.getHost();
            int port = url.getPort();//不包含端口时返回-1
            String path = url.getPath();

            if ((port == 80 && protocol.equalsIgnoreCase("http")) || (port == 443 && protocol.equalsIgnoreCase("https"))) {
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
     * 注意：
     * 这个表达式的结果会包含类似o.bind、r.length、index.html的结果，误报较多，慎用！！！
     *
     * @param text
     * @return
     */
    @Deprecated
    public static List<String> grepUrls(String text) {
        return TextUtils.grepWithRegex(text, REGEX_TO_GREP_URL);
    }


    /**
     * 以协议开头，能避免大量误报，但同时就无法提取单独URL的path部分
     *
     * @param text
     * @return
     */
    public static List<String> grepUrlsWithProtocol(String text) {
        return TextUtils.grepWithRegex(text, REGEX_TO_GREP_URL_WITH_PROTOCOL);
    }

    /**
     * 提取引号包含的URL路径
     *
     * @param httpResponse
     * @return
     */
    public static List<String> grepUrlsInQuotes(String httpResponse) {
        return TextUtils.grepWithRegex(httpResponse, REGEX_TO_GREP_URL_IN_QUOTES, false, false, 1);
    }

    /**
     * 提取没有以/开头的URL path，误报较多，却有时候有用。慎用！！！
     *
     * @param text
     * @return
     */
    @Deprecated
    public static List<String> grepUrlPathNotStartWithSlash(String text) {
        return TextUtils.grepWithRegex(text, REGEX_TO_GREP_URL_PATH_NOT_START_WITH_SLASH);
    }


    /**
     * 提取没有以/开头的URL path，内容限定在引号之中
     *
     * @param text
     * @return
     */
    public static List<String> grepUrlPathNotStartWithSlashInQuotes(String text) {
        return TextUtils.grepWithRegex(text, REGEX_TO_GREP_URL_PATH_NOT_START_WITH_SLASH_IN_QUOTES, false, false, 1);
    }

    /**
     * 对于信息收集来说，没有用的文件
     * js是有用的
     * pdf\doc\excel等也是有用的，可以收集到其中的域名
     * rar\zip文件即使其中包含了有用信息，是无法直接读取的
     *
     * @param urlpath
     * @return
     */
    public static boolean uselessExtension(String urlpath) {
        String extensions = "css|jpeg|gif|jpg|png|rar|zip|svg|jpeg|ico|woff|woff2|ttf|otf|vue";
        String[] extList = extensions.split("\\|");

        urlpath = urlpath.split("#")[0];

        for (String item : extList) {
            if (urlpath.endsWith("." + item)) {
                return true;
            }
        }
        return false;
    }
    
    
    public static void main(String[] args) throws MalformedURLException {
        String aaa = "https://api.example.vn:443/Execute#1653013013763 /*";
        String bbb = "https://api.example.vn/Execute#1653013013763";
        String ccc = "      routes: [\r\n"
                + "        {\r\n"
                + "          path: '/home',\r\n"
                + "          name: 'home',\r\n"
                + "          component: function () {\r\n"
                + "            return o.e('chunk-xxx').then(o.bind(null, 'xxx'))\r\n"
                + "          },\r\n"
                + "          meta: {\r\n"
                + "          }\r\n"
                + "        },\r\n"
                + "        {\r\n"
                + "          path: '/',\r\n"
                + "          redirect: '/home'\r\n"
                + "        },\r\n"
                + "        {\r\n"
                + "          path: '/index.html',\r\n"
                + "          redirect: '/home'\r\n"
                + "        },\r\n"
                + "        {\r\n"
                + "          path: '/web/index.html',\r\n"
                + "          redirect: '/home'\r\n"
                + "        }"
                + "'/home111'"
                + "'http://www.home111.com/aaa/bbb'";

        String url1 = "http://www.example.com";
        String url2 = "https://www.example.com:8080";
        String url3 = "ftp://www.example.com:21/files#1111";
        //system_println(url2.split("#")[0]);

        //system_println(grepUrls(ccc));
        System.out.println(grepUrlsInQuotes(ccc));
        System.out.println(grepUrls(ccc));
        System.out.println(grepUrlsWithProtocol(ccc));
        System.out.println(removeUrlDefaultPort(url3));
        //system_println(grepURL1(ccc));
    }

}
