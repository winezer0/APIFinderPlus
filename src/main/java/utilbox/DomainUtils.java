package utilbox;

import com.google.common.net.InternetDomainName;
import org.apache.commons.lang3.StringUtils;
import org.xbill.DNS.Record;
import org.xbill.DNS.*;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;



public class DomainUtils {


    //可能有xxx.services，xxx.international这样的域名,适当提高长度
    public static final String REGEX_TO_VAILDATE_DOMAIN_NAME_MAY_WITH_PORT = "^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,11}(?::\\d{1,5})?$";
    public static final String REGEX_TO_VAILDATE_DOMAIN_NAME_NO_PORT = "^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,11}$";
    //final String DOMAIN_NAME_PATTERN = "([A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}";//-this.state.scroll 这种也会被认为是合法的。

    public static final String REGEX_TO_GREP_DOMAIN_NAME_NO_PORT = "((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,11}";
    public static final String REGEX_TO_GREP_DOMAIN_NAME_MAY_WITH_PORT = "((?!-)[A-Za-z0-9-*]{1,63}(?<!-)\\.)+[A-Za-z]{2,11}(?::\\d{1,5})?";
    //加上(?::\\d{1,5})?部分，支持端口模式
    //加*号是为了匹配 类似 *.baidu.com的这种域名记录。

    /**
     * 和VAILD_DOMAIN_NAME_PATTERN的正则进行比较：
     * 前面的部分可以是((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)即不以-开头的字符串，长度1到63；也可以是(\*\.)，即*.
     * 后缀部分即可以是[A-Za-z]{2,6}，也可以是*
     * <p>
     * a86ba224e43010880724df4a4be78c11
     * administratoradministrator
     * 虽然按照RFC的规定，域名的单个字符的模块长度可以是63。但是实际使用情况中，基本不可能有这样的域名。
     */
    public static final String REGEX_TO_VAILD_WILDCARD_DOMAIN_NAME = "^((?!-)[A-Za-z0-9\\*-]{1,32}(?<!-)\\.)+([A-Za-z*]{1,11})$";
    //final String DOMAIN_NAME_PATTERN = "([A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}";//-this.state.scroll 这种也会被认为是合法的。


    //域名校验和域名提取还是要区分对待
    public static boolean isValidDomainMayPort(String domain) {
        return isValidDomainPrivate(domain, REGEX_TO_VAILDATE_DOMAIN_NAME_MAY_WITH_PORT);
    }


    public static boolean isValidDomainNoPort(String domain) {
        return isValidDomainPrivate(domain, REGEX_TO_VAILDATE_DOMAIN_NAME_NO_PORT);
    }

    private static boolean isValidDomainPrivate(String domain, String patternStr) {
        if (StringUtils.isEmpty(domain)) {
            return false;
        }

        boolean isOk = TextUtils.isRegexMatch(domain, patternStr);
        if (isOk) {
            //a86ba224e43010880724df4a4be78c11
            //administratoradministrator
            //虽然按照RFC的规定，域名的单个字符的模块长度可以是63。但是实际使用情况中，基本不可能有这样的域名。
            String tmp = domain.replaceAll("-", ".");
            String[] tmpArray = tmp.split("\\.");
            for (String item : tmpArray) {
                if (item.length() >= 32) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    /**
     * seller.uat.example.com.my
     * seller.uat.example.ph
     * seller.uat.example.sg
     * seller.test.example.ph
     * seller.test.example.sg
     * seller.uat.example.co.id
     * seller.uat.example.co.th
     * seller.test.example.vn
     * seller.uat.example.vn
     * 经常会遇到这样的域名；其中的环境关键词和后缀TLD都是变化的。
     * 但是它们属于同一类业务，我们需要能够识别这种类型的资产
     * seller.*.example.*
     *
     * @param domain
     * @return
     */
    public static boolean isValidWildCardDomain(String domain) {
        if (StringUtils.isEmpty(domain)) {
            return false;
        }

        boolean isOk = TextUtils.isRegexMatch(domain, REGEX_TO_VAILD_WILDCARD_DOMAIN_NAME);
        return isOk && domain.contains("*");
    }

    /**
     * @param wildCardDomain 比如seller.*.example.*
     * @param StrDomain      比如seller.uat.example.vn
     * @return 判断StrDomain是否符合wildCardDomain的规则
     * 注意："seller.xx.example.com"不能匹配"*.seller.*.example.*"和日常的思路想法有点不同
     */
    @Deprecated
    public static boolean isMatchWildCardDomainOld(String wildCardDomain, String StrDomain) {
        String domainRegex = wildCardDomain;
        //"seller.xx.example.com"应当匹配"*.seller.*.example.*"
        if (domainRegex.startsWith("*.")) {
            domainRegex = domainRegex.replaceFirst("\\*\\.", "((?!-)[A-Za-z0-9-]{1,63}(?<!-))+.");
        }
        if (domainRegex.endsWith(".*")) {
            domainRegex = TextUtils.replaceLast(domainRegex, ".*", ".((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)*[A-Za-z]{2,6}");
        }

        //考虑一些极端情况（*.*sel*ler*.*.*ex*ample*.*）
        //1 ".*."  这种情况*的内容不能为空，用+
        domainRegex = domainRegex.replaceAll("\\.\\*\\.", ".((?!-)[A-Za-z0-9-]{1,63}(?<!-))+.");
        //2 ".*."替换后，剩下的只有 ".*字符串" 和 "字符串*." 两种情况了，
        //3 ".*字符串"不可以以"-"开头，但是可以以它结尾
        domainRegex = domainRegex.replaceAll("\\.\\*", ".((?!-)[A-Za-z0-9-]{1,63})*");
        //4 "字符串*."可以以"-"开头，但是不可以以它结尾
        domainRegex = domainRegex.replaceAll("\\.\\*", ".([A-Za-z0-9-]{1,63}(?<!-))*");

        //replaceFirst的参数也是正则，能代替正则匹配？
        return "".equals(StrDomain.replaceFirst(domainRegex, ""));
    }

    /**
     * @param wildCardDomain 比如seller.*.example.*
     * @param StrDomain      比如seller.uat.example.vn
     * @return 判断StrDomain是否符合wildCardDomain的规则
     */
    public static boolean isMatchWildCardDomain(String wildCardDomain, String StrDomain) {
        String domainRegex = wildCardDomain;
        domainRegex = domainRegex.replaceAll("\\.", "\\\\.");//  . ---> \.  即域名中的点表示原意,不是正则中的点

        domainRegex = domainRegex.replaceAll("\\*", "\\.\\*");//  * ---> .*  即*就是正则中的.*
        //System.out.println(domainRegex);

        return TextUtils.isRegexMatch(StrDomain, domainRegex);
    }

    public static List<String> grepDomainAndPort(String text) {
        return TextUtils.grepWithRegex(text, REGEX_TO_GREP_DOMAIN_NAME_MAY_WITH_PORT);
    }

    public static List<String> grepDomainNoPort(String text) {
        return TextUtils.grepWithRegex(text, REGEX_TO_GREP_DOMAIN_NAME_NO_PORT);
    }

    public static List<String> grepPort(String text) {
        return TextUtils.grepWithRegex(text, "(\\d{1,6})");
    }

    /**
     * http://www.xbill.org/dnsjava/dnsjava-current/examples.html
     * 返回数据格式如下
     * {IP=[69.171.234.48], CDN=[www.google.com.]}
     *
     * @param domain
     * @param server
     * @return
     */
    public static HashMap<String, Set<String>> dnsQuery(String domain, String server) {
        HashMap<String, Set<String>> result = new HashMap<>();
        Set<String> IPset = new HashSet<>();
        Set<String> CDNSet = new HashSet<>();
        result.put("IP", IPset);
        result.put("CDN", CDNSet);

        if (domain == null || IPAddressUtils.isValidIPv4NoPort(domain)) {//目标是一个IP
            IPset.add(domain);
            result.put("IP", IPset);
            return result;
        }

        try {
            Resolver resolver = null;
            Lookup lookup = new Lookup(domain, Type.A);
            if (IPAddressUtils.isValidIPv4MayPort(server)) {
                resolver = new SimpleResolver(server);
                lookup.setResolver(resolver);
            }
            lookup.run();

            if (lookup.getResult() == Lookup.SUCCESSFUL) {
                Record[] records = lookup.getAnswers();
                for (Record record : records) {
                    ARecord a = (ARecord) record;
                    String ip = a.getAddress().getHostAddress();
                    String CName = a.getAddress().getHostName();
                    if (ip != null) {
                        IPset.add(ip);
                    }
                    if (CName != null) {
                        CDNSet.add(CName);
                    }
                }
            } else if (lookup.getResult() == Lookup.TRY_AGAIN) {
                if (resolver == null) {
                    System.out.println("DNS Query Failed with default server, try with 8.8.8.8");
                    return dnsQuery(domain, "8.8.8.8");
                }
                if (server.equals("8.8.8.8")) {
                    System.out.println("DNS Query Failed with 8.8.8.8, try with 223.6.6.6");
                    return dnsQuery(domain, "223.6.6.6");
                }
            }
            result.put("IP", IPset);
            result.put("CDN", CDNSet);
            return result;

        } catch (Exception e) {
            e.printStackTrace();
            return result;
        }
    }


    /**
     * 获取域名的权威服务器
     *
     * @param domain
     * @param server 可以为null
     * @return
     */
    public static List<String> GetAuthServer(String domain, String server) {
        List<String> result = new ArrayList<>();
        if (StringUtils.isEmpty(domain) || IPAddressUtils.isValidIPv4MayPort(domain)) {//目标是一个IP
            return result;
        }
        try {
            Lookup lookup = new Lookup(domain, Type.NS);
            if (IPAddressUtils.isValidIPv4MayPort(server) || DomainUtils.isValidDomainMayPort(server)) {
                Resolver resolver = new SimpleResolver(server);
                lookup.setResolver(resolver);
            }
            lookup.run();

            if (lookup.getResult() == Lookup.SUCCESSFUL) {
                Record[] records = lookup.getAnswers();
                for (int i = 0; i < records.length; i++) {
                    NSRecord a = (NSRecord) records[i];
                    String Nserver = a.getTarget().toString();
                    if (StringUtils.isNotEmpty(Nserver)) {
                        result.add(Nserver);
                    }
                }
            }
            return result;
        } catch (Exception e) {
            e.printStackTrace();
            return result;
        }
    }

    public static List<String> ZoneTransferCheck(String domain, String NameServer) {
        List<String> result = new ArrayList<>();
        try {
            ZoneTransferIn zone = ZoneTransferIn.newAXFR(new Name(domain), NameServer, null);
            zone.run();
            result = zone.getAXFR();
            return result;
        } catch (Exception e1) {

        }
        return result;
    }


    /**
     * 注意，仅用于relatedToRoot转换时
     *
     * @param inputDomain
     * @return
     */
    public static String getRootDomain(String inputDomain) {
        inputDomain = DomainUtils.clearDomainWithoutPort(inputDomain);
        try {
            return InternetDomainName.from(inputDomain).topPrivateDomain().toString();
        } catch (Exception e) {
            //InternetDomainName.from("www.jd.local").topPrivateDomain()//Not under a public suffix: www.jd.local
            Set<String> customPublicSuffixes = new HashSet<>();
            customPublicSuffixes.add("inner");
            customPublicSuffixes.add("local");

            int lastIndex = inputDomain.lastIndexOf(".");
            if (lastIndex != -1 && lastIndex + 1 <= inputDomain.length()) {
                String suffix = inputDomain.substring(lastIndex + 1);
                if (customPublicSuffixes.contains(suffix)) {
                    int secondLastIndex = inputDomain.lastIndexOf(".", lastIndex - 1);
                    if (secondLastIndex != -1 && secondLastIndex + 1 <= inputDomain.length()) {
                        return inputDomain.substring(secondLastIndex + 1);
                    }
                }
            }
        }
        return inputDomain;
    }

    /**
     * 获取纯域名，不包含端口
     *
     * @param domain
     * @return
     */
    public static String clearDomainWithoutPort(String domain) {
        if (domain == null) {
            return null;
        }
        domain = domain.toLowerCase().trim();
        if (domain.startsWith("http://") || domain.startsWith("https://")) {
            try {
                domain = new URL(domain).getHost();
            } catch (MalformedURLException e) {
                return null;
            }
        } else {
            if (domain.contains(":")) {//处理带有端口号的域名
                domain = domain.substring(0, domain.indexOf(":"));
            }
        }

        if (domain.endsWith(".")) {
            domain = domain.substring(0, domain.length() - 1);
        }

        return domain;
    }

    /**
     * 是否是TLD域名。比如 baidu.net 是baidu.com的TLD域名
     * 注意：www.baidu.com不是baidu.com的TLD域名，但是是子域名！！！
     * <p>
     * 这里的rootDomain不一定是 topPrivate。比如 examplepay.example.sg 和examplepay.example.io
     *
     * @param domain
     * @param rootDomain
     */
    @Deprecated //范围太广，误报太多
    private static boolean isTLDDomain(String domain, String rootDomain) {
        try {
            InternetDomainName suffixDomain = InternetDomainName.from(domain).publicSuffix();
            InternetDomainName suffixRootDomain = InternetDomainName.from(rootDomain).publicSuffix();
            if (suffixDomain != null && suffixRootDomain != null) {
                String suffixOfDomain = suffixDomain.toString();
                String suffixOfRootDomain = suffixRootDomain.toString();//TODO 校验一下；gettitle控制
                //域名后缀比较
                if (suffixOfDomain.equalsIgnoreCase(suffixOfRootDomain)) {
                    return false;
                }
                //去除后缀然后比较
                String tmpDomain = TextUtils.replaceLast(domain, suffixOfDomain, "");
                String tmpRootdomain = TextUtils.replaceLast(rootDomain, suffixOfRootDomain, "");
                if (tmpDomain.endsWith("." + tmpRootdomain) || tmpDomain.equalsIgnoreCase(tmpRootdomain)) {
                    return true;
                }
            }
            return false;
        } catch (IllegalArgumentException e) {
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * 相比isTLDDomain() 通过白名单缩小范围
     *
     * @param domain
     * @param rootDomain
     * @return
     */
    public static boolean isWhiteListTLD(String domain, String rootDomain) {
        String listStr = ".ac|.ad|.ae|.af|.ag|.ai|.al|.am|.ao|.aq|.ar|.as|.at|.au|.aw|.ax|.az|.ba|" +
                ".bb|.bd|.be|.bf|.bg|.bh|.bi|.bj|.bm|.bn|.bo|.bq|.br|.bs|.bt|.bw|.by|.bz|.ca|" +
                ".cc|.cd|.cf|.cg|.ch|.ci|.ck|.cl|.cm|.cn|.co|.com|.cr|.cu|.cv|.cw|.cx|.cy|.cz|" +
                ".de|.dj|.dk|.dm|.do|.dz|.ec|.edu|.ee|.eg|.eh|.er|.es|.et|.eu|.fi|.fj|.fk|.fm|" +
                ".fo|.fr|.ga|.gd|.ge|.gf|.gg|.gh|.gi|.gl|.gm|.gn|.gov|.gp|.gq|.gr|.gs|.gt|.gu|" +
                ".gw|.gy|.hk|.hm|.hn|.hr|.ht|.hu|.id|.ie|.il|.im|.in|.int|.io|.iq|.ir|.is|.it|" +
                ".je|.jm|.jo|.jp|.ke|.kg|.kh|.ki|.km|.kn|.kp|.kr|.kw|.ky|.kz|.la|.lb|.lc|.li|" +
                ".lk|.lr|.ls|.lt|.lu|.lv|.ly|.ma|.mc|.md|.me|.mg|.mh|.mil|.mk|.ml|.mm|.mn|.mo|" +
                ".mp|.mq|.mr|.ms|.mt|.mu|.mv|.mw|.mx|.my|.mz|.na|.nc|.ne|.net|.nf|.ng|.ni|.nl|" +
                ".no|.np|.nr|.nu|.nz|.om|.org|.pa|.pe|.pf|.pg|.ph|.pk|.pl|.pm|.pn|.pr|.ps|.pt|" +
                ".pw|.py|.qa|.re|.ro|.rs|.ru|.rw|.sa|.sb|.sc|.sd|.se|.sg|.sh|.si|.sk|.sl|.sm|" +
                ".sn|.so|.sr|.ss|.st|.su|.sv|.sx|.sy|.sz|.tc|.td|.tf|.tg|.th|.tj|.tk|.tl|.tm|" +
                ".tn|.to|.tr|.tt|.tv|.tw|.tz|.ua|.ug|.uk|.us|.uy|.uz|.va|.vc|.ve|.vg|.vi|.vn|" +
                ".vu|.wf|.ws|.ye|.yt|.za|.zm|.zw";
        List<String> tlds = Arrays.asList(listStr.split("\\|"));

        try {
            if (isTLDDomain(domain, rootDomain)) {
                String suffixOfDomain = InternetDomainName.from(domain).publicSuffix().toString();//没有保护点号
                String[] items = suffixOfDomain.split("\\.");
                for (String item : items) {
                    if (!tlds.contains("." + item)) {
                        return false;
                    }
                }
                return true;
            }
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * 由于这里的rootDomain是我们自己指定的不一定是topPrivate。
     * 比如 examplepay.example.sg 和examplepay.example.io 应该返回false
     * 比如 examplepay.example.sg example.io 应该返回true
     * <p>
     * 关键看rootDomain是不是topPrivate
     *
     * @param domain
     * @param rootDomain
     * @return
     */
    public static boolean isTLDDomainOfTopPrivate(String domain, String rootDomain) {
        try {
            if (isTLDDomain(domain, rootDomain)) {
                return !InternetDomainName.from(rootDomain).hasParent();
            }
            return false;
        } catch (IllegalArgumentException e) {
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }


    /**
     * 将域名或IP拼接成URL
     *
     * @param host 如果想要指定自定义端口，传入类似baidu.com:8888的形式即可
     * @return
     */
    public static List<URL> toURLs(String host) {
        List<URL> result = new ArrayList<>();
        if (host == null) return result;

        host = host.trim();
        int port = -1;
        if (IPAddressUtils.isValidIPv4MayPort(host) || DomainUtils.isValidDomainMayPort(host)) {
            try {
                if (host.contains(":")) {
                    host = host.split(":")[0];
                    port = Integer.parseInt(host.split(":")[1]);
                }
            } catch (Exception e) {
                return result;
            }
        }

        try {
            result.add(new URL(String.format("http://%s:%s/", host, 80)));
            result.add(new URL(String.format("https://%s:%s/", host, 443)));

            if (port == -1 || port == 80 || port == 443) {
                //Nothing to do;
            } else {
                result.add(new URL(String.format("http://%s:%s/", host, port)));
                result.add(new URL(String.format("https://%s:%s/", host, port)));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }


    public static void testWildCard() {
        System.out.println(isMatchWildCardDomain("*.baidu.com", "www.baidu.com"));
        System.out.println(isMatchWildCardDomain("*.seller.*.example.*", "xxx.xxx.seller.xxx.example.com"));
        System.out.println(isMatchWildCardDomain("*.seller.*.example.*", "seller.xx.example.com"));
        System.out.println(isMatchWildCardDomain("*.*", "aaa"));
        System.out.println(isMatchWildCardDomain("*.*", "aa.aa"));
    }

    public static void testWild() {
        System.out.println(isValidWildCardDomain("*.baidu.com"));
        System.out.println(isValidWildCardDomain("*.seller.*.example.com"));
        System.out.println(isValidWildCardDomain("*.seller.*.example.*"));
        System.out.println(isValidWildCardDomain("*xxx*.baidu.com"));
        System.out.println(isValidWildCardDomain("*.*"));
    }


    public static void main(String[] args) {
        //System.out.println(isWhiteListTDL("test.example.co.th","example.com"));
        System.out.println(isValidDomainMayPort("test-api.xxx.services:22"));
        //testWild();

        //System.out.println(isValidWildCardDomain("aaaaaaaaa-aaaaaaaaaaaaaaa-aaaaaaaaaaaaaa.www1.baidu.com"));
        //System.out.println(dnsquery("www.google1.com",null));
    }
}
