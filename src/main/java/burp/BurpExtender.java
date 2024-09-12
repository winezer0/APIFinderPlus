package burp;


import com.alibaba.fastjson2.JSON;
import database.DBService;
import model.FingerPrintRule;
import model.FingerPrintRulesWrapper;
import ui.BasicHostInfoPanel;
import ui.BasicUrlInfoPanel;
import ui.Tabs;
import utils.BurpFileUtils;
import utils.BurpPrintUtils;
import utils.ConfigUtils;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import static utils.BurpPrintUtils.*;
import static utils.CastUtils.isEmptyObj;
import static utils.CastUtils.isNotEmptyObj;

public class BurpExtender implements IBurpExtender, IExtensionStateListener, IContextMenuFactory {
    private static IBurpExtenderCallbacks callbacks;
    private static PrintWriter stdout;
    private static PrintWriter stderr;
    private static IExtensionHelpers helpers;

    private static IProxyScanner iProxyScanner;
    private static Tabs tags;

    public static PrintWriter getStdout() {
        return stdout;
    }

    public static PrintWriter getStderr() {
        return stderr;
    }

    public static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public static IExtensionHelpers getHelpers() {
        return helpers;
    }

    public static IProxyScanner getIProxyScanner() {
        return iProxyScanner;
    }

    public static String extensionName = "APIFinderPlus";

    public static List<FingerPrintRule> fingerprintRules;


    //响应体分割的大小 字符串长度
    public static int maxPatterChunkSizeDefault=20000;
    //最大支持存储的响应 比特长度
    public static int maxStoreRespBodyLenDefault=500000;
    //自动处理任务的时间频率,性能越低,频率越应该慢
    public static int monitorExecutorIntervalsDefault=4;
    //是否启用增强的path过滤模式 //需要设置默认关闭,暂时功能没有完善、对于URL无法访问的情况没有正常处理、导致卡顿
    public static boolean dynamicPathFilterIsOpenDefault=false;
    //是否启用自动记录每个请求的PATH //自动记录功能应该开启,不然没有pathTree生成
    public static boolean autoRecordPathIsOpenDefault=true;
    //是否进行自动PathTree生成URL
    public static boolean autoPathsToUrlsIsOpenDefault=true;
    //是否进行递归URL扫描
    public static boolean autoRecursiveIsOpenDefault=false;
    //开关插件的监听功能
    public static boolean proxyListenIsOpenDefault=false;
    //自动刷新未访问URL的功能
    public static boolean autoRefreshUnvisitedIsOpenDefault=false;
    //自动刷新表格
    public static boolean autoRefreshUiIsOpenDefault=false;
    //自动解码响应Unicode字符
    public static boolean forceDecodeUnicodeDefault=false;

    //一些需要被排除|允许的情况
    public static List<String> CONF_DEFAULT_PERFORMANCE = new ArrayList<>(); //默认的性能配置选项
    public static List<String> CONF_WHITE_ROOT_URL = new ArrayList<>(); //仅保留的白名单主机,为空时忽略

    public static List<String> CONF_WHITE_RECORD_PATH_STATUS = new ArrayList<>(); //作为正常访问结果的状态码

    public static List<String> CONF_BLACK_URL_EXT = new ArrayList<>(); //不检查的URL后缀
    public static List<String> CONF_BLACK_URI_PATH_KEYS = new ArrayList<>(); //不检查的URL路径
    public static List<String> CONF_BLACK_ROOT_URL = new ArrayList<>(); //不检查的ROOT URL 关键字
    public static List<String> CONF_BLACK_AUTO_RECORD_PATH = new ArrayList<>(); //不检查的ROOT URL 关键字
    public static List<String> CONF_BLACK_AUTO_RECURSE_SCAN = new ArrayList<>(); //不检查的ROOT URL 关键字

    public static List<String> CONF_BLACK_RECORD_PATH_TITLE = new ArrayList<>(); // 不记录到PATH 的 TITLE 关键字

    public static List<String> CONF_BLACK_EXTRACT_PATH_EQUAL = new ArrayList<>();  //需要忽略的响应提取路径 完整路径

    public static List<String> CONF_BLACK_EXTRACT_INFO_KEYS = new ArrayList<>();  //需要忽略的响应提取信息
    public static List<String> CONF_REGULAR_EXTRACT_URIS = new ArrayList<>();  //URL提取正则表达式

    public static List<Pattern> URI_MATCH_REGULAR_COMPILE = new ArrayList<>();  //存储编译后的正则表达式

    //添加HTTP请求相关参数配置
    public static List<String> CONF_BLACK_RECURSE_REQ_PATH_KEYS = new ArrayList<>();  //禁止递归访问的URL路径[包含]此项任一元素
    public static List<String> CONF_RECURSE_REQ_HTTP_METHODS = new ArrayList<>();  //递归访问URL时的HTTP请求方法
    public static List<String> CONF_RECURSE_REQ_HTTP_PARAMS = new ArrayList<>();  //递归访问URL时的HTTP请求参数

    private static DBService dbService;  //数据库实例

    public static int SHOW_MSG_LEVEL = LOG_DEBUG;  //显示消息级别

    public static  String configName = "finger-important.json";

    public static boolean onlyScopeDomain = false; //是否仅显示本主机域名的URL


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        new BurpPrintUtils(this.stdout, this.stderr);  //初始化输出类

        SwingUtilities.invokeLater(new Runnable() { public void run() {
            // 读取配置文件参数
            String configJson = BurpFileUtils.ReadPluginConfFile(callbacks, configName, StandardCharsets.UTF_8);
            // 加载配置规则
            if(isNotEmptyObj(configJson)){
                FingerPrintRulesWrapper rulesWrapper;
                try{
                    rulesWrapper = JSON.parseObject(configJson, FingerPrintRulesWrapper.class);
                } catch (Exception e){
                    stderr_println(LOG_ERROR, String.format("[!] JSON.parseObject Config Error:[%s]", e.getMessage()));
                    configJson = BurpFileUtils.ReadPluginConfFile(callbacks, configName, Charset.forName("GBK"));
                    rulesWrapper = JSON.parseObject(configJson, FingerPrintRulesWrapper.class);
                }
                // 使用Fastjson的parseObject方法将JSON字符串转换为Rule对象
                fingerprintRules = rulesWrapper.getFingerprint();
                ConfigUtils.reloadConfigArrayListFromRules(fingerprintRules);
                stdout_println(LOG_INFO, String.format("[*] Load Config Rules Size: %s", fingerprintRules.size()));
            }

            if (isEmptyObj(fingerprintRules)){
                stderr_println(LOG_ERROR, "[!] 配置文件加载出错!!!");
                return;
            }

            //加载UI 标签界面
            tags = new Tabs(callbacks, extensionName);

            //初始化数据配置
            dbService = DBService.getInstance();
            dbService.initDBConnection();
            dbService.initCreateTables();

            //注册监听操作
            iProxyScanner = new IProxyScanner();
            callbacks.registerProxyListener(iProxyScanner);

            // 注册插件状态监听操作
            callbacks.registerExtensionStateListener(BurpExtender.this);
            callbacks.registerContextMenuFactory(BurpExtender.this); //注册右键菜单Factory


            //设置插件已加载完成
            stdout_println(LOG_INFO, String.format("[+] Extension [%s] Loaded Successfully ...", extensionName));
        }});
    }

    @Override
    public void extensionUnloaded() {
        // 扩展卸载时，立刻关闭线程池
        stdout_println(LOG_DEBUG, "[+] Extension Will Unloaded, Cleaning Resources ing ...");

        // 立刻关闭线程池
        if (iProxyScanner.executorService != null) {
            // 尝试立即关闭所有正在执行的任务
            List<Runnable> notExecutedTasks = iProxyScanner.executorService.shutdownNow();
            stdout_println(LOG_DEBUG, "[+] Try to Stop All Tasks, The Number of Not Executed Tasks：" + notExecutedTasks.size());
        }

        //停止UI的定时任务    // 停止面板更新器
        BasicUrlInfoPanel.stopTimerBasicUrl();
        BasicHostInfoPanel.stopTimerBasicHost();

        // 关闭计划任务
        IProxyScanner.shutdownMonitorExecutor();
        stdout_println(LOG_DEBUG, "[+] The Scheduled Task is Shutdown Successfully...");

        // 关闭数据库连接
        if (dbService != null) {
            dbService.closeConnection();
            stdout_println(LOG_DEBUG, "[+] The Database Connection is Disconnected Successfully...");
        }

        stdout_println(LOG_INFO, String.format("[-] Extension [%s] Unloaded Complete .", this.extensionName));
    }

    //callbacks.registerContextMenuFactory(this);//必须注册右键菜单Factory
    //实现右键 感谢原作者Conanjun
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        final IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        JMenuItem menuItem = new JMenuItem(String.format("Send to %s", BurpExtender.extensionName));
        menuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                for (final IHttpRequestResponse message : messages) {
                    IProxyScanner.addRightScanTask(message);
                }
            }
        });

        return Arrays.asList(menuItem);
    }

}