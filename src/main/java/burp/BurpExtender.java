package burp;


import com.alibaba.fastjson2.JSON;
import dataModel.DBService;
import model.FingerPrintRule;
import model.FingerPrintRulesWrapper;
import utils.BurpPrintUtils;

import javax.swing.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import static utils.BurpFileUtils.ReadPluginConfFile;
import static utils.BurpPrintUtils.*;


public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    private static IBurpExtenderCallbacks callbacks;
    private static PrintWriter stdout;
    private static PrintWriter stderr;
    private static IExtensionHelpers helpers;

    private static IProxyScanner iProxyScanner;

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

    public static String extensionName = "APIFinder";

    public static List<FingerPrintRule> fingerprintRules;

    //一些需要被排除|允许的情况
    public static List<String> CONF_NEED_RECORD_STATUS = new ArrayList<>(); //作为正常访问结果的状态码

    public static List<String> CONF_BLACK_URL_EXT = new ArrayList<>(); //不检查的URL后缀
    public static List<String> CONF_BLACK_URL_PATH = new ArrayList<>(); //不检查的URL路径
    public static List<String> CONF_BLACK_URL_HOSTS = new ArrayList<>(); //不检查的URL域名

    public static List<String> CONF_BLACK_PATH_KEYS = new ArrayList<>();  //需要忽略的响应提取路径 关键字
    public static List<String> CONF_BLACK_PATH_EQUALS = new ArrayList<>();  //需要忽略的响应提取路径 完整路径

    public static List<String> CONF_EXTRACT_SUFFIX = new ArrayList<>(); //需要提取API的URL后缀类型

    private static DBService dbService;  //数据库实例

    public static int SHOW_MSG_LEVEL = LOG_DEBUG;  //显示消息级别

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        new BurpPrintUtils(this.stdout, this.stderr);  //初始化输出类

        SwingUtilities.invokeLater(new Runnable() { public void run() {
            // 读取配置文件参数
            String configName = "finger-important.json";
            String configJson = ReadPluginConfFile(callbacks, configName);
            // 加载配置规则
            if(configJson != null && configJson != ""){
                // 使用Fastjson的parseObject方法将JSON字符串转换为Rule对象
                FingerPrintRulesWrapper rulesWrapper = JSON.parseObject(configJson, FingerPrintRulesWrapper.class);
                fingerprintRules = rulesWrapper.getFingerprint();
                // 从规则json内获取黑名单设置 //此处后续可能需要修改,修改配置类型
                if (fingerprintRules != null && !fingerprintRules.isEmpty()){
                    for (int i = 0 ; i < fingerprintRules.size(); i ++){
                        FingerPrintRule rule = fingerprintRules.get(i);

                        if (rule.getIsOpen())
                            switch (rule.getType()) {
                                case "CONF_NEED_RECORD_STATUS":
                                    CONF_NEED_RECORD_STATUS.addAll(rule.getKeyword());
                                    break;

                                case "CONF_BLACK_URL_HOSTS":
                                    CONF_BLACK_URL_HOSTS.addAll(rule.getKeyword());
                                    break;
                                case "CONF_BLACK_URL_PATH":
                                    CONF_BLACK_URL_PATH.addAll(rule.getKeyword());
                                    break;
                                case "CONF_BLACK_URL_EXT":
                                    CONF_BLACK_URL_EXT.addAll(rule.getKeyword());
                                    break;

                                case "CONF_EXTRACT_SUFFIX":
                                    CONF_EXTRACT_SUFFIX.addAll(rule.getKeyword());
                                    break;

                                case "CONF_BLACK_PATH_KEYS":
                                    CONF_BLACK_PATH_KEYS.addAll(rule.getKeyword());
                                    break;
                                case "CONF_BLACK_PATH_EQUALS":
                                    CONF_BLACK_PATH_EQUALS.addAll(rule.getKeyword());
                                    break;
                                default:
                                    break;
                            }
                    }

                    stdout_println(LOG_INFO, String.format("[*] Load Config Rules Size: %s", fingerprintRules.size()));
                }
            }

            //初始化数据配置
            dbService = DBService.getInstance();

            //注册监听操作
            BurpExtender.iProxyScanner = new IProxyScanner();
            callbacks.registerProxyListener(iProxyScanner);

            // 标签界面, ExtensionTab 构造时依赖 BurpExtender.callbacks, 所以这个必须放在下面
            // BurpExtender.tags = new Tags(callbacks, extensionName);

            // 注册插件状态监听操作
            callbacks.registerExtensionStateListener(BurpExtender.this);
        }});

        //表示打印成功
        stdout_println(LOG_INFO, String.format("[+] %s Load success ...", this.extensionName));
    }

    @Override
    public void extensionUnloaded() {
        // 扩展卸载时，立刻关闭线程池
        stdout_println(LOG_DEBUG, "[+] Plugin will unloaded, cleaning resources...");

        // 立刻关闭线程池
        if (iProxyScanner.executorService != null) {
            // 尝试立即关闭所有正在执行的任务
            List<Runnable> notExecutedTasks = iProxyScanner.executorService.shutdownNow();
            stdout_println(LOG_DEBUG, "[+] 尝试停止所有任务, 未执行的任务数量：" + notExecutedTasks.size());
        }

        //Todo: 停止面板更新器, 待实现数据查询面板
        //MailPanel.timer.stop();

        // 关闭数据库连接
        if (dbService != null) {
            dbService.closeConnection();
            stdout_println(LOG_DEBUG, "[+] 断开数据连接成功.");
        }

        // 关闭计划任务
        IProxyScanner.shutdownMonitorExecutor();
        stdout_println(LOG_DEBUG, "[+] 定时爬去任务断开成功.");

        stdout_println(LOG_INFO, String.format("[-] %s Unloaded ...", this.extensionName));
    }
}