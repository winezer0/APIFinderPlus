package burp;


import com.alibaba.fastjson2.JSON;
import dataModel.DBService;
import model.FingerPrintRule;
import model.FingerPrintRulesWrapper;

import javax.swing.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import static utils.BurpFileUtils.ReadPluginConfFile;

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
    public static List<String> NEED_RECORD_STATUS_CODE = new ArrayList<>(); //作为正常访问结果的状态码

    public static List<String> UN_CHECKED_URL_EXT = new ArrayList<>(); //不检查的URL后缀
    public static List<String> UN_CHECKED_URL_PATH = new ArrayList<>(); //不检查的URL路径
    public static List<String> UN_CHECKED_URL_DOMAIN = new ArrayList<>(); //不检查的URL域名

    public static List<String> USELESS_PATH_KEYS = new ArrayList<>();  //需要忽略的响应提取路径 关键字
    public static List<String> USELESS_PATH_EQUAL = new ArrayList<>();  //需要忽略的响应提取路径 完整路径

    public static List<String> NEED_EXTRACT_SUFFIX = new ArrayList<>(); //需要提取API的URL后缀类型

    private static DBService dbService;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);


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
                        String type = rule.getType();
                        switch (type) {
                            case "NEED_RECORD_STATUS_CODE":
                                NEED_RECORD_STATUS_CODE.addAll(rule.getKeyword());
                                break;

                            case "UN_CHECKED_URL_EXT":
                                UN_CHECKED_URL_EXT.addAll(rule.getKeyword());
                                break;
                            case "UN_CHECKED_URL_PATH":
                                UN_CHECKED_URL_PATH.addAll(rule.getKeyword());
                                break;
                            case "UN_CHECKED_URL_DOMAIN":
                                UN_CHECKED_URL_DOMAIN.addAll(rule.getKeyword());
                                break;

                            case "NEED_EXTRACT_SUFFIX":
                                NEED_EXTRACT_SUFFIX.addAll(rule.getKeyword());
                                break;

                            case "USELESS_PATH_KEYS":
                                USELESS_PATH_KEYS.addAll(rule.getKeyword());
                                break;
                            case "USELESS_PATH_EQUAL":
                                USELESS_PATH_EQUAL.addAll(rule.getKeyword());
                                break;
                            default:
                                break;
                        }
                    }

                    stdout.println(String.format("[*] Load Config Rules Size: %s", fingerprintRules.size()));
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
        stdout.println(String.format("[+] %s Load success ...", this.extensionName));
    }




    @Override
    public void extensionUnloaded() {
        // 扩展卸载时，立刻关闭线程池
        stdout.println("[+] Plugin will unloaded, cleaning resources...");

        // 立刻关闭线程池
        if (iProxyScanner.executorService != null) {
            // 尝试立即关闭所有正在执行的任务
            List<Runnable> notExecutedTasks = iProxyScanner.executorService.shutdownNow();
            stdout.println("[+] 尝试停止所有任务, 未执行的任务数量：" + notExecutedTasks.size());
        }

        //Todo: 停止面板更新器, 待实现数据查询面板
        //MailPanel.timer.stop();

        // 关闭数据库连接
        if (dbService != null) {
            dbService.closeConnection();
            stdout.println("[+] 断开数据连接成功.");
        }

        // 关闭计划任务
        IProxyScanner.shutdownMonitorExecutor();
        stdout.println("[+] 定时爬去任务断开成功.");

        stdout.println(String.format("[-] %s Unloaded ...", this.extensionName));
    }
}