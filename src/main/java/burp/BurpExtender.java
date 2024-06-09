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
    public static List<String> ALLOWED_STATUS_CODE = new ArrayList<>(); //作为正常访问结果的状态码, 为空时应该跳过判断
    public static List<String> UN_CHECKED_URL_EXT = new ArrayList<>(); //不检查的URL后缀
    public static List<String> UN_CHECKED_URL_PATH = new ArrayList<>(); //不检查的URL路径
    public static List<String> UN_CHECKED_URL_DOMAIN = new ArrayList<>(); //不检查的URL域名
    public static List<String> UN_CHECKED_RESP_PATH = new ArrayList<>();  //不检查的响应路径

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
                            case "ALLOWED_STATUS_CODE":
                                ALLOWED_STATUS_CODE.addAll(rule.getKeyword());
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
                            case "UN_CHECKED_RESP_PATH":
                                UN_CHECKED_RESP_PATH.addAll(rule.getKeyword());
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
        // 关闭数据库连接
        if (dbService != null) {
            dbService.closeConnection();
            BurpExtender.getStdout().println("[+] 断开数据连接成功.");
        }

        stdout.println(String.format("[-] %s Unloaded ...", this.extensionName));
    }
}