package ui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;

import javax.swing.*;
import java.awt.*;


public class Tabs implements ITab {
    private final JTabbedPane tabs;
    private final String name;
    private final RuleConfigPanel ruleConfigPanel;
    private final MsgInfoPanel msgInfoPanel;

    public Tabs(IBurpExtenderCallbacks callbacks, String name){
        this.name = name;

        // 定义tab标签页
        this.tabs = new JTabbedPane();

        this.msgInfoPanel = MsgInfoPanel.getInstance();
        this.tabs.add("主页", this.msgInfoPanel);

        this.ruleConfigPanel = RuleConfigPanel.getInstance();
        this.tabs.add("配置", this.ruleConfigPanel);

        // 将整个tab加载到平台即可
        callbacks.customizeUiComponent(tabs);
        // 将自定义选项卡添加到Burp的UI
        callbacks.addSuiteTab(this);
    }


    @Override
    public String getTabCaption() {
        return this.name;
    }

    @Override
    public Component getUiComponent() {
        return this.tabs;
    }
}