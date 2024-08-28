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
    private final HostInfoPanel hostInfoPanel;

    public Tabs(IBurpExtenderCallbacks callbacks, String name){
        this.name = name;

        // 定义tab标签页
        this.tabs = new JTabbedPane();

        this.hostInfoPanel = HostInfoPanel.getInstance();
        this.tabs.add("聚合面板", this.hostInfoPanel);

        this.msgInfoPanel = MsgInfoPanel.getInstance();
        this.tabs.add("请求详情", this.msgInfoPanel);

        this.ruleConfigPanel = RuleConfigPanel.getInstance();
        this.tabs.add("规则配置", this.ruleConfigPanel);

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