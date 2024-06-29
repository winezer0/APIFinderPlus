package ui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;

import javax.swing.*;
import java.awt.*;


public class Tags implements ITab {

    private final JTabbedPane tabs;
    private final String tagName;
    private FingerConfigTab fingerConfigTab;
//    private final MainPanel mailPanel;

    public Tags(IBurpExtenderCallbacks callbacks, String name){
        this.tagName = name;

        // 定义tab标签页
        tabs = new JTabbedPane();

        this.fingerConfigTab = new FingerConfigTab();
        tabs.add("配置", this.fingerConfigTab);

        //this.mailPanel = new MainPanel(callbacks, name);
        //tabs.add("主页", MainPanel.getContentPane());

        // 将整个tab加载到平台即可
        callbacks.customizeUiComponent(tabs);
        // 将自定义选项卡添加到Burp的UI
        callbacks.addSuiteTab(this);
    }


    @Override
    public String getTabCaption() {
        return this.tagName;
    }

    @Override
    public Component getUiComponent() {
        return this.tabs;
    }
}