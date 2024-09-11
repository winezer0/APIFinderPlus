package ui;

import burp.BurpExtender;
import burp.IProxyScanner;
import utils.UiUtils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import static utils.BurpPrintUtils.*;

public class BasicUrlConfigPanel extends JPanel {
    public static JLabel lbRequestCountOnUrl;   //记录所有加入到URL的请求
    public static JLabel lbTaskerCountOnUrl;    //记录所有加入数据库的请求
    public static JLabel lbAnalysisEndCountOnUrl;   //记录所有已经分析完成的结果数量
    public static int timerDelayOnUrl=15;

    private static JComboBox<String> choicesComboBoxOnUrl;   //数据表显示快速选择框
    private static JTextField urlSearchBoxOnUrl;                 //URl搜索框

    public static JToggleButton autoRefreshUiButtonOnUrl; //自动刷新开关按钮状态
    public static JToggleButton forceDecodeUnicodeButtonOnUrl; //强制解码响应Unicode

    //用于两端联动使用
    public static JToggleButton proxyListenButtonOnUrl;
    public static JToggleButton autoRecordPathButtonOnUrl; //自动保存响应状态码合适的URL 目前过滤功能不完善,只能手动开启
    public static JToggleButton dynamicPathFilterButtonOnUrl;
    public static JToggleButton autoPathsToUrlsButtonOnUrl;
    public static JToggleButton autoRefreshUnvisitedButtonOnUrl;
    public static JToggleButton autoRecursiveButtonOnUrl;

    public BasicUrlConfigPanel() {
        GridBagLayout gridBagLayout = new GridBagLayout();
        //GridBagLayout 允许以网格形式布局容器中的组件，同时为每个组件提供独立的定位和大小控制，非常适用于需要复杂布局设计的GUI界面。
        // 列数，行数  //表示容器被划分为两列，每一列的初始宽度均为0。
        // 这里的0不代表实际宽度为零，而是告诉布局管理器根据组件的实际大小和其他约束（如权重）来计算列宽。
        gridBagLayout.columnWidths = new int[] { 0, 0};
        gridBagLayout.rowHeights = new int[] {5};
        // 各列占宽度比，各行占高度比
        gridBagLayout.columnWeights = new double[] { 1.0D, Double.MIN_VALUE };
        //设置了两列的扩展权重。第一列的权重为1.0，意味着当容器有多余空间时，这一列会优先扩展以填充可用空间。
        // 第二列的权重设为Double.MIN_VALUE，表示这一列不应该扩展，保持最小或固定大小。
        setLayout(gridBagLayout);

        //创建FilterPanel
        JPanel FilterPanel = new JPanel();
        GridBagConstraints gbc_panel_1 = new GridBagConstraints();
        gbc_panel_1.insets = new Insets(0, 5, 5, 5);
        gbc_panel_1.fill = 2;
        gbc_panel_1.gridx = 0;
        gbc_panel_1.gridy = 2;
        add(FilterPanel, gbc_panel_1);
        //设置一个名为FilterPanel的面板在父容器中的布局位置
        // 布局约束包括：
        //insets: 设置了组件边缘的内边距，上5px，左5px，下5px，右5px，为组件提供一定的间距。
        //fill: 设置组件在可扩展空间中的填充方式，值为2表示BOTH，即组件可以在水平和垂直方向上填充其显示区域。
        //gridx 和 gridy: 分别设置组件在网格布局中的起始列和起始行，这里是第0列第2行。

        //为 FilterPanel 设置布局
        GridBagLayout gbl_panel_1 = new GridBagLayout();
        gbl_panel_1.columnWidths = new int[] { 0, 0, 0, 0, 0 };//设置每列的初始宽度为0 指示布局管理器根据组件实际大小和其他约束来计算宽度。
        gbl_panel_1.rowHeights = new int[] { 0, 0 };  //设置每行的初始高度为0，指按需计算行高。

        // 指定每列的扩展权重。这里前9列的权重都设为0.0，意味着这些列不会随容器大小变化而扩展，
        // 而最后列的权重设为Double.MIN_VALUE，这通常用于指示该列应该尽可能小，不参与额外空间的分配。
        //gbl_panel_1.columnWeights = new double[] { 0.0D, 0.0D, 0.0D, 0.0D, 0.0D, 0.0D, 0.0D, 0.0D, 0.0D, Double.MIN_VALUE};
        //第一行权重为0.0，不随容器扩展，第二行的权重为Double.MIN_VALUE，表示该行也不扩展。
        gbl_panel_1.rowWeights = new double[] { 0.0D, Double.MIN_VALUE };
        FilterPanel.setLayout(gbl_panel_1);

        // 在添加 "Requests Total" 和 lbRequestCount 之前添加一个占位组件
        Component leftStrut = Box.createHorizontalStrut(5); // 你可以根据需要调整这个值
        GridBagConstraints gbc_leftStrut = new GridBagConstraints();
        gbc_leftStrut.insets = new Insets(0, 0, 0, 5);
        gbc_leftStrut.fill = GridBagConstraints.HORIZONTAL;
        gbc_leftStrut.weightx = 1.0; // 这个值决定了 leftStrut 占据的空间大小
        gbc_leftStrut.gridx = 6;
        gbc_leftStrut.gridy = 0;
        FilterPanel.add(leftStrut, gbc_leftStrut);

        // 转发url总数，默认0
        JLabel lbRequest = new JLabel("Requests Total:");
        GridBagConstraints gbc_lbRequest = new GridBagConstraints();
        gbc_lbRequest.insets = new Insets(0, 0, 0, 5);
        gbc_lbRequest.fill = GridBagConstraints.HORIZONTAL;
        gbc_lbRequest.weightx = 0.0;
        gbc_lbRequest.gridx = 0;
        gbc_lbRequest.gridy = 0;
        FilterPanel.add(lbRequest, gbc_lbRequest);

        lbRequestCountOnUrl = new JLabel("0");
        lbRequestCountOnUrl.setForeground(new Color(0,0,255));
        GridBagConstraints gbc_lbRequestCount = new GridBagConstraints();
        gbc_lbRequestCount.insets = new Insets(0, 0, 0, 5);
        gbc_lbRequestCount.fill = GridBagConstraints.HORIZONTAL;
        gbc_lbRequestCount.weightx = 0.0;
        gbc_lbRequestCount.gridx = 1;
        gbc_lbRequestCount.gridy = 0;
        FilterPanel.add(lbRequestCountOnUrl, gbc_lbRequestCount);

        // 转发成功url数，默认0
        JLabel lbTasker = new JLabel("Tasker Total:");
        GridBagConstraints gbc_lbTasker = new GridBagConstraints();
        gbc_lbTasker.insets = new Insets(0, 0, 0, 5);
        gbc_lbTasker.fill = 0;
        gbc_lbTasker.gridx = 2;
        gbc_lbTasker.gridy = 0;
        FilterPanel.add(lbTasker, gbc_lbTasker);

        lbTaskerCountOnUrl = new JLabel("0");
        lbTaskerCountOnUrl.setForeground(new Color(0, 255, 0));
        GridBagConstraints gbc_lbTaskerCount = new GridBagConstraints();
        gbc_lbTaskerCount.insets = new Insets(0, 0, 0, 5);
        gbc_lbTaskerCount.fill = 0;
        gbc_lbTaskerCount.gridx = 3;
        gbc_lbTaskerCount.gridy = 0;
        FilterPanel.add(lbTaskerCountOnUrl, gbc_lbTaskerCount);

        // 分析URL的数量
        JLabel lbAnalysisEnd = new JLabel("Analysis End:");
        GridBagConstraints gbc_lbAnalysisEnd = new GridBagConstraints();
        gbc_lbAnalysisEnd.insets = new Insets(0, 0, 0, 5);
        gbc_lbAnalysisEnd.fill = 0;
        gbc_lbAnalysisEnd.gridx = 4;
        gbc_lbAnalysisEnd.gridy = 0;
        FilterPanel.add(lbAnalysisEnd, gbc_lbAnalysisEnd);

        lbAnalysisEndCountOnUrl = new JLabel("0");
        lbAnalysisEndCountOnUrl.setForeground(new Color(0, 0, 255)); // 蓝色
        GridBagConstraints gbc_lbAnalysisEndCount = new GridBagConstraints();
        gbc_lbAnalysisEndCount.insets = new Insets(0, 0, 0, 5);
        gbc_lbAnalysisEndCount.fill = 0;
        gbc_lbAnalysisEndCount.gridx = 5;
        gbc_lbAnalysisEndCount.gridy = 0;
        FilterPanel.add(lbAnalysisEndCountOnUrl, gbc_lbAnalysisEndCount);

        // 添加填充以在左侧占位
        Component horizontalBlank = Box.createHorizontalGlue(); //创建一个水平组件
        GridBagConstraints gbc_leftFiller = new GridBagConstraints();
        gbc_leftFiller.weightx = 1; // 使得这个组件吸收额外的水平空间
        gbc_leftFiller.gridx = 6; // 位置设置为第一个单元格
        gbc_leftFiller.gridy = 0; // 第一行
        gbc_leftFiller.fill = GridBagConstraints.HORIZONTAL; // 水平填充
        FilterPanel.add(horizontalBlank, gbc_leftFiller);

        // 开关 是否开启代理流量监听 //自动保存响应状态码合适的URL 目前过滤功能不完善,只能手动开启\
        proxyListenButtonOnUrl = UiUtils.getToggleButtonByDefaultValue(BurpExtender.proxyListenIsOpenDefault);
        proxyListenButtonOnUrl.setToolTipText("Proxy模块流量监听开关");

        proxyListenButtonOnUrl.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //默认开启本功能, 点击后应该关闭配置 //默认关闭本功能, 点击后应该开启配置
                boolean selected = proxyListenButtonOnUrl.isSelected();
                IProxyScanner.proxyListenIsOpen = BurpExtender.proxyListenIsOpenDefault ? !selected : selected;
                stdout_println(LOG_DEBUG, String.format("proxyListenIsOpen: %s", IProxyScanner.proxyListenIsOpen));

                BasicHostConfigPanel.proxyListenButtonOnHost.setSelected(selected);  //联动更新Host面板的情况
            }
        });

        // 刷新按钮按钮
        JToggleButton clickRefreshButtonOnUrl = new JToggleButton(UiUtils.getImageIcon("/icon/refreshButton2.png", 24, 24));
        clickRefreshButtonOnUrl.setPreferredSize(new Dimension(30, 30));
        clickRefreshButtonOnUrl.setBorder(null);  // 设置无边框
        clickRefreshButtonOnUrl.setFocusPainted(false);  // 移除焦点边框
        clickRefreshButtonOnUrl.setContentAreaFilled(false);  // 移除选中状态下的背景填充
        clickRefreshButtonOnUrl.setToolTipText("点击强制刷新表格");

        // 手动刷新按钮监听事件
        clickRefreshButtonOnUrl.addActionListener(new ActionListener() {
            private boolean canClick = true;

            @Override
            public void actionPerformed(ActionEvent e) {
                if (canClick) {
                    canClick = false;
                    ImageIcon originalIcon = (ImageIcon) clickRefreshButtonOnUrl.getIcon();  // 保存原始图标
                    String originalTip = clickRefreshButtonOnUrl.getToolTipText();   // 保存原始批注

                    // 更换为新图标
                    clickRefreshButtonOnUrl.setIcon(UiUtils.getImageIcon("/icon/runningButton.png", 24, 24)); // 立即显示新图标

                    // 调用刷新表格的方法
                    try{
                        BasicUrlInfoPanel.getInstance().refreshBasicUrlTableModel(false);
                        //建议JVM清理内存
                        System.gc();
                    } catch (Exception ep){
                        stderr_println(LOG_ERROR, String.format("[!] 刷新表格发生错误：%s", ep.getMessage()) );
                    }
                    // 设置定时器，5秒后允许再次点击并恢复图标
                    Timer timer = new Timer(3000, new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent ae) {
                            canClick = true;
                            clickRefreshButtonOnUrl.setIcon(originalIcon); // 恢复原始图标
                            clickRefreshButtonOnUrl.setToolTipText(originalTip); // 恢复原始批注
                        }
                    });
                    timer.setRepeats(false);
                    timer.start();
                }
            }
        });

        // 开关 是否开启自动记录PATH
        autoRecordPathButtonOnUrl = UiUtils.getToggleButtonByDefaultValue(BurpExtender.autoRecordPathIsOpenDefault);
        autoRecordPathButtonOnUrl.setToolTipText("自动保存有效请求PATH");
        autoRecordPathButtonOnUrl.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //默认开启本功能, 点击后应该关闭配置 //默认关闭本功能, 点击后应该开启配置
                boolean selected = autoRecordPathButtonOnUrl.isSelected();
                IProxyScanner.autoRecordPathIsOpen = BurpExtender.autoRecordPathIsOpenDefault ? !selected : selected;
                stdout_println(LOG_DEBUG, String.format("autoRecordPathIsOpen: %s", IProxyScanner.autoRecordPathIsOpen));

                BasicHostConfigPanel.autoRecordPathButtonOnHost.setSelected(selected); //联动更新URL面板的情况
            }
        });

        // 开关 是否开启复杂的动态PATH过滤
        dynamicPathFilterButtonOnUrl= UiUtils.getToggleButtonByDefaultValue(BurpExtender.dynamicPathFilterIsOpenDefault);
        dynamicPathFilterButtonOnUrl.setToolTipText("开启智能响应过滤(访问随机URL获取目标的404页面的条件)");
        dynamicPathFilterButtonOnUrl.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //默认开启本功能, 点击后应该关闭配置 //默认关闭本功能, 点击后应该开启配置
                boolean selected = dynamicPathFilterButtonOnUrl.isSelected();
                IProxyScanner.dynamicPathFilterIsOpen = BurpExtender.dynamicPathFilterIsOpenDefault ? !selected : selected;
                stdout_println(LOG_DEBUG, String.format("dynamicPathFilterIsOpen: %s", IProxyScanner.dynamicPathFilterIsOpen));

                BasicHostConfigPanel.dynamicPathFilterButtonOnHost.setSelected(selected); //联动更新URL面板的情况
            }
        });


        autoPathsToUrlsButtonOnUrl= UiUtils.getToggleButtonByDefaultValue(BurpExtender.autoPathsToUrlsIsOpenDefault);
        autoPathsToUrlsButtonOnUrl.setToolTipText("自动基于PathTree结合FindPath生成URL");
        autoPathsToUrlsButtonOnUrl.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //默认开启本功能, 点击后应该关闭配置 //默认关闭本功能, 点击后应该开启配置
                boolean selected = autoPathsToUrlsButtonOnUrl.isSelected();
                IProxyScanner.autoPathsToUrlsIsOpen = BurpExtender.autoPathsToUrlsIsOpenDefault ? !selected : selected;
                stdout_println(LOG_DEBUG, String.format("autoPathsToUrlsIsOpen: %s", IProxyScanner.autoPathsToUrlsIsOpen));

                BasicHostConfigPanel.autoPathsToUrlsButtonOnHost.setSelected(selected); //联动更新URL面板的情况
            }
        });

        // 开关 是否开启自动刷新未访问URL
        autoRefreshUnvisitedButtonOnUrl = UiUtils.getToggleButtonByDefaultValue(BurpExtender.autoRefreshUnvisitedIsOpenDefault);
        autoRefreshUnvisitedButtonOnUrl.setToolTipText("自动刷新未访问URL");
        autoRefreshUnvisitedButtonOnUrl.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //默认开启本功能, 点击后应该关闭配置 //默认关闭本功能, 点击后应该开启配置
                boolean selected = autoRefreshUnvisitedButtonOnUrl.isSelected();
                IProxyScanner.autoRefreshUnvisitedIsOpen = BurpExtender.autoRefreshUnvisitedIsOpenDefault ? !selected : selected;
                stdout_println(LOG_DEBUG, String.format("autoRefreshUnvisitedIsOpen: %s", IProxyScanner.autoRefreshUnvisitedIsOpen));

                BasicHostConfigPanel.autoRefreshUnvisitedButtonOnHost.setSelected(selected); //联动更新URL面板的情况
            }
        });

        // 开关 是否开启对提取URL进行发起请求
        autoRecursiveButtonOnUrl= UiUtils.getToggleButtonByDefaultValue(BurpExtender.autoRecursiveIsOpenDefault);
        autoRecursiveButtonOnUrl.setToolTipText("自动测试未访问URL");
        autoRecursiveButtonOnUrl.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //默认开启本功能, 点击后应该关闭配置 //默认关闭本功能, 点击后应该开启配置
                boolean selected = autoRecursiveButtonOnUrl.isSelected();
                IProxyScanner.autoRecursiveIsOpen = BurpExtender.autoRecursiveIsOpenDefault ? !selected : selected;
                stdout_println(LOG_DEBUG, String.format("autoRecursiveIsOpen: %s", IProxyScanner.autoRecursiveIsOpen));

                BasicHostConfigPanel.autoRecursiveButtonOnHost.setSelected(selected); //联动更新URL面板的情况
            }
        });

        //刷新按钮
        autoRefreshUiButtonOnUrl= UiUtils.getToggleButtonByDefaultValue(BurpExtender.autoRefreshUiIsOpenDefault);
        autoRefreshUiButtonOnUrl.setToolTipText(String.format("每[%s]秒刷新表格", timerDelayOnUrl));
        // 自动刷新按钮监听事件
        autoRefreshUiButtonOnUrl.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //默认开启本功能, 点击后应该关闭配置 //默认关闭本功能, 点击后应该开启配置
                boolean selected = autoRefreshUiButtonOnUrl.isSelected();
                IProxyScanner.autoRefreshUiIsOpen = BurpExtender.autoRefreshUiIsOpenDefault ? !selected : selected;
                stdout_println(LOG_DEBUG, String.format("autoRefreshUiIsOpen: %s", IProxyScanner.autoRefreshUiIsOpen));

                BasicHostConfigPanel.autoRefreshUiButtonOnHost.setSelected(selected); //联动更新URL面板的情况

                //根据当前刷新开关状态配置定时器暂停或者重启
                UiUtils.setAutoRefreshUiByButton(IProxyScanner.autoRefreshUiIsOpen);
            }
        });

        // 开关 是否开启对提取URL进行发起请求
        forceDecodeUnicodeButtonOnUrl = UiUtils.getToggleButtonByDefaultValue(BurpExtender.forceDecodeUnicodeDefault);
        forceDecodeUnicodeButtonOnUrl.setToolTipText("强制解码响应Unicode 默认只对Json响应解码");
        forceDecodeUnicodeButtonOnUrl.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //默认开启本功能, 点击后应该关闭配置 //默认关闭本功能, 点击后应该开启配置
                boolean selected = forceDecodeUnicodeButtonOnUrl.isSelected();
                IProxyScanner.forceDecodeUnicode = BurpExtender.forceDecodeUnicodeDefault ? !selected : selected;
                stdout_println(LOG_DEBUG, String.format("forceDecodeUnicode: %s", IProxyScanner.forceDecodeUnicode));

                BasicHostConfigPanel.forceDecodeUnicodeButtonOnHost.setSelected(selected); //联动更新URL面板的情况
            }
        });

        // 设置按钮的 GridBagConstraints
        GridBagConstraints gbc_buttons = new GridBagConstraints();
        gbc_buttons.insets = new Insets(0, 5, 0, 5);
        gbc_buttons.gridy = 0; // 设置按钮的纵坐标位置
        gbc_buttons.fill = GridBagConstraints.NONE; // 不填充

        // 点击按钮 点击后刷新数据 含未访问数据
        gbc_buttons.gridx = 7; // 设置按钮的横坐标位置
        FilterPanel.add(proxyListenButtonOnUrl, gbc_buttons);

        gbc_buttons.gridx = 8; // 设置按钮的横坐标位置
        FilterPanel.add(forceDecodeUnicodeButtonOnUrl, gbc_buttons);

        // 自动记录有效的PATH到path表中 功能开关
        gbc_buttons.gridx = 9; // 设置按钮的横坐标位置
        FilterPanel.add(autoRecordPathButtonOnUrl, gbc_buttons);

        // 高级动态有效路径过滤 功能开关
        gbc_buttons.gridx = 10;
        FilterPanel.add(dynamicPathFilterButtonOnUrl, gbc_buttons);

        // 高级动态有效路径过滤 功能开关
        gbc_buttons.gridx = 11;
        FilterPanel.add(autoPathsToUrlsButtonOnUrl, gbc_buttons);

        // 自动刷新 未访问URL列表
        gbc_buttons.gridx = 12; // 设置按钮的横坐标位置
        FilterPanel.add(autoRefreshUnvisitedButtonOnUrl, gbc_buttons);

        // 自动递归 开关
        gbc_buttons.gridx = 13; // 设置按钮的横坐标位置
        FilterPanel.add(autoRecursiveButtonOnUrl, gbc_buttons);

        // 定时刷新按钮
        gbc_buttons.gridx = 14; // 将横坐标位置移动到下一个单元格
        FilterPanel.add(autoRefreshUiButtonOnUrl, gbc_buttons);

        // 点击按钮 点击后刷新数据 含未访问数据
        gbc_buttons.gridx = 15; // 设置按钮的横坐标位置
        FilterPanel.add(clickRefreshButtonOnUrl, gbc_buttons);

        // 添加填充以在右侧占位
        GridBagConstraints gbc_rightFiller = new GridBagConstraints();
        gbc_rightFiller.weightx = 1; // 使得这个组件吸收额外的水平空间
        gbc_rightFiller.gridx = 16; // 位置设置为最后一个单元格
        gbc_rightFiller.gridy = 0; // 第一行
        gbc_rightFiller.fill = GridBagConstraints.HORIZONTAL; // 水平填充
        FilterPanel.add(horizontalBlank, gbc_rightFiller);

        // 全部按钮
        choicesComboBoxOnUrl = new JComboBox<>(new String[]{
                "显示有效内容",
                "待处理有效内容",
                "显示敏感内容",
                "待处理敏感内容",
                "显示全部内容",
                "显示无效内容",
        });
        GridBagConstraints gbc_btnall = new GridBagConstraints();
        gbc_btnall.insets = new Insets(0, 0, 0, 5);
        gbc_btnall.fill = 0;
        gbc_btnall.gridx = 17;  // 根据该值来确定是确定从左到右的顺序
        gbc_btnall.gridy = 0;
        FilterPanel.add(choicesComboBoxOnUrl, gbc_btnall);
        // 检索框
        urlSearchBoxOnUrl = new JTextField(15);
        GridBagConstraints gbc_btnSearchField = new GridBagConstraints();
        gbc_btnSearchField.insets = new Insets(0, 0, 0, 5);
        gbc_btnSearchField.fill = 0;
        gbc_btnSearchField.gridx = 18;  // 根据该值来确定是确定从左到右的顺序
        gbc_btnSearchField.gridy = 0;
        urlSearchBoxOnUrl.setToolTipText("搜索URL关键字");
        FilterPanel.add(urlSearchBoxOnUrl, gbc_btnSearchField);
        // 检索按钮
        JButton searchButton = new JButton();
        searchButton.setIcon(UiUtils.getImageIcon("/icon/searchButton.png"));
        searchButton.setToolTipText("点击搜索");
        GridBagConstraints gbc_btnSearch = new GridBagConstraints();
        gbc_btnSearch.insets = new Insets(0, 0, 0, 5);
        gbc_btnSearch.fill = 0;
        gbc_btnSearch.gridx = 19;  // 根据该值来确定是确定从左到右的顺序
        gbc_btnSearch.gridy = 0;
        FilterPanel.add(searchButton, gbc_btnSearch);

        // 功能按钮
        JButton moreButton = new JButton();
        moreButton.setToolTipText("更多功能 ");
        moreButton.setIcon(UiUtils.getImageIcon("/icon/moreButton.png", 17, 17));
        GridBagConstraints gbc_btnMore = new GridBagConstraints();
        gbc_btnMore.insets = new Insets(0, 0, 0, 5);
        gbc_btnMore.fill = 0;
        gbc_btnMore.gridx = 20;  // 根据该值来确定是确定从左到右的顺序
        gbc_btnMore.gridy = 0;
        FilterPanel.add(moreButton, gbc_btnMore);

        // 功能按钮 弹出选项
        JPopupMenu moreMenu = UiUtils.createMoreMenuWithAction();

        // 快速选择框的监听事件
        choicesComboBoxOnUrl.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try{
                    // 触发显示所有行事件
                    String searchText = urlSearchBoxOnUrl.getText();
                    if(searchText.isEmpty()){
                        searchText = "";
                    }
                    String selectedOption = (String) choicesComboBoxOnUrl.getSelectedItem();
                    BasicUrlInfoPanel.showDataUrlTableByFilter(selectedOption, searchText);
                } catch (Exception ex) {
                    stderr_println(String.format("[!] choicesComboBoxOnUrl: %s", ex.getMessage()));
                }
            }
        });

        // 检索按钮事件监听器
        searchButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String searchText = urlSearchBoxOnUrl.getText();
                String selectedOption = (String) BasicUrlConfigPanel.choicesComboBoxOnUrl.getSelectedItem();
                BasicUrlInfoPanel.showDataUrlTableByFilter(selectedOption, searchText);
            }
        });

        //搜索框的回车事件
        urlSearchBoxOnUrl.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String searchText = urlSearchBoxOnUrl.getText();
                String selectedOption = (String) BasicUrlConfigPanel.choicesComboBoxOnUrl.getSelectedItem();
                BasicUrlInfoPanel.showDataUrlTableByFilter(selectedOption, searchText);
            }
        });

        // 点击”功能“的监听事件
        moreButton.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                moreMenu.show(e.getComponent(), e.getX(), e.getY());
            }
        });
 }

    public static String getUrlSearchBoxTextOnUrl() {
        return urlSearchBoxOnUrl.getText();
    }

    public static void setUrlSearchBoxTextOnUrl(String string) {
        urlSearchBoxOnUrl.setText(string);
    }


    public static String getComboBoxSelectedOptionOnUrl() {
        return (String) BasicUrlConfigPanel.choicesComboBoxOnUrl.getSelectedItem();
    }
}
