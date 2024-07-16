package ui;

import burp.BurpExtender;
import burp.IProxyScanner;
import database.*;
import utils.BurpSitemapUtils;
import utils.CastUtils;
import utils.UiUtils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.time.LocalDateTime;

import static utils.BurpPrintUtils.*;

public class ConfigPanel extends JPanel {
    public static JLabel lbRequestCount;   //记录所有加入到URL的请求
    public static JLabel lbTaskerCount;    //记录所有加入数据库的请求
    public static JLabel lbAnalysisEndCount;   //记录所有已经分析完成的结果数量

    private static JComboBox<String> choicesComboBox;   //数据表显示快速选择框
    private static JTextField urlSearchBox;                 //URl搜索框

    private static JToggleButton autoRefreshButton; //自动刷新开关按钮状态
    private static JLabel autoRefreshText; //自动刷新按钮显示的文本
    public static int timerDelay = 15;  //定时器刷新间隔,单位秒

    public ConfigPanel() {
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

        lbRequestCount = new JLabel("0");
        lbRequestCount.setForeground(new Color(0,0,255));
        GridBagConstraints gbc_lbRequestCount = new GridBagConstraints();
        gbc_lbRequestCount.insets = new Insets(0, 0, 0, 5);
        gbc_lbRequestCount.fill = GridBagConstraints.HORIZONTAL;
        gbc_lbRequestCount.weightx = 0.0;
        gbc_lbRequestCount.gridx = 1;
        gbc_lbRequestCount.gridy = 0;
        FilterPanel.add(lbRequestCount, gbc_lbRequestCount);

        // 转发成功url数，默认0
        JLabel lbTasker = new JLabel("Tasker Total:");
        GridBagConstraints gbc_lbTasker = new GridBagConstraints();
        gbc_lbTasker.insets = new Insets(0, 0, 0, 5);
        gbc_lbTasker.fill = 0;
        gbc_lbTasker.gridx = 2;
        gbc_lbTasker.gridy = 0;
        FilterPanel.add(lbTasker, gbc_lbTasker);

        lbTaskerCount = new JLabel("0");
        lbTaskerCount.setForeground(new Color(0, 255, 0));
        GridBagConstraints gbc_lbTaskerCount = new GridBagConstraints();
        gbc_lbTaskerCount.insets = new Insets(0, 0, 0, 5);
        gbc_lbTaskerCount.fill = 0;
        gbc_lbTaskerCount.gridx = 3;
        gbc_lbTaskerCount.gridy = 0;
        FilterPanel.add(lbTaskerCount, gbc_lbTaskerCount);

        // 分析URL的数量
        JLabel lbAnalysisEnd = new JLabel("Analysis End:");
        GridBagConstraints gbc_lbAnalysisEnd = new GridBagConstraints();
        gbc_lbAnalysisEnd.insets = new Insets(0, 0, 0, 5);
        gbc_lbAnalysisEnd.fill = 0;
        gbc_lbAnalysisEnd.gridx = 4;
        gbc_lbAnalysisEnd.gridy = 0;
        FilterPanel.add(lbAnalysisEnd, gbc_lbAnalysisEnd);

        lbAnalysisEndCount = new JLabel("0");
        lbAnalysisEndCount.setForeground(new Color(0, 0, 255)); // 蓝色
        GridBagConstraints gbc_lbAnalysisEndCount = new GridBagConstraints();
        gbc_lbAnalysisEndCount.insets = new Insets(0, 0, 0, 5);
        gbc_lbAnalysisEndCount.fill = 0;
        gbc_lbAnalysisEndCount.gridx = 5;
        gbc_lbAnalysisEndCount.gridy = 0;
        FilterPanel.add(lbAnalysisEndCount, gbc_lbAnalysisEndCount);

        // 添加填充以在左侧占位
        Component horizontalBlank = Box.createHorizontalGlue(); //创建一个水平组件
        GridBagConstraints gbc_leftFiller = new GridBagConstraints();
        gbc_leftFiller.weightx = 1; // 使得这个组件吸收额外的水平空间
        gbc_leftFiller.gridx = 6; // 位置设置为第一个单元格
        gbc_leftFiller.gridy = 0; // 第一行
        gbc_leftFiller.fill = GridBagConstraints.HORIZONTAL; // 水平填充
        FilterPanel.add(horizontalBlank, gbc_leftFiller);

        // 刷新按钮按钮
        JToggleButton clickRefreshButton = new JToggleButton(UiUtils.getImageIcon("/icon/refreshButton2.png", 24, 24));
        clickRefreshButton.setPreferredSize(new Dimension(30, 30));
        clickRefreshButton.setBorder(null);  // 设置无边框
        clickRefreshButton.setFocusPainted(false);  // 移除焦点边框
        clickRefreshButton.setContentAreaFilled(false);  // 移除选中状态下的背景填充
        clickRefreshButton.setToolTipText("点击强制刷新表格");

        // 手动刷新按钮监听事件
        clickRefreshButton.addActionListener(new ActionListener() {
            private boolean canClick = true;

            @Override
            public void actionPerformed(ActionEvent e) {
                if (canClick) {
                    canClick = false;
                    ImageIcon originalIcon = (ImageIcon) clickRefreshButton.getIcon();  // 保存原始图标
                    String originalTip = clickRefreshButton.getToolTipText();   // 保存原始批注

                    // 更换为新图标
                    clickRefreshButton.setIcon(UiUtils.getImageIcon("/icon/runningButton.png", 24, 24)); // 立即显示新图标

                    //关键的代码
                    MainPanel.getInstance().refreshAllUnVisitedUrlsAndTableUI(false, true);

                    // 设置定时器，5秒后允许再次点击并恢复图标
                    Timer timer = new Timer(3000, new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent ae) {
                            canClick = true;
                            clickRefreshButton.setIcon(originalIcon); // 恢复原始图标
                            clickRefreshButton.setToolTipText(originalTip); // 恢复原始批注
                        }
                    });
                    timer.setRepeats(false);
                    timer.start();
                }
            }
        });

        // 开关 是否开启自动记录PATH
        JToggleButton autoRecordPathButton; //自动保存响应状态码合适的URL 目前过滤功能不完善,只能手动开启
        autoRecordPathButton = new JToggleButton(UiUtils.getImageIcon("/icon/openButtonIcon.png", 40, 24));
        autoRecordPathButton.setSelectedIcon(UiUtils.getImageIcon("/icon/shutdownButtonIcon.png", 40, 24));
        autoRecordPathButton.setPreferredSize(new Dimension(50, 24));
        autoRecordPathButton.setBorder(null);  // 设置无边框
        autoRecordPathButton.setFocusPainted(false);  // 移除焦点边框
        autoRecordPathButton.setContentAreaFilled(false);  // 移除选中状态下的背景填充
        autoRecordPathButton.setToolTipText("自动保存有效请求PATH");

        autoRecordPathButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //默认开启本功能, 点击后应该作为不开启配置
                IProxyScanner.autoRecordPathIsOpen = !autoRecordPathButton.isSelected();
                stdout_println(LOG_DEBUG, String.format("dynamicPthFilterIsOpen: %s", IProxyScanner.autoRecordPathIsOpen));
            }
        });

        // 开关 是否开启自动记录PATH
        JToggleButton dynamicPthFilterButton = new JToggleButton(UiUtils.getImageIcon("/icon/openButtonIcon.png", 40, 24));
        dynamicPthFilterButton.setSelectedIcon(UiUtils.getImageIcon("/icon/shutdownButtonIcon.png", 40, 24));
        dynamicPthFilterButton.setPreferredSize(new Dimension(50, 24));
        dynamicPthFilterButton.setBorder(null);  // 设置无边框
        dynamicPthFilterButton.setFocusPainted(false);  // 移除焦点边框
        dynamicPthFilterButton.setContentAreaFilled(false);  // 移除选中状态下的背景填充
        dynamicPthFilterButton.setToolTipText("开启动态PATH过滤要求");


        dynamicPthFilterButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //默认开启本功能, 点击后应该作为不开启配置
                IProxyScanner.dynamicPthFilterIsOpen = !dynamicPthFilterButton.isSelected();
                stdout_println(LOG_DEBUG, String.format("dynamicPthFilterIsOpen: %s", IProxyScanner.dynamicPthFilterIsOpen));
            }
        });

        JToggleButton autoPathsToUrlsButton = new JToggleButton(UiUtils.getImageIcon("/icon/shutdownButtonIcon.png", 40, 24));
        autoPathsToUrlsButton.setSelectedIcon(UiUtils.getImageIcon("/icon/openButtonIcon.png", 40, 24));
        autoPathsToUrlsButton.setPreferredSize(new Dimension(50, 24));
        autoPathsToUrlsButton.setBorder(null);  // 设置无边框
        autoPathsToUrlsButton.setFocusPainted(false);  // 移除焦点边框
        autoPathsToUrlsButton.setContentAreaFilled(false);  // 移除选中状态下的背景填充
        autoPathsToUrlsButton.setToolTipText("自动基于PathTree结合FindPath生成URL");

        autoPathsToUrlsButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //默认关闭本功能, 点击后应该作为开启配置
                IProxyScanner.autoPathsToUrlsIsOpen = autoPathsToUrlsButton.isSelected();
                stdout_println(LOG_DEBUG, String.format("autoPathsToUrlsIsOpen: %s", IProxyScanner.autoPathsToUrlsIsOpen));
            }
        });

        // 开关 是否开启自动刷新未访问URL
        JToggleButton autoRefreshUnvisitedButton = new JToggleButton(UiUtils.getImageIcon("/icon/shutdownButtonIcon.png", 40, 24));
        autoRefreshUnvisitedButton.setSelectedIcon(UiUtils.getImageIcon("/icon/openButtonIcon.png", 40, 24));
        autoRefreshUnvisitedButton.setPreferredSize(new Dimension(50, 24));
        autoRefreshUnvisitedButton.setBorder(null);  // 设置无边框
        autoRefreshUnvisitedButton.setFocusPainted(false);  // 移除焦点边框
        autoRefreshUnvisitedButton.setContentAreaFilled(false);  // 移除选中状态下的背景填充
        autoRefreshUnvisitedButton.setToolTipText("自动刷新未访问URL");

        autoRefreshUnvisitedButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //默认关闭本功能, 点击后应该作为开启配置
                MainPanel.autoRefreshUnvisitedIsOpen = autoRefreshUnvisitedButton.isSelected();
                stdout_println(LOG_DEBUG, String.format("auroRefreshUnvisitedIsOpen: %s", MainPanel.autoRefreshUnvisitedIsOpen));
            }
        });

        // 开关 是否开启对提取URL进行发起请求
        JToggleButton autoRecursiveButton = new JToggleButton(UiUtils.getImageIcon("/icon/shutdownButtonIcon.png", 40, 24));
        autoRecursiveButton.setSelectedIcon(UiUtils.getImageIcon("/icon/openButtonIcon.png", 40, 24));
        autoRecursiveButton.setPreferredSize(new Dimension(50, 24));
        autoRecursiveButton.setBorder(null);  // 设置无边框
        autoRecursiveButton.setFocusPainted(false);  // 移除焦点边框
        autoRecursiveButton.setContentAreaFilled(false);  // 移除选中状态下的背景填充
        autoRecursiveButton.setToolTipText("自动测试未访问URL");

        autoRecursiveButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //默认关闭本功能, 点击后应该作为开启配置
                IProxyScanner.autoRecursiveIsOpen = autoRecursiveButton.isSelected();
                stdout_println(LOG_DEBUG, String.format("autoRecursiveIsOpen: %s", IProxyScanner.autoRecursiveIsOpen));
            }
        });


        // 刷新按钮按钮
        autoRefreshButton = new JToggleButton(UiUtils.getImageIcon("/icon/refreshButton.png", 24, 24));
        autoRefreshButton.setSelectedIcon(UiUtils.getImageIcon("/icon/runningButton.png", 24, 24));
        autoRefreshButton.setPreferredSize(new Dimension(30, 30));
        autoRefreshButton.setBorder(null);  // 设置无边框
        autoRefreshButton.setFocusPainted(false);  // 移除焦点边框
        autoRefreshButton.setContentAreaFilled(false);  // 移除选中状态下的背景填充
        autoRefreshButton.setToolTipText("用于控制表格是否自动化刷新，还是手工点击刷新");

        // 刷新文本
        autoRefreshText = new JLabel(String.format("暂停每%s秒刷新表格", timerDelay));

        // 设置按钮的 GridBagConstraints
        GridBagConstraints gbc_buttons = new GridBagConstraints();
        gbc_buttons.insets = new Insets(0, 5, 0, 5);
        gbc_buttons.gridy = 0; // 设置按钮的纵坐标位置
        gbc_buttons.fill = GridBagConstraints.NONE; // 不填充

        // 点击按钮 点击后刷新数据 含未访问数据
        gbc_buttons.gridx = 7; // 设置按钮的横坐标位置
        FilterPanel.add(clickRefreshButton, gbc_buttons);

        // 自动记录有效的PATH到path表中 功能开关
        gbc_buttons.gridx = 8; // 设置按钮的横坐标位置
        FilterPanel.add(autoRecordPathButton, gbc_buttons);

        // 高级动态有效路径过滤 功能开关
        gbc_buttons.gridx = 9;
        FilterPanel.add(dynamicPthFilterButton, gbc_buttons);

        // 高级动态有效路径过滤 功能开关
        gbc_buttons.gridx = 10;
        FilterPanel.add(autoPathsToUrlsButton, gbc_buttons);


        // 自动刷新 未访问URL列表
        gbc_buttons.gridx = 11; // 设置按钮的横坐标位置
        FilterPanel.add(autoRefreshUnvisitedButton, gbc_buttons);

        // 自动递归 开关
        gbc_buttons.gridx = 12; // 设置按钮的横坐标位置
        FilterPanel.add(autoRecursiveButton, gbc_buttons);

        // 定时刷新按钮
        gbc_buttons.gridx = 13; // 将横坐标位置移动到下一个单元格
        FilterPanel.add(autoRefreshButton, gbc_buttons);
        // 定时刷新按钮旁边的描述
        gbc_buttons.gridx = 14; // 将横坐标位置移动到下一个单元格
        FilterPanel.add(autoRefreshText, gbc_buttons);

        // 添加填充以在右侧占位
        GridBagConstraints gbc_rightFiller = new GridBagConstraints();
        gbc_rightFiller.weightx = 1; // 使得这个组件吸收额外的水平空间
        gbc_rightFiller.gridx = 15; // 位置设置为最后一个单元格
        gbc_rightFiller.gridy = 0; // 第一行
        gbc_rightFiller.fill = GridBagConstraints.HORIZONTAL; // 水平填充
        FilterPanel.add(horizontalBlank, gbc_rightFiller);

        // 全部按钮
        choicesComboBox = new JComboBox<>(new String[]{
                "显示有效内容",
                "显示敏感内容",
                "显示未访问路径",
                "显示全部内容",
                "显示无效内容",
        });
        GridBagConstraints gbc_btnall = new GridBagConstraints();
        gbc_btnall.insets = new Insets(0, 0, 0, 5);
        gbc_btnall.fill = 0;
        gbc_btnall.gridx = 16;  // 根据该值来确定是确定从左到右的顺序
        gbc_btnall.gridy = 0;
        FilterPanel.add(choicesComboBox, gbc_btnall);
        // 检索框
        urlSearchBox = new JTextField(15);
        GridBagConstraints gbc_btnSearchField = new GridBagConstraints();
        gbc_btnSearchField.insets = new Insets(0, 0, 0, 5);
        gbc_btnSearchField.fill = 0;
        gbc_btnSearchField.gridx = 17;  // 根据该值来确定是确定从左到右的顺序
        gbc_btnSearchField.gridy = 0;
        urlSearchBox.setToolTipText("搜索URL关键字");
        FilterPanel.add(urlSearchBox, gbc_btnSearchField);
        // 检索按钮
        JButton searchButton = new JButton();
        searchButton.setIcon(UiUtils.getImageIcon("/icon/searchButton.png"));
        searchButton.setToolTipText("点击搜索");
        GridBagConstraints gbc_btnSearch = new GridBagConstraints();
        gbc_btnSearch.insets = new Insets(0, 0, 0, 5);
        gbc_btnSearch.fill = 0;
        gbc_btnSearch.gridx = 18;  // 根据该值来确定是确定从左到右的顺序
        gbc_btnSearch.gridy = 0;
        FilterPanel.add(searchButton, gbc_btnSearch);

        // 功能按钮
        JButton moreButton = new JButton();
        moreButton.setToolTipText("更多功能 ");
        moreButton.setIcon(UiUtils.getImageIcon("/icon/moreButton.png", 17, 17));
        GridBagConstraints gbc_btnMore = new GridBagConstraints();
        gbc_btnMore.insets = new Insets(0, 0, 0, 5);
        gbc_btnMore.fill = 0;
        gbc_btnMore.gridx = 19;  // 根据该值来确定是确定从左到右的顺序
        gbc_btnMore.gridy = 0;
        FilterPanel.add(moreButton, gbc_btnMore);

        // 功能按钮 弹出选项
        JPopupMenu moreMenu = createMoreMenuWithAction();

        // 自动刷新按钮监听事件
        autoRefreshButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 检查按钮的选中状态
                if (autoRefreshButton.isSelected()) {
                    MainPanel.autoRefreshIsOpen = autoRefreshButton.isSelected();
                    autoRefreshText.setText(String.format("自动每%s秒刷新表格", timerDelay));
                } else {
                    MainPanel.autoRefreshIsOpen = !autoRefreshButton.isSelected();
                    autoRefreshText.setText(String.format("暂停每%s秒刷新表格", timerDelay));
                }
            }
        });

        // 快速选择框的监听事件
        choicesComboBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try{
                    // 触发显示所有行事件
                    String searchText = urlSearchBox.getText();
                    if(searchText.isEmpty()){
                        searchText = "";
                    }
                    String selectedOption = (String)choicesComboBox.getSelectedItem();
                    MainPanel.showDataTableByFilter(selectedOption, searchText);
                } catch (Exception ex) {
                    stderr_println(String.format("[!] choicesComboBox: %s", ex.getMessage()));
                }
            }
        });

        // 检索按钮事件监听器
        searchButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String searchText = urlSearchBox.getText();
                String selectedOption = (String)ConfigPanel.choicesComboBox.getSelectedItem();
                MainPanel.showDataTableByFilter(selectedOption, searchText);
                setAutoRefreshClose();
            }
        });

        //搜索框的回车事件
        urlSearchBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String searchText = urlSearchBox.getText();
                String selectedOption = (String)ConfigPanel.choicesComboBox.getSelectedItem();
                MainPanel.showDataTableByFilter(selectedOption, searchText);
                setAutoRefreshClose();
            }
        });

        // 点击”功能“的监听事件
        moreButton.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                moreMenu.show(e.getComponent(), e.getX(), e.getY());
            }
        });
 }

    //创建功能按钮内容和对应事件
    private JPopupMenu createMoreMenuWithAction() {
        JPopupMenu moreMenu = new JPopupMenu("功能");

        JMenuItem addRootUrlToAllowListen = new JMenuItem("添加到RootUrl白名单");
        addRootUrlToAllowListen.setIcon(UiUtils.getImageIcon("/icon/addButtonIcon.png"));
        moreMenu.add(addRootUrlToAllowListen);

        JMenuItem addRootUrlToBlackUrlRoot = new JMenuItem("添加到RootUrl黑名单");
        addRootUrlToBlackUrlRoot.setIcon(UiUtils.getImageIcon("/icon/addButtonIcon.png"));
        moreMenu.add(addRootUrlToBlackUrlRoot);

        JMenuItem addUrlToRecordPath = new JMenuItem("添加有效PATH到PathTree");
        addUrlToRecordPath.setIcon(UiUtils.getImageIcon("/icon/addButtonIcon.png"));
        moreMenu.add(addUrlToRecordPath);

        JMenuItem addUrlToRecordUrl = new JMenuItem("添加已访问URL到访问记录");
        addUrlToRecordUrl.setIcon(UiUtils.getImageIcon("/icon/addButtonIcon.png"));
        moreMenu.add(addUrlToRecordUrl);

        JMenuItem loadSitemapToRecordPath = new JMenuItem("加载SiteMap到Path记录");
        loadSitemapToRecordPath.setIcon(UiUtils.getImageIcon("/icon/importItem.png"));
        moreMenu.add(loadSitemapToRecordPath);

        JMenuItem loadSitemapToRecordUrl = new JMenuItem("加载SiteMap到Url记录");
        loadSitemapToRecordUrl.setIcon(UiUtils.getImageIcon("/icon/importItem.png"));
        moreMenu.add(loadSitemapToRecordUrl);

        JMenuItem clearUselessData = new JMenuItem("清除无用数据");
        clearUselessData.setIcon(UiUtils.getImageIcon("/icon/deleteButton.png"));
        moreMenu.add(clearUselessData);

        JMenuItem clearModelTableData = new JMenuItem("清除表格数据表");
        clearModelTableData.setIcon(UiUtils.getImageIcon("/icon/deleteButton.png"));
        moreMenu.add(clearModelTableData);

        JMenuItem clearRecordTableData = new JMenuItem("清除记录数据表");
        clearRecordTableData.setIcon(UiUtils.getImageIcon("/icon/deleteButton.png"));
        moreMenu.add(clearRecordTableData);

        JMenuItem clearRecordUrlTableData = new JMenuItem("清除访问记录表");
        clearRecordUrlTableData.setIcon(UiUtils.getImageIcon("/icon/deleteButton.png"));
        moreMenu.add(clearRecordUrlTableData);


        JMenuItem clearAllTableData = new JMenuItem("清空所有数据表");
        clearAllTableData.setIcon(UiUtils.getImageIcon("/icon/deleteButton.png"));
        moreMenu.add(clearAllTableData);


        // 为 功能 菜单项 清除无用数据 添加 Action Listener
        clearUselessData.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 清空表格模型中的无效数据
                UnionTableSql.clearUselessData();
                setAutoRefreshOpen();
            }
        });

        // 为 功能 菜单项 清除数据表数据 添加 Action Listener
        clearModelTableData.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 清空表格模型中的所有行数据
                MainPanel.clearModelData(false);
                setAutoRefreshOpen();
            }
        });

        // 为 功能 菜单项 清除所有表数据 添加 Action Listener
        clearAllTableData.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 清空表格模型中的所有行数据
                MainPanel.clearModelData(true);
                setAutoRefreshOpen();
            }
        });

        // 清除记录URL PATH TREE 数据
        clearRecordTableData.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                DBService.clearRecordTables();
                setAutoRefreshOpen();
            }
        });

        // 清除记录URL数据
        clearRecordUrlTableData.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                DBService.clearRecordUrlTable();
                setAutoRefreshOpen();
            }
        });


        // 为 功能 菜单项 加载站点地图到PATH记录 添加 Action Listener
        loadSitemapToRecordPath.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new SwingWorker<Void, Void>() {
                    @Override
                    protected Void doInBackground() throws Exception {
                        BurpSitemapUtils.addSiteMapUrlsToRecord(false);
                        stdout_println(LOG_DEBUG, "Add SiteMap Urls To Record Path Table End.");
                        return null;
                    }
                }.execute();
            }
        });

        // 为 功能 菜单项 加载站点地图到URL记录 添加 Action Listener
        loadSitemapToRecordUrl.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new SwingWorker<Void, Void>() {
                    @Override
                    protected Void doInBackground() throws Exception {
                        BurpSitemapUtils.addSiteMapUrlsToRecord(true);
                        stdout_println(LOG_DEBUG, "Add SiteMap Urls To Record Url Table End.");
                        return null;
                    }
                }.execute();
            }
        });

        // 为 功能 菜单项 输入有效URL列表到数据框 从而加入到PATH
        addUrlToRecordPath.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                creatTextDialogForAddRecord("添加有效PATH至PATH记录", "addUrlToRecordPath");
            }
        });

        // 为 功能 菜单项 输入URL列表到数据框 从而加入到 URL记录
        addUrlToRecordUrl.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                creatTextDialogForAddRecord("添加URL至已访问URL记录", "addUrlToRecordUrl");
            }
        });

        // 为 功能 菜单项 输入有效URL列表到数据框 从而加入到PATH
        addRootUrlToAllowListen.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                creatTextDialogForAddRecord("添加到RootUrl白名单", "addRootUrlToAllowListen");
            }
        });

        // 为 功能 菜单项 输入有效URL列表到数据框 从而加入到PATH
        addRootUrlToBlackUrlRoot.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                creatTextDialogForAddRecord("添加到RootUrl黑名单", "addRootUrlToBlackUrlRoot");
            }
        });
        return moreMenu;
    }

    /**
     * 创建加入URL和PATh表的对话框函数
     * @param title
     * @param RecordType 分支类型
     */
    private void creatTextDialogForAddRecord(String title, String RecordType) {
        //创建一个对话框,便于输入url数据
        JDialog dialog = new JDialog();
        dialog.setTitle(title);
        dialog.setLayout(new GridBagLayout()); // 使用GridBagLayout布局管理器

        GridBagConstraints constraints = new GridBagConstraints();
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.insets = new Insets(10, 10, 10, 10); // 设置组件之间的间距
        // 添加第一行提示
        JLabel urlJLabel = new JLabel("输入数据:");
        constraints.gridx = 0; // 第1列
        constraints.gridy = 0; // 第1行
        constraints.gridwidth = 2; // 占据两列的空间
        dialog.add(urlJLabel, constraints);

        JTextArea customParentPathArea = new JTextArea(5, 20);
        customParentPathArea.setText("");
        customParentPathArea.setLineWrap(true); // 自动换行
        customParentPathArea.setWrapStyleWord(true); //断行不断字
        constraints.gridy = 1; // 第2行
        constraints.gridx = 0; // 第1列
        dialog.add(new JScrollPane(customParentPathArea), constraints); // 添加滚动条

        // 添加按钮面板
        JPanel buttonPanel = new JPanel();
        JButton confirmButton = new JButton("确认");
        JButton cancelButton = new JButton("取消");
        buttonPanel.add(confirmButton);
        buttonPanel.add(cancelButton);

        constraints.gridx = 0; // 第一列
        constraints.gridy = 2; // 第三行
        constraints.gridwidth = 2; // 占据两列的空间
        dialog.add(buttonPanel, constraints);

        dialog.pack(); // 调整对话框大小以适应其子组件
        dialog.setLocationRelativeTo(null); // 居中显示
        dialog.setVisible(true); // 显示对话框

        // 取消按钮事件
        cancelButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                dialog.dispose(); // 关闭对话框
            }
        });

        // 不同的 确认按钮动作
        confirmButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 获取用户输入
                String inputText = customParentPathArea.getText();
                dialog.dispose(); // 关闭对话框
                //调用新的动作
                java.util.List<String> urlList = CastUtils.getUniqueLines(inputText);
                if (!urlList.isEmpty()){
                    // 使用SwingWorker来处理数据更新，避免阻塞EDT
                    new SwingWorker<Void, Void>() {
                        @Override
                        protected Void doInBackground() throws Exception {
                            switch (RecordType){
                                case "addUrlToRecordUrl":
                                    RecordUrlTable.batchInsertOrUpdateAccessedUrls(urlList, 299);
                                    break;
                                case "addUrlToRecordPath":
                                    RecordPathTable.batchInsertOrUpdateRecordPath(urlList, 299);
                                    break;
                                case "addRootUrlToAllowListen":
                                    BurpExtender.CONF_WHITE_URL_ROOT = CastUtils.addRootUrlToList(urlList, BurpExtender.CONF_WHITE_URL_ROOT);
                                    FingerConfigTab.saveConfigToDefaultJson();
                                    break;
                                case "addRootUrlToBlackUrlRoot":
                                    //1、修改配置文件
                                    BurpExtender.CONF_BLACK_URL_ROOT = CastUtils.addRootUrlToList(urlList, BurpExtender.CONF_BLACK_URL_ROOT);
                                    FingerConfigTab.saveConfigToDefaultJson();
                                    //2、删除 Root URL 对应的 结果数据
                                    java.util.List<String> rootUrlList = CastUtils.getRootUrlList(urlList);
                                    int count1 = UnionTableSql.batchDeleteDataByRootUrlList(rootUrlList, ReqDataTable.tableName);
                                    int count2 = UnionTableSql.batchDeleteDataByRootUrlList(rootUrlList, AnalyseResultTable.tableName);
                                    stdout_println(LOG_DEBUG, String.format("deleteReqDataCount：%s , deleteAnalyseResultCount:%s", count1, count2));
                                    //3、刷新表格
                                    MainPanel.getInstance().refreshTableModel(false);
                                    break;
                            }
                            return null;
                        }
                    }.execute();
                }
            }
        });
    }

    //设置打开自动刷新
    public static void setAutoRefreshOpen(){
        autoRefreshButton.setSelected(true);
        autoRefreshText.setText(String.format("自动每%s秒刷新表格", timerDelay));
    }

    //设置关闭自动刷新
    public static void setAutoRefreshClose(){
        autoRefreshButton.setSelected(false);
        autoRefreshText.setText(String.format("暂停每%s秒刷新表格", timerDelay));
        MainPanel.operationStartTime = LocalDateTime.now();
    }

    public static String getUrlSearchBoxText() {
        return urlSearchBox.getText();
    }

    public static void setUrlSearchBoxText(String string) {
        urlSearchBox.setText(string);
    }


    public static String getComboBoxSelectedOption() {
        return (String) ConfigPanel.choicesComboBox.getSelectedItem();
    }
}
