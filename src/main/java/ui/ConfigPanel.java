package ui;

import database.UnionTableSql;
import utils.BurpSitemapUtils;
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

    // public static JLabel jsCrawledCount;
    public static JComboBox<String> choicesComboBox;

    public static JToggleButton autoRefreshButton;
    public static JLabel autoRefreshText;

    public static JTextField searchField;

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
        gbl_panel_1.columnWeights = new double[] { 0.0D, 0.0D, 0.0D, 0.0D, 0.0D, 0.0D, 0.0D, 0.0D, 0.0D, Double.MIN_VALUE};
        //第一行权重为0.0，不随容器扩展，第二行的权重为Double.MIN_VALUE，表示该行也不扩展。
        gbl_panel_1.rowWeights = new double[] { 0.0D, Double.MIN_VALUE };
        FilterPanel.setLayout(gbl_panel_1);

        // 在添加 "Requests Total" 和 lbRequestCount 之前添加一个占位组件
        Component leftStrut = Box.createHorizontalStrut(5); // 你可以根据需要调整这个值
        GridBagConstraints gbc_leftStrut = new GridBagConstraints();
        gbc_leftStrut.insets = new Insets(0, 0, 0, 5);
        gbc_leftStrut.fill = GridBagConstraints.HORIZONTAL;
        gbc_leftStrut.weightx = 1.0; // 这个值决定了 leftStrut 占据的空间大小
        gbc_leftStrut.gridx = 8;
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


//        // 爬取JS的数量
//        JLabel jsCrawled = new JLabel("Crawled JS:");
//        GridBagConstraints gbc_jsCrawled = new GridBagConstraints();
//        gbc_jsCrawled.insets = new Insets(0, 0, 0, 5);
//        gbc_jsCrawled.fill = 0;
//        gbc_jsCrawled.gridx = 6;
//        gbc_jsCrawled.gridy = 0;
//        FilterPanel.add(jsCrawled, gbc_jsCrawled);
//
//        jsCrawledCount = new JLabel("0/0");
//        jsCrawledCount.setForeground(new Color(0, 0, 255)); // 蓝色
//        GridBagConstraints gbc_jsCrawledCount = new GridBagConstraints();
//        gbc_jsCrawledCount.insets = new Insets(0, 0, 0, 5);
//        gbc_jsCrawledCount.fill = 0;
//        gbc_jsCrawledCount.gridx = 7;
//        gbc_jsCrawledCount.gridy = 0;
//        FilterPanel.add(jsCrawledCount, gbc_jsCrawledCount);

        // 添加填充以在左侧占位
        Component horizontalBlank = Box.createHorizontalGlue(); //创建一个水平组件
        GridBagConstraints gbc_leftFiller = new GridBagConstraints();
        gbc_leftFiller.weightx = 1; // 使得这个组件吸收额外的水平空间
        gbc_leftFiller.gridx = 8; // 位置设置为第一个单元格
        gbc_leftFiller.gridy = 0; // 第一行
        gbc_leftFiller.fill = GridBagConstraints.HORIZONTAL; // 水平填充
        FilterPanel.add(horizontalBlank, gbc_leftFiller);

        // 刷新按钮按钮
        JToggleButton refreshButton = new JToggleButton(UiUtils.getImageIcon("/icon/refreshButton2.png", 24, 24));
        refreshButton.setPreferredSize(new Dimension(30, 30));
        refreshButton.setBorder(null);  // 设置无边框
        refreshButton.setFocusPainted(false);  // 移除焦点边框
        refreshButton.setContentAreaFilled(false);  // 移除选中状态下的背景填充
        refreshButton.setToolTipText("点击刷新表格");

        // 开关 是否开启对提取URL进行发起请求
        JToggleButton toggleButton = new JToggleButton(UiUtils.getImageIcon("/icon/openButtonIcon.png", 40, 24));
        toggleButton.setSelectedIcon(UiUtils.getImageIcon("/icon/shutdownButtonIcon.png", 40, 24));
        toggleButton.setPreferredSize(new Dimension(50, 24));
        toggleButton.setBorder(null);  // 设置无边框
        toggleButton.setFocusPainted(false);  // 移除焦点边框
        toggleButton.setContentAreaFilled(false);  // 移除选中状态下的背景填充
        toggleButton.setToolTipText("是否开启对提取URL进行发起请求");

        // 刷新按钮按钮
        autoRefreshButton = new JToggleButton(UiUtils.getImageIcon("/icon/runningButton.png", 24, 24));
        autoRefreshButton.setSelectedIcon(UiUtils.getImageIcon("/icon/refreshButton.png", 24, 24));
        autoRefreshButton.setPreferredSize(new Dimension(30, 30));
        autoRefreshButton.setBorder(null);  // 设置无边框
        autoRefreshButton.setFocusPainted(false);  // 移除焦点边框
        autoRefreshButton.setContentAreaFilled(false);  // 移除选中状态下的背景填充
        autoRefreshButton.setToolTipText("用于控制表格是否自动化刷新，还是手工点击刷新");

        // 刷新文本
        autoRefreshText = new JLabel("自动每10秒刷新表格中");

        // 设置按钮的 GridBagConstraints
        GridBagConstraints gbc_buttons = new GridBagConstraints();
        gbc_buttons.insets = new Insets(0, 5, 0, 5);
        gbc_buttons.gridy = 0; // 设置按钮的纵坐标位置
        gbc_buttons.fill = GridBagConstraints.NONE; // 不填充

        // 在 FilterPanel 中添加 refreshButton
        gbc_buttons.gridx = 9; // 设置按钮的横坐标位置
        FilterPanel.add(refreshButton, gbc_buttons);
        // 在 FilterPanel 中添加 toggleButton
        gbc_buttons.gridx = 10; // 设置按钮的横坐标位置
        FilterPanel.add(toggleButton, gbc_buttons);
        gbc_buttons.gridx = 11; // 将横坐标位置移动到下一个单元格
        FilterPanel.add(autoRefreshButton, gbc_buttons);
        gbc_buttons.gridx = 12; // 将横坐标位置移动到下一个单元格
        FilterPanel.add(autoRefreshText, gbc_buttons);

        // 添加填充以在右侧占位
        GridBagConstraints gbc_rightFiller = new GridBagConstraints();
        gbc_rightFiller.weightx = 1; // 使得这个组件吸收额外的水平空间
        gbc_rightFiller.gridx = 13; // 位置设置为最后一个单元格
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
        gbc_btnall.gridx = 15;  // 根据该值来确定是确定从左到右的顺序
        gbc_btnall.gridy = 0;
        FilterPanel.add(choicesComboBox, gbc_btnall);
        // 检索框
        searchField = new JTextField(15);
        GridBagConstraints gbc_btnSearchField = new GridBagConstraints();
        gbc_btnSearchField.insets = new Insets(0, 0, 0, 5);
        gbc_btnSearchField.fill = 0;
        gbc_btnSearchField.gridx = 16;  // 根据该值来确定是确定从左到右的顺序
        gbc_btnSearchField.gridy = 0;
        searchField.setToolTipText("搜索URL关键字");
        FilterPanel.add(searchField, gbc_btnSearchField);
        // 检索按钮
        JButton searchButton = new JButton();
        searchButton.setIcon(UiUtils.getImageIcon("/icon/searchButton.png"));
        searchButton.setToolTipText("点击搜索");
        GridBagConstraints gbc_btnSearch = new GridBagConstraints();
        gbc_btnSearch.insets = new Insets(0, 0, 0, 5);
        gbc_btnSearch.fill = 0;
        gbc_btnSearch.gridx = 17;  // 根据该值来确定是确定从左到右的顺序
        gbc_btnSearch.gridy = 0;
        FilterPanel.add(searchButton, gbc_btnSearch);

        // 功能按钮
        JButton moreButton = new JButton();
        moreButton.setToolTipText("更多功能 ");
        moreButton.setIcon(UiUtils.getImageIcon("/icon/moreButton.png", 17, 17));
        GridBagConstraints gbc_btnMore = new GridBagConstraints();
        gbc_btnMore.insets = new Insets(0, 0, 0, 5);
        gbc_btnMore.fill = 0;
        gbc_btnMore.gridx = 18;  // 根据该值来确定是确定从左到右的顺序
        gbc_btnMore.gridy = 0;
        FilterPanel.add(moreButton, gbc_btnMore);

        // 功能按钮 弹出选项
        JPopupMenu moreMenu = new JPopupMenu("功能");

        JMenuItem loadSitemapToRecordPath = new JMenuItem("加载SiteMap到Path记录");
        loadSitemapToRecordPath.setIcon(UiUtils.getImageIcon("/icon/importItem.png"));
        moreMenu.add(loadSitemapToRecordPath);

        JMenuItem loadSitemapToRecordUrl = new JMenuItem("加载SiteMap到Url记录");
        loadSitemapToRecordUrl.setIcon(UiUtils.getImageIcon("/icon/importItem.png"));
        moreMenu.add(loadSitemapToRecordUrl);

        JMenuItem clearUselessData = new JMenuItem("清除无用数据");
        clearUselessData.setIcon(UiUtils.getImageIcon("/icon/deleteButton.png"));
        moreMenu.add(clearUselessData);

        JMenuItem clearModelTableData = new JMenuItem("清除表格数据");
        clearModelTableData.setIcon(UiUtils.getImageIcon("/icon/deleteButton.png"));
        moreMenu.add(clearModelTableData);

        JMenuItem clearAllTableData = new JMenuItem("清除所有数据");
        clearAllTableData.setIcon(UiUtils.getImageIcon("/icon/deleteButton.png"));
        moreMenu.add(clearAllTableData);

        // 自动刷新按钮监听事件
        autoRefreshButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 检查按钮的选中状态
                if (autoRefreshButton.isSelected()) {
                    // 如果按钮被选中，意味着刷新功能被激活，我们将文本设置为 "暂停刷新中"
                    autoRefreshText.setText(String.format("暂停每%s秒刷新表格", timerDelay));
                } else {
                    // 如果按钮没有被选中，意味着刷新功能没有被激活，我们将文本设置为 "自动刷新"
                    autoRefreshText.setText(String.format("自动每%s秒刷新表格", timerDelay));
                }
            }
        });

        // 手动刷新按钮监听事件
        refreshButton.addActionListener(new ActionListener() {
            private boolean canClick = true;

            @Override
            public void actionPerformed(ActionEvent e) {
                if (canClick) {
                    canClick = false;
                    ImageIcon originalIcon = (ImageIcon) refreshButton.getIcon();  // 保存原始图标
                    String originalTip = refreshButton.getToolTipText();   // 保存原始批注

                    // 更换为新图标
                    refreshButton.setIcon(UiUtils.getImageIcon("/icon/runningButton.png", 24, 24)); // 立即显示新图标

                    //关键的代码
                    MainPanel.getInstance().refreshUnVisitedUrlsAndTableModel(false, true);

                    // 设置定时器，5秒后允许再次点击并恢复图标
                    Timer timer = new Timer(3000, new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent ae) {
                            canClick = true;
                            refreshButton.setIcon(originalIcon); // 恢复原始图标
                            refreshButton.setToolTipText(originalTip); // 恢复原始批注
                        }
                    });
                    timer.setRepeats(false);
                    timer.start();
                }
            }
        });

        // 快速选择框的监听事件
        choicesComboBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try{
                    // 触发显示所有行事件
                    String searchText = searchField.getText();
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
                String searchText = searchField.getText();
                String selectedOption = (String)ConfigPanel.choicesComboBox.getSelectedItem();
                MainPanel.showDataTableByFilter(selectedOption, searchText);
                setAutoRefreshButtonFalse();
            }
        });

        //搜索框的回车事件
        searchField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String searchText = searchField.getText();
                String selectedOption = (String)ConfigPanel.choicesComboBox.getSelectedItem();
                MainPanel.showDataTableByFilter(selectedOption, searchText);
                setAutoRefreshButtonFalse();
            }
        });

        // 点击”功能“的监听事件
        moreButton.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                moreMenu.show(e.getComponent(), e.getX(), e.getY());
            }
        });

        // 为 功能 菜单项 清除无用数据 添加 Action Listener
        clearUselessData.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 清空表格模型中的无效数据
                UnionTableSql.clearUselessData();
                setAutoRefreshButtonTrue();
            }
        });

        // 为 功能 菜单项 清除数据表数据 添加 Action Listener
        clearModelTableData.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 清空表格模型中的所有行数据
                MainPanel.clearModelData(false);
                setAutoRefreshButtonTrue();
            }
        });

        // 为 功能 菜单项 清除所有表数据 添加 Action Listener
        clearAllTableData.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 清空表格模型中的所有行数据
                MainPanel.clearModelData(true);
                setAutoRefreshButtonTrue();
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

 }

    public static void setAutoRefreshButtonTrue(){
        autoRefreshButton.setSelected(false);
        autoRefreshText.setText(String.format("自动每%s秒刷新表格", timerDelay));
    }

    public static void setAutoRefreshButtonFalse(){
        autoRefreshButton.setSelected(true);
        autoRefreshText.setText(String.format("暂停每%s秒刷新表格", timerDelay));
        MainPanel.operationStartTime = LocalDateTime.now();
    }

    public static boolean getAutoRefreshButtonStatus(){
        // 检查按钮的选中状态
        // 如果按钮被选中，意味着刷新功能被激活，我们将文本设置为 "暂停刷新中"
        // 如果按钮没有被选中，意味着刷新功能没有被激活，我们将文本设置为 "自动刷新"
        return autoRefreshButton.isSelected();
    }
}
