package ui;

import burp.*;
import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;
import database.*;
import model.*;
import ui.MainTabRender.TableHeaderWithTips;
import ui.MainTabRender.importantCellRenderer;
import utils.CastUtils;
import utils.PathTreeUtils;
import utils.UiUtils;

import javax.swing.Timer;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.*;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.*;
import java.util.concurrent.ExecutionException;

import static utils.BurpPrintUtils.*;
import static utils.CastUtils.isEmptyObj;
import static utils.CastUtils.isNotEmptyObj;

public class BasicHostInfoPanel extends JPanel {
    private static volatile BasicHostInfoPanel instance; //实现单例模式

    private static JTable basicHostMsgTableUI; //表格UI
    private static DefaultTableModel basicHostMsgTableModel; // 存储表格数据

    private static JEditorPane basicHostFindInfoTextPane;  //敏感信息文本面板
    private static ITextEditor basicHostRespFindUrlTEditor; //显示找到的URL
    private static ITextEditor basicHostRespFindPathTEditor; //显示找到的PATH
    private static ITextEditor basicHostDirectPath2UrlTEditor; //基于PATH计算出的URL
    private static ITextEditor basicHostSmartPath2UrlTEditor; //基于树算法计算出的URL
    private static ITextEditor basicHostUnvisitedUrlTEditor; //未访问过的URL

    private static ITextEditor basicHostPathTreeTEditor; //当前目标的路径树信息

    public static Timer basicHostTimer;  //定时器 为线程调度提供了一个简单的时间触发机制，广泛应用于需要定时执行某些操作的场景，
    public static LocalDateTime basicHostOperationStartTime = LocalDateTime.now(); //操作开始时间

    public static boolean basicHostAutoRefreshIsOpen = false;

    public static BasicHostInfoPanel getInstance() {
        if (instance == null) {
            synchronized (BasicHostInfoPanel.class) {
                if (instance == null) {
                    instance = new BasicHostInfoPanel();
                }
            }
        }
        return instance;
    }

    public BasicHostInfoPanel() {
        // EmptyBorder 四周各有了5像素的空白边距
        setBorder(new EmptyBorder(5, 5, 5, 5));
        ////BorderLayout 将容器分为五个区域：北 南 东 西 中 每个区域可以放置一个组件，
        setLayout(new BorderLayout(0, 0));

        // 主分隔面板
        // JSplitPane可以包含两个（或更多）子组件，允许用户通过拖动分隔条来改变两个子组件的相对大小。
        JSplitPane basicHostMainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        // 首行配置面板
        BasicHostConfigPanel basicHostConfigPanel = new BasicHostConfigPanel();

        // 数据表格
        initBasicHostDataTableUI();

        //将包含table的滚动面板的upScrollPane 设置为另一个组件mainSplitPane的上半部分。
        basicHostMainSplitPane.setTopComponent(new JScrollPane(basicHostMsgTableUI));

        //获取下方的消息面板
        JTabbedPane basicHostMsgTabs = getBasicHostMsgTabs();
        basicHostMainSplitPane.setBottomComponent(basicHostMsgTabs);

        //组合最终的内容面板
        add(basicHostConfigPanel, BorderLayout.NORTH);
        add(basicHostMainSplitPane, BorderLayout.CENTER);

        //初始化表格数据
        initBasicHostDataTableUIData(basicHostMsgTableModel);

        // 初始化定时刷新页面函数 单位是毫秒
        initBasicHostTimer(BasicHostConfigPanel.timerDelayOnHost * 1000);
    }


    /**
     * 查询 TableLineDataModelBasicHostSQL 初始化 table 数据
     */
    private void initBasicHostDataTableUIData(DefaultTableModel tableModel) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                //获取所有数据 查询 HOST信息表
                ArrayList<BasicHostTableLineDataModel> allReqAnalyseData  = TableLineDataModelBasicHostSQL.fetchHostTableLineDataAll();
                //将数据赋值给表模型
                basicHostPopulateModelFromList(tableModel, allReqAnalyseData);
            }
        });
    }

    /**
     * 把 jsonArray 赋值到 model 中
     * @param model
     * @param arrayList
     */
    private void basicHostPopulateModelFromList(DefaultTableModel model, ArrayList<BasicHostTableLineDataModel> arrayList) {
        if (isEmptyObj(arrayList)) return;

        Iterator<BasicHostTableLineDataModel> iterator = arrayList.iterator();
        while (iterator.hasNext()) {
            BasicHostTableLineDataModel apiDataModel = iterator.next();
            Object[] rowData = apiDataModel.toRowDataArray();
            model.addRow(rowData);
        }
        //刷新表数据模型
        model.fireTableDataChanged();
    }

    /**
     * 初始化Table
     */
    private void initBasicHostDataTableUI() {
        // 数据展示面板
        basicHostMsgTableModel = new DefaultTableModel(new Object[]{
                "id",
                "root_url",
                "important",
                "find_info",
                "find_url",
                "find_path",
                "find_api",
                "path_url",
                "unvisited",
                "basic_num",
                "run_status"
        }, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                //在数据模型层面禁止编辑行数据
                return false;
            }
        };

        basicHostMsgTableUI = UiUtils.creatTableUiWithTips(basicHostMsgTableModel);

        // 设置列选中模式
        int listSelectionModel = ListSelectionModel.MULTIPLE_INTERVAL_SELECTION;
        basicHostMsgTableUI.setSelectionMode(listSelectionModel);

        //自己实现TableHeader 支持请求头提示
        String[] basicHostColHeaderTooltips = new String[]{
                "请求ID",
                "请求目标",
                "是否存在匹配重要规则",
                "当前响应中匹配的【敏感信息】数量",
                "当前响应中提取的【直接URL】数量",
                "当前响应中提取的【网站PATH】数量",
                "当前请求目录 直接组合 已提取PATH =【拼接URL】数量（已过滤）",
                "网站有效目录 智能组合 已提取PATH =【动态URL】数量（已过滤|只能计算带目录的PATH|跟随网站有效目录新增而变动）",
                "当前直接URL数量+拼接URL数量+动态URL数量-全局已访问URL=【当前未访问URL】数量 ",
                "当前【动态URL数量计算基准】（表明动态URL基于多少个网站路径计算|跟随网站有效目录新增而变动）",
                "当前【请求上下文分析状态】(不为 Waiting 表示已提取[敏感信息|URL信息|PATH信息])"
        };

        TableHeaderWithTips basicHostTableHeader = new TableHeaderWithTips(basicHostMsgTableUI.getColumnModel(), basicHostColHeaderTooltips);
        basicHostMsgTableUI.setTableHeader(basicHostTableHeader);

        //添加表头排序功能
        UiUtils.tableAddActionSortByHeader(basicHostMsgTableUI, basicHostMsgTableModel);

        //设置数据表的宽度
        UiUtils.tableSetColumnMaxWidth(basicHostMsgTableUI, 0, 50);
        UiUtils.tableSetColumnMinWidth(basicHostMsgTableUI, 1, 200);

        //设置表格每列的对齐设置
        List<Integer> leftColumns = Arrays.asList(1);
        UiUtils.tableSetColumnsAlignRender(basicHostMsgTableUI, leftColumns);

        //为重要信息列添加额外的渲染
        importantCellRenderer havingImportantRenderer = new importantCellRenderer();
        basicHostMsgTableUI.getColumnModel().getColumn(2).setCellRenderer(havingImportantRenderer);

        //为表格添加点击显示下方的消息动作
        basicHostTableAddActionSetMsgTabData();

        //为表的每一行添加右键菜单
        basicHostTableAddRightClickMenu(basicHostMsgTableUI, listSelectionModel);
    }


    /**
     * 初始化任务定时器 定时刷新UI内容
     * @param delay
     */
    private void initBasicHostTimer(int delay) {
        // 创建一个每10秒触发一次的定时器
        //int delay = 10000; // 延迟时间，单位为毫秒
        basicHostTimer = new Timer(delay, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (IProxyScanner.executorService == null || IProxyScanner.executorService.getActiveCount() < 3) {
                    //stdout_println(LOG_DEBUG, String.format(String.format("[*] 当前进程数量[%s]", IProxyScanner.executorService.getActiveCount())) );
                    // 调用更新未访问URL列的数据
                    try{
                        //当添加进程还比较多的时候,暂时不进行响应数据处理
                        updateUnVisitedUrlsByRootUrls(null);
                    } catch (Exception ep){
                        stderr_println(LOG_ERROR, String.format("[!] 更新未访问URL发生错误：%s", ep.getMessage()) );
                    }

                    // 调用刷新表格的方法
                    try{
                        BasicHostInfoPanel.getInstance().refreshBasicHostTableModel(false);
                    } catch (Exception ep){
                        stderr_println(LOG_ERROR, String.format("[!] 刷新表格发生错误：%s", ep.getMessage()) );
                    }

                    //建议JVM清理内存
                    System.gc();
                }
            }
        });

        // 启动定时器
        basicHostTimer.start();
    }

    /**
     * 初始化创建表格下方的消息内容面板
     */
    private JTabbedPane getBasicHostMsgTabs() {
        IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();

        // 将 结果消息面板 添加到窗口下方
        JTabbedPane tabs = new JTabbedPane();

        //敏感信息结果面板 使用 "text/html" 可用于 html 渲染颜色
        basicHostFindInfoTextPane = new JEditorPane("text/html", "");
        JScrollPane basicHostFindInfoTextScrollPane = new JScrollPane(basicHostFindInfoTextPane);
        basicHostFindInfoTextScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);

        // 提取到URL的面板
        basicHostRespFindUrlTEditor = callbacks.createTextEditor();
        basicHostRespFindPathTEditor = callbacks.createTextEditor();
        basicHostDirectPath2UrlTEditor = callbacks.createTextEditor();
        basicHostSmartPath2UrlTEditor = callbacks.createTextEditor();
        basicHostUnvisitedUrlTEditor = callbacks.createTextEditor();
        basicHostPathTreeTEditor = callbacks.createTextEditor();

        tabs.addTab("RespFindInfo",null, basicHostFindInfoTextScrollPane, "基于当前响应体提取的敏感信息"); //显示提取的信息
        tabs.addTab("RespFindUrl",null, basicHostRespFindUrlTEditor.getComponent(), "基于当前响应体提取的URL"); //显示在这个URL中找到的PATH
        tabs.addTab("RespFindPath",null, basicHostRespFindPathTEditor.getComponent(), "基于当前响应体提取的PATH"); //显示在这个URL中找到的PATH
        tabs.addTab("DirectPath2Url",null, basicHostDirectPath2UrlTEditor.getComponent(), "基于当前请求URL目录 拼接 提取的PATH"); //显示在这个URL中找到的PATH
        tabs.addTab("SmartPath2Url",null, basicHostSmartPath2UrlTEditor.getComponent(), "基于当前网站有效目录 和 提取的PATH 动态计算出的URL"); //显示在这个URL中找到的PATH
        tabs.addTab("UnvisitedUrl",null, basicHostUnvisitedUrlTEditor.getComponent(), "当前URL所有提取URL 减去 已经访问过的URL"); //显示在这个URL中找到的Path 且还没有访问过的URL
        tabs.addTab("PathTreeInfo",null, basicHostPathTreeTEditor.getComponent(), "当前目前的路径树信息");
        return tabs;
    }

    /**
     * 清空当前Msg tabs中显示的数据
     */
    private static void clearBasicHostMsgTabsShowData() {
        basicHostFindInfoTextPane.setText("");
        basicHostRespFindUrlTEditor.setText(new byte[0]);
        basicHostRespFindPathTEditor.setText(new byte[0]);
        basicHostDirectPath2UrlTEditor.setText(new byte[0]);
        basicHostSmartPath2UrlTEditor.setText(new byte[0]);
        basicHostUnvisitedUrlTEditor.setText(new byte[0]);
        basicHostPathTreeTEditor.setText(new byte[0]);
    }

    /**
     * 鼠标点击或键盘移动到行时,自动更新下方的msgTab
     */
    private void basicHostTableAddActionSetMsgTabData() {
        //为表格 添加 鼠标监听器
        //获取点击事件发生时鼠标所在行的索引 根据选中行的索引来更新其他组件的状态或内容。
        basicHostMsgTableUI.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                // 只有在双击时才执行
                //if (e.getClickCount() == 2) {
                SwingUtilities.invokeLater(new Runnable() {
                    public void run() {
                        try {
                            int row = basicHostMsgTableUI.rowAtPoint(e.getPoint());
                            if (row >= 0) {
                                updateComponentsBasedOnSelectedRow(row);
                            }
                        }catch (Exception ef) {
                            BurpExtender.getStderr().println("[-] Error click table: " + basicHostMsgTableUI.rowAtPoint(e.getPoint()));
                            ef.printStackTrace(BurpExtender.getStderr());
                        }
                    }
                });
            }
        });

        //为表格 添加 键盘按键释放事件监听器
        //获取按键事件发生时鼠标所在行的索引 根据选中行的索引来更新其他组件的状态或内容。
        basicHostMsgTableUI.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                //关注向上 和向下 的按键事件
                if (e.getKeyCode() == KeyEvent.VK_UP || e.getKeyCode() == KeyEvent.VK_DOWN) {
                    SwingUtilities.invokeLater(new Runnable() {
                        public void run() {
                            try {
                                int row = basicHostMsgTableUI.getSelectedRow();
                                if (row >= 0) {
                                    updateComponentsBasedOnSelectedRow(row);
                                }
                            }catch (Exception ef) {
                                BurpExtender.getStderr().println("[-] Error KeyEvent.VK_UP OR  KeyEvent.VK_DOWN: ");
                                ef.printStackTrace(BurpExtender.getStderr());
                            }
                        }
                    });
                }
            }
        });
    }

    /**
     * 更新表格行对应的下方数据信息
     * @param row
     */
    private void updateComponentsBasedOnSelectedRow(int row) {
        //清理下方数据内容
        clearBasicHostMsgTabsShowData();

        //1、获取当前行的 rootUrl
        String rootUrl = null;
        try {
            //实现排序后 视图行 数据的正确获取
            rootUrl = UiUtils.getStringAtActualRow(basicHostMsgTableUI, row, 1);
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[!] Table get Value At Row [%s] Error:%s", row, e.getMessage()));
        }

        if (CastUtils.isEmptyObj(rootUrl)) return;

        //查询路径树信息 并美化输出
        PathTreeModel pathTreeModel = PathTreeTable.fetchPathTreeByRootUrl(rootUrl);
        if (pathTreeModel!=null){
            JSONObject pathTree = pathTreeModel.getPathTree();
            String prettyJson = JSON.toJSONString(pathTree, JSONWriter.Feature.PrettyFormat);
            basicHostPathTreeTEditor.setText(prettyJson.getBytes());
        }

        //查询详细数据
        BasicHostTableTabDataModel tabDataModel = AnalyseHostResultTable.fetchHostResultByRootUrl(rootUrl);
        if (tabDataModel != null) {
            //格式化为可输出的类型
            String findInfo = CastUtils.infoJsonArrayFormatHtml(tabDataModel.getFindInfo());
            String findUrl = CastUtils.stringJsonArrayFormat(tabDataModel.getFindUrl());
            String findPath = CastUtils.stringJsonArrayFormat(tabDataModel.getFindPath());
            String findApi = CastUtils.stringJsonArrayFormat(tabDataModel.getFindApi());
            String pathToUrl = CastUtils.stringJsonArrayFormat(tabDataModel.getPathToUrl());
            String unvisitedUrl = CastUtils.stringJsonArrayFormat(tabDataModel.getUnvisitedUrl());

            basicHostFindInfoTextPane.setText(findInfo);
            basicHostRespFindUrlTEditor.setText(findUrl.getBytes());
            basicHostRespFindPathTEditor.setText(findPath.getBytes());
            basicHostDirectPath2UrlTEditor.setText(findApi.getBytes());
            basicHostSmartPath2UrlTEditor.setText(pathToUrl.getBytes());
            basicHostUnvisitedUrlTEditor.setText(unvisitedUrl.getBytes());
        }
    }

    /**
     * 定时刷新表数据
     */
    public void refreshBasicHostTableModel(boolean checkAutoRefreshButtonStatus) {
        //当已经卸载插件时,不要再进行刷新UI
        if (!BurpExtender.EXTENSION_IS_LOADED)
            return;

        //设置已加入数据库的数量
        BasicHostConfigPanel.lbTaskerCountOnHost.setText(String.valueOf(CommonSql.getTableCounts(ReqDataTable.tableName)));
        //设置成功分析的数量
        BasicHostConfigPanel.lbAnalysisEndCountOnHost.setText(String.valueOf(ReqDataTable.getReqDataCountWhereStatusIsEnd()));

        // 刷新页面, 如果自动更新关闭，则不刷新页面内容
        if (checkAutoRefreshButtonStatus && basicHostAutoRefreshIsOpen) {
            if (Duration.between(basicHostOperationStartTime, LocalDateTime.now()).getSeconds() > 600) {
                BasicHostConfigPanel.setAutoRefreshOpenOnHost();
            }
            return;
        }

        // 获取搜索框和搜索选项
        final String searchText = BasicHostConfigPanel.getUrlSearchBoxTextOnHost();
        final String selectedOption = BasicHostConfigPanel.getComboBoxSelectedOptionOnHost();

        // 使用SwingWorker来处理数据更新，避免阻塞EDT
        SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                try {
                    // 执行耗时的数据操作
                    BasicHostInfoPanel.showDataHostTableByFilter(selectedOption, searchText.isEmpty() ? "" : searchText);
                } catch (Exception e) {
                    // 处理数据操作中可能出现的异常
                    System.err.println("Error while updating data: " + e.getMessage());
                    e.printStackTrace();
                }
                return null;
            }

            @Override
            protected void done() {
                // 更新UI组件
                try {
                    // 更新UI组件
                    SwingUtilities.invokeLater(() -> {
                        try {
                            basicHostMsgTableModel.fireTableDataChanged(); // 通知模型数据发生了变化
                        } catch (Exception e) {
                            // 处理更新UI组件时可能出现的异常
                            System.err.println("Error while updating UI: " + e.getMessage());
                            e.printStackTrace();
                        }
                    });
                } catch (Exception e) {
                    // 处理在done()方法中可能出现的异常，例如InterruptedException或ExecutionException
                    System.err.println("Error in done method: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        };
        worker.execute();
    }

    /**
     * 基于过滤选项 和 搜索框内容 显示结果
     * @param selectOption
     * @param searchText
     */
    public static void showDataHostTableByFilter(String selectOption, String searchText) {
        // 在后台线程获取数据，避免冻结UI
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                // 构建一个新的表格模型
                basicHostMsgTableModel.setRowCount(0);

                // 获取数据库中的所有ApiDataModels
                ArrayList<BasicHostTableLineDataModel> apiDataModels;

                switch (selectOption) {
                    case "显示有效内容":
                        apiDataModels = TableLineDataModelBasicHostSQL.fetchHostTableLineDataHasData();
                        break;
                    case "显示敏感内容":
                        apiDataModels = TableLineDataModelBasicHostSQL.fetchHostTableLineDataHasInfo();
                        break;
                    case "显示未访问路径":
                        apiDataModels = TableLineDataModelBasicHostSQL.fetchHostTableLineDataHasUnVisitedUrls();
                        break;
                    case "显示无效内容":
                        apiDataModels = TableLineDataModelBasicHostSQL.fetchHostTableLineDataIsNull();
                        break;
                    case "显示全部内容":
                    default:
                        apiDataModels = TableLineDataModelBasicHostSQL.fetchHostTableLineDataAll();
                        break;
                }

                // 遍历apiDataModelMap
                for (BasicHostTableLineDataModel apiDataModel : apiDataModels) {
                    String url = apiDataModel.getRootUrl();
                    //是否包含关键字,当输入了关键字时,使用本函数再次进行过滤
                    if (url.toLowerCase().contains(searchText.toLowerCase())) {
                        Object[] rowData = apiDataModel.toRowDataArray();
                        //model.insertRow(0, rowData); //插入到首行
                        basicHostMsgTableModel.insertRow(basicHostMsgTableModel.getRowCount(), rowData); //插入到最后一行
                    }
                }
                return null;
            }

            @Override
            protected void done() {
                try {
                    get();
                } catch (InterruptedException | ExecutionException e) {
                    stderr_println(String.format("[!] showFilter error: %s", e.getMessage()));
                    //e.printStackTrace(BurpExtender.getStderr());
                }
            }
        }.execute();
    }

    /**
     * 查询所有 UnVisitedUrls 并逐个进行过滤
     * @param rootUrls  rootUrls目标列表, 为空 为Null时更新全部
     */
    public void updateUnVisitedUrlsByRootUrls(List<String> rootUrls) {
        // 使用SwingWorker来处理数据更新，避免阻塞EDT
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                // 获取所有未访问URl 注意需要大于0
                List<UnVisitedUrlsModel> unVisitedUrlsModels;
                if (rootUrls == null || rootUrls.isEmpty()) {
                    //更新所有的结果
                    unVisitedUrlsModels = AnalyseHostUnVisitedUrls.fetchAllUnVisitedUrlsWithLimit(99);
                }else {
                    //仅更新指定 msgHash 对应的未访问URL
                    unVisitedUrlsModels = AnalyseHostUnVisitedUrls.fetchUnVisitedUrlsByRootUrls(rootUrls);
                }

                if (unVisitedUrlsModels.size() > 0) {
                    // 获取所有 已经被访问过得URL列表
                    //List<String> accessedUrls = RecordUrlTable.fetchAllAccessedUrls();
                    //获取所有由reqHash组成的字符串
                    String accessedUrlHashes = CommonSql.fetchColumnGroupConcatString(RecordUrlTable.tableName, RecordUrlTable.urlHashName);
                    // 遍历 unVisitedUrlsModels 进行更新
                    for (UnVisitedUrlsModel urlsModel : unVisitedUrlsModels) {
                        //更新 unVisitedUrls 对象
                        List<String> rawUnVisitedUrls = urlsModel.getUnvisitedUrls();
                        //List<String> newUnVisitedUrls = CastUtils.listReduceList(rawUnVisitedUrls, accessedUrls);

                        List<String> newUnVisitedUrls = new ArrayList<>();
                        for (String url : rawUnVisitedUrls) {
                            String urlHash = CastUtils.calcCRC32(url);
                            if (!accessedUrlHashes.contains(urlHash)) {
                                newUnVisitedUrls.add(url);
                            }
                        }

                        //过滤黑名单中的URL 因为黑名单是不定时更新的
                        newUnVisitedUrls = AnalyseInfo.filterFindUrls(urlsModel.getRootUrl(), newUnVisitedUrls, BurpExtender.onlyScopeDomain);
                        urlsModel.setUnvisitedUrls(newUnVisitedUrls);

                        // 执行更新插入数据操作
                        try {
                            AnalyseHostUnVisitedUrls.updateUnVisitedUrlsById(urlsModel);
                        } catch (Exception ex) {
                            stderr_println(String.format("[!] Updating unvisited URL Error:%s", ex.getMessage()));
                        }
                    }
                }
                return null;
            }
        }.execute();
    }

    private List<Integer> getIdsAtActualRows(JTable tableUI, int[] selectedRows) {
        return UiUtils.getIdsAtActualRows(tableUI, selectedRows, 0);
    }

    private List<String> getRootUrlsAtActualRows(JTable tableUI, int[] selectedRows) {
        return UiUtils.getStringListAtActualRows(tableUI, selectedRows, 1);
    }


    /**
     * 为 table 设置每一列的 右键菜单
     */
    private void basicHostTableAddRightClickMenu(JTable tableUI, int selectModel) {
        // 创建右键菜单
        JPopupMenu popupMenu = new JPopupMenu();

        JMenuItem copyUrlItem = new JMenuItem("复制RootURL", UiUtils.getImageIcon("/icon/copyIcon.png", 15, 15));
        // 添加 copyUrlItem 事件监听器
        copyUrlItem.setToolTipText("[多行]复制选定行对应的RootURL到剪贴板");
        copyUrlItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行模式下的调用
                if (selectModel >= 0){
                    int[] selectedRows = tableUI.getSelectedRows();
                    List<String> rootUrls = getRootUrlsAtActualRows(tableUI, selectedRows);
                    if (!rootUrls.isEmpty())
                        UiUtils.copyToSystemClipboard(String.join("\n", rootUrls));
                }
            }
        });

        JMenuItem deleteItem = new JMenuItem("删除数据行", UiUtils.getImageIcon("/icon/deleteButton.png", 15, 15));
        // 添加 deleteItem 事件监听器
        deleteItem.setToolTipText("[多行]删除选定行对应的聚合结果表数据");
        deleteItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (selectModel >= 0){
                    int[] selectedRows = tableUI.getSelectedRows();
                    List<Integer> ids = getIdsAtActualRows(tableUI, selectedRows);
                    // 使用SwingWorker来处理数据更新，避免阻塞EDT
                    new SwingWorker<Void, Void>() {
                        @Override
                        protected Void doInBackground() throws Exception {
                            CommonDeleteLine.deleteLineByIds(ids, AnalyseHostResultTable.tableName);
                            refreshBasicHostTableModel(false);
                            return null;
                        }
                    }.execute();
                }
            }
        });

        JMenuItem ClearUnVisitedItem = new JMenuItem("清空当前未访问URL", UiUtils.getImageIcon("/icon/deleteButton.png", 15, 15));
        // 添加 ClearUnVisitedItem 事件监听器
        ClearUnVisitedItem.setToolTipText("[多行]清空选定行对应的未访问URL");
        ClearUnVisitedItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (selectModel >= 0){
                    int[] selectedRows = tableUI.getSelectedRows();
                    List<String> rootUrls = getRootUrlsAtActualRows(tableUI, selectedRows);
                    if (!rootUrls.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                AnalyseHostUnVisitedUrls.clearUnVisitedUrlsByRootUrls(rootUrls);
                                refreshBasicHostTableModel(false);
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        JMenuItem IgnoreUnVisitedItem = new JMenuItem("忽略当前未访问URL", UiUtils.getImageIcon("/icon/editButton.png", 15, 15));
        // 添加 IgnoreUnVisitedItem 事件监听器
        IgnoreUnVisitedItem.setToolTipText("[多行]标记选定行对应的未访问URL为已访问 并清空 当访问URL后依然无法过滤时使用");
        IgnoreUnVisitedItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (selectModel >= 0){
                    int[] selectedRows = tableUI.getSelectedRows();
                    List<String> rootUrls = getRootUrlsAtActualRows(tableUI, selectedRows);
                    if (!rootUrls.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                //获取所有msgHash相关的结果
                                List<UnVisitedUrlsModel> unVisitedUrlsModels = AnalyseHostUnVisitedUrls.fetchUnVisitedUrlsByRootUrls(rootUrls);

                                //整合所有结果URL到一个Set
                                Set<String> unvisitedUrlsSet = new HashSet<>();
                                for (UnVisitedUrlsModel unVisitedUrlsModel:unVisitedUrlsModels){
                                    List<String> unvisitedUrls = unVisitedUrlsModel.getUnvisitedUrls();
                                    unvisitedUrlsSet.addAll(unvisitedUrls);
                                }

                                //批量插入所有URL
                                RecordUrlTable.batchInsertOrUpdateAccessedUrls(new ArrayList<>(unvisitedUrlsSet), 299);
                                //批量删除所有msgHashList
                                AnalyseHostUnVisitedUrls.clearUnVisitedUrlsByRootUrls(rootUrls);
                                refreshBasicHostTableModel(false);
                                return null;
                            }
                        }.execute();

                    }
                }
            }
        });

        JMenuItem updateUnVisitedItem = new JMenuItem("刷新当前未访问URL", UiUtils.getImageIcon("/icon/refreshButton2.png", 15, 15));
        // 添加 updateUnVisitedItem 事件监听器
        updateUnVisitedItem.setToolTipText("[多行]更新选定行对应的未访问URL情况");
        updateUnVisitedItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (selectModel >= 0) {
                    int[] selectedRows = tableUI.getSelectedRows();
                    List<String> rootUrls = getRootUrlsAtActualRows(tableUI, selectedRows);
                    if (!rootUrls.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                updateUnVisitedUrlsByRootUrls(rootUrls);
                                refreshBasicHostTableModel(false);
                                return null;
                            }
                        }.execute();

                    }
                }
            }
        });

        JMenuItem accessUnVisitedItem = new JMenuItem("访问当前未访问URL", UiUtils.getImageIcon("/icon/urlIcon.png", 15, 15));
        // 添加 accessUnVisitedItem 事件监听器

        accessUnVisitedItem.setToolTipText("[多行]访问选定行对应的当前所有未访问URL");
        accessUnVisitedItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (selectModel >= 0) {
                    int[] selectedRows = tableUI.getSelectedRows();
                    List<String> rootUrls = getRootUrlsAtActualRows(tableUI, selectedRows);
                    if (!rootUrls.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                //获取所有msgHash相关的结果
                                List<UnVisitedUrlsModel> unVisitedUrlsModels = AnalyseHostUnVisitedUrls.fetchUnVisitedUrlsByRootUrls(rootUrls);
                                //批量访问所有URL模型
                                for (UnVisitedUrlsModel unVisitedUrlsModel: unVisitedUrlsModels){
                                    IProxyScanner.accessUnVisitedUrlsModel(unVisitedUrlsModel, false);
                                }
                                //更新 检查 rootUrls 对应的 未访问URl情况
                                updateUnVisitedUrlsByRootUrls(rootUrls);
                                refreshBasicHostTableModel(false);
                                return null;
                            }
                        }.execute();

                    }
                }
            }
        });

        JMenuItem removeHostFromPathTreeItem = new JMenuItem("清空HOST对应PathTree", UiUtils.getImageIcon("/icon/customizeIcon.png", 15, 15));
        // 添加 removeHostFromPathTreeItem 事件监听器
        removeHostFromPathTreeItem.setToolTipText("[多行]清空选定行对应的HOST在PathTree及RecordPath中的数据");
        removeHostFromPathTreeItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (selectModel>=0) {
                    int[] selectedRows = tableUI.getSelectedRows();
                    List<String> rootUrls = getRootUrlsAtActualRows(tableUI, selectedRows);
                    if (!rootUrls.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                CommonDeleteLine.deleteLineByRootUrls(PathTreeTable.tableName, rootUrls);
                                CommonDeleteLine.deleteLineByRootUrls(RecordPathTable.tableName, rootUrls);
                                refreshBasicHostTableModel(false);
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });


        JMenuItem addRootUrlToBlackUrlRootItem = new JMenuItem("添加到RootUrl黑名单", UiUtils.getImageIcon("/icon/noFindUrlFromJS.png", 15, 15));
        // 添加 addRootUrlToBlackUrlRootItem 事件监听器
        addRootUrlToBlackUrlRootItem.setToolTipText("[多行]添加选定行对应的RootUrl到禁止扫描黑名单 CONF_BLACK_URL_ROOT");
        addRootUrlToBlackUrlRootItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (selectModel>=0) {
                    int[] selectedRows = tableUI.getSelectedRows();
                    List<String> rootUrls = getRootUrlsAtActualRows(tableUI, selectedRows);
                    if (!rootUrls.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                // 合并 rootUrls 到 BurpExtender.CONF_BLACK_URL_ROOT 保持唯一性
                                BurpExtender.CONF_BLACK_URL_ROOT =CastUtils.listAddList(rootUrls, BurpExtender.CONF_BLACK_URL_ROOT);

                                //保存Json
                                RuleConfigPanel.saveConfigToDefaultJson();

                                //2、删除 Root URL 对应的 结果数据
                                int countReq = CommonDeleteLine.deleteLineByUrlLikeRootUrls(ReqDataTable.tableName, rootUrls);
                                int countUrl = CommonDeleteLine.deleteLineByRootUrls(AnalyseUrlResultTable.tableName, rootUrls);
                                int countHost = CommonDeleteLine.deleteLineByRootUrls(AnalyseHostResultTable.tableName, rootUrls);
                                stdout_println(LOG_DEBUG, String.format("delete ReqData Count：%s , delete Analyse Host Result Count:%s, delete Analyse Url Result Count:%s", countReq, countHost, countUrl));

                                //3、刷新表格
                                refreshBasicHostTableModel(false);
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        JMenuItem addRootUrlToNotAutoRecurseItem = new JMenuItem("添加到禁止自动递归目标", UiUtils.getImageIcon("/icon/noFindUrlFromJS.png", 15, 15));
        // 添加 addRootUrlToNotAutoRecurseItem 事件监听器
        addRootUrlToNotAutoRecurseItem.setToolTipText("[多行]添加选定行对应的RootUrl加入到禁止自动递归列表 CONF_BLACK_AUTO_RECURSE_SCAN");
        addRootUrlToNotAutoRecurseItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (selectModel>=0) {
                    int[] selectedRows = tableUI.getSelectedRows();
                    List<String> rootUrls = getRootUrlsAtActualRows(tableUI, selectedRows);
                    if (!rootUrls.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                BurpExtender.CONF_BLACK_AUTO_RECURSE_SCAN = CastUtils.listAddList(rootUrls, BurpExtender.CONF_BLACK_AUTO_RECURSE_SCAN);

                                RuleConfigPanel.saveConfigToDefaultJson();
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        JMenuItem addRootUrlToAllowListenItem = new JMenuItem("添加到允许监听白名单", UiUtils.getImageIcon("/icon/findUrlFromJS.png", 15, 15));
        // 添加 addRootUrlToAllowListenItem 事件监听器
        addRootUrlToAllowListenItem.setToolTipText("[多行]添加选定行对应的RootUrl到仅监听的白名单 CONF_WHITE_URL_ROOT");
        addRootUrlToAllowListenItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (selectModel>=0) {
                    int[] selectedRows = tableUI.getSelectedRows();
                    List<String> rootUrls =  getRootUrlsAtActualRows(tableUI, selectedRows);
                    if (!rootUrls.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                BurpExtender.CONF_WHITE_URL_ROOT = CastUtils.listAddList(rootUrls, BurpExtender.CONF_WHITE_URL_ROOT);
                                //保存Json
                                RuleConfigPanel.saveConfigToDefaultJson();
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        JMenuItem pathTreeToPathListItem = new JMenuItem("提取当前HOST的所有PATH", UiUtils.getImageIcon("/icon/copyIcon.png", 15, 15));
        //pathTreeToPathListItem
        pathTreeToPathListItem.setToolTipText("[多行]复制选定行对应的RootUrl在PathTree中的路径数据到剪贴板 并弹框");
        pathTreeToPathListItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (selectModel>=0) {
                    int[] selectedRows = tableUI.getSelectedRows();
                    List<String> rootUrls = getRootUrlsAtActualRows(tableUI,selectedRows);
                    if (!rootUrls.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                Set<String> pathSet = new LinkedHashSet<>();

                                for (String rootUrl:rootUrls){
                                    //查询 rootUrl 对应的树
                                    PathTreeModel pathTreeModel = PathTreeTable.fetchPathTreeByRootUrl(rootUrl);
                                    if (isNotEmptyObj(pathTreeModel)){
                                        JSONObject currPathTree = pathTreeModel.getPathTree();
                                        if (isNotEmptyObj(currPathTree)  && isNotEmptyObj(currPathTree.getJSONObject("ROOT"))){
                                            List<String> pathList = PathTreeUtils.covertTreeToPaths(currPathTree);
                                            for (String path:pathList){
                                                pathSet.add(path.replace("ROOT", rootUrl) + "/");
                                            }
                                        }
                                    }
                                }
                                //直接复制到用户的粘贴板
                                UiUtils.copyToSystemClipboard(String.join("\n", pathSet));
                                //弹框让用户查看
                                UiUtils.showOneMsgBoxToCopy(String.join("\n",pathSet), "所有路径信息");
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });


        //提取当前API结果的单层节点 单层节点没有办法通过PATH树计算,必须手动拼接测试
        JMenuItem copySingleLayerNodeItem = new JMenuItem("提取当前PATH结果中的单层节点", UiUtils.getImageIcon("/icon/copyIcon.png", 15, 15));
        //copySingleLayerNodeItem
        copySingleLayerNodeItem.setToolTipText("[多行]复制选定行对应的提取PATH中的单层(无目录)路径到剪贴板 并弹框");
        copySingleLayerNodeItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (selectModel >= 0) {
                    int[] selectedRows = tableUI.getSelectedRows();
                    List<String> rootUrls = getRootUrlsAtActualRows(tableUI, selectedRows);
                    if (!rootUrls.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                List<FindPathModel> findPathModelList = AnalyseHostResultTable.fetchPathDataByRootUrl(rootUrls);
                                Set<String> pathSet = FindPathModel.getSingleLayerPathSet(findPathModelList);
                                //直接复制到用户的粘贴板
                                UiUtils.copyToSystemClipboard(String.join("\n", pathSet));
                                //弹框让用户查看
                                UiUtils.showOneMsgBoxToCopy(String.join("\n",pathSet), "单层路径信息");
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });


        JMenuItem calcSingleLayerNodeItemOnHost = new JMenuItem("输入URL前缀生成单层节点对应URL", UiUtils.getImageIcon("/icon/copyIcon.png", 15, 15));
        //calcSingleLayerNodeItem
        calcSingleLayerNodeItemOnHost.setToolTipText("[多行]基于选定行对应的提取PATH中的单层(无目录)PATH和用户输入的URL前缀计算新的URL");
        calcSingleLayerNodeItemOnHost.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (selectModel >= 0) {
                    int[] selectedRows = tableUI.getSelectedRows();
                    List<String> rootUrls = getRootUrlsAtActualRows(tableUI, selectedRows);
                    if (!rootUrls.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                UiUtils.showInputBoxAndHandle(rootUrls, "calcSingleLayerNodeItemOnHost", "指定PATH生成单层节点URL");
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });


//        JMenuItem removeFindApiIListItem = new JMenuItem("清空当前PATH拼接URL的结果内容", UiUtils.getImageIcon("/icon/deleteButton.png", 15, 15));
//        //removeFindApiIListItem
//        removeFindApiIListItem.setToolTipText("[多行]移除选定行对应的PATH拼接URL内容 前后端分离时使用");
//        removeFindApiIListItem.addActionListener(new ActionListener() {
//            @Override
//            public void actionPerformed(ActionEvent e) {
//                //多行选定模式
//                if (selectModel >= 0) {
//                    int[] selectedRows = tableUI.getSelectedRows();
//                    List<String> rootUrls = getRootUrlsAtActualRows(tableUI, selectedRows);
//                    if (!rootUrls.isEmpty()){
//                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
//                        new SwingWorker<Void, Void>() {
//                            @Override
//                            protected Void doInBackground() throws Exception {
//                                //删除所有findApi
//                                AnalyseHostResultTable.clearFindApiUrlsByRootUrls(rootUrls);
//                                //刷新表单
//                                refreshBasicHostTableModel(false);
//                                return null;
//                            }
//                        }.execute();
//                    }
//                }
//            }
//        });

        popupMenu.add(copyUrlItem);
        popupMenu.add(deleteItem);

        popupMenu.add(accessUnVisitedItem);
        popupMenu.add(updateUnVisitedItem);
        popupMenu.add(ClearUnVisitedItem);
        popupMenu.add(IgnoreUnVisitedItem);

        popupMenu.add(removeHostFromPathTreeItem);

        popupMenu.add(addRootUrlToBlackUrlRootItem);
        popupMenu.add(addRootUrlToNotAutoRecurseItem);
        popupMenu.add(addRootUrlToAllowListenItem);

        popupMenu.add(pathTreeToPathListItem);


        popupMenu.add(copySingleLayerNodeItem);
        popupMenu.add(calcSingleLayerNodeItemOnHost);

//        popupMenu.add(removeFindApiIListItem);

        // 将右键菜单添加到表格
        tableUI.setComponentPopupMenu(popupMenu);

    }


    /**
     * 清空当前Msg tabs中显示的数据
     */
    public static void clearBasicHostMsgTabsData() {
        basicHostFindInfoTextPane.setText("");
        basicHostRespFindUrlTEditor.setText(new byte[0]);
        basicHostRespFindPathTEditor.setText(new byte[0]);
        basicHostDirectPath2UrlTEditor.setText(new byte[0]);
        basicHostSmartPath2UrlTEditor.setText(new byte[0]);
        basicHostUnvisitedUrlTEditor.setText(new byte[0]);
        basicHostPathTreeTEditor.setText(new byte[0]);
    }

    public static void clearBasicHostMsgTableModel(){
        basicHostMsgTableModel.setRowCount(0);
    }
}


