package ui;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.ITextEditor;
import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;
import database.*;
import model.*;
import ui.MainTabRender.TableHeaderWithTips;
import ui.MainTabRender.importantCellRenderer;
import utils.CastUtils;
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

public class BasicHostInfoPanel extends JPanel {
    private static volatile BasicHostInfoPanel instance; //实现单例模式

    private static JTable baseHostMsgTableUI; //表格UI
    private static DefaultTableModel baseHostMsgTableModel; // 存储表格数据

    private static JEditorPane basicHostFindInfoTextPane;  //敏感信息文本面板
    private static ITextEditor basicHostRespFindUrlTEditor; //显示找到的URL
    private static ITextEditor basicHostRespFindPathTEditor; //显示找到的PATH
    private static ITextEditor basicHostDirectPath2UrlTEditor; //基于PATH计算出的URL
    private static ITextEditor basicHostSmartPath2UrlTEditor; //基于树算法计算出的URL
    private static ITextEditor basicHostUnvisitedUrlTEditor; //未访问过的URL

    private static ITextEditor basicHostPathTreeTEditor; //当前目标的路径树信息

    public static Timer baseHostTimer;  //定时器 为线程调度提供了一个简单的时间触发机制，广泛应用于需要定时执行某些操作的场景，
    public static LocalDateTime baseHostOperationStartTime = LocalDateTime.now(); //操作开始时间

    public static boolean baseHostAutoRefreshUnvisitedIsOpenDefault = false;
    public static boolean baseHostAutoRefreshUnvisitedIsOpen = baseHostAutoRefreshUnvisitedIsOpenDefault; //自动刷新未访问URL

    public static boolean baseHostAutoRefreshIsOpen = false;

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
        basicHostMainSplitPane.setTopComponent(new JScrollPane(baseHostMsgTableUI));

        //获取下方的消息面板
        JTabbedPane basicHostMsgTabs = getBasicHostMsgTabs();
        basicHostMainSplitPane.setBottomComponent(basicHostMsgTabs);

        //组合最终的内容面板
        add(basicHostConfigPanel, BorderLayout.NORTH);
        add(basicHostMainSplitPane, BorderLayout.CENTER);

        //初始化表格数据
        initBasicHostDataTableUIData(baseHostMsgTableModel);

//        // 初始化定时刷新页面函数 单位是毫秒
//        initTimer(ConfigPanel.timerDelay * 1000);
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
                baseHostPopulateModelFromList(tableModel, allReqAnalyseData);
            }
        });
    }

    /**
     * 把 jsonArray 赋值到 model 中
     * @param model
     * @param arrayList
     */
    private void baseHostPopulateModelFromList(DefaultTableModel model, ArrayList<BasicHostTableLineDataModel> arrayList) {
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
        baseHostMsgTableModel = new DefaultTableModel(new Object[]{
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

        baseHostMsgTableUI = UiUtils.creatTableUiWithTips(baseHostMsgTableModel);

        // 设置列选中模式
        int listSelectionModel = ListSelectionModel.MULTIPLE_INTERVAL_SELECTION;
        baseHostMsgTableUI.setSelectionMode(listSelectionModel);

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

        TableHeaderWithTips basicHostTableHeader = new TableHeaderWithTips(baseHostMsgTableUI.getColumnModel(), basicHostColHeaderTooltips);
        baseHostMsgTableUI.setTableHeader(basicHostTableHeader);

        //添加表头排序功能
        UiUtils.tableAddActionSortByHeader(baseHostMsgTableUI, baseHostMsgTableModel);

        //设置数据表的宽度
        UiUtils.tableSetColumnMaxWidth(baseHostMsgTableUI, 0, 50);
        UiUtils.tableSetColumnMinWidth(baseHostMsgTableUI, 1, 200);

        //设置表格每列的对齐设置
        List<Integer> leftColumns = Arrays.asList(1);
        UiUtils.tableSetColumnsAlignRender(baseHostMsgTableUI, leftColumns);

        //为重要信息列添加额外的渲染
        importantCellRenderer havingImportantRenderer = new importantCellRenderer();
        baseHostMsgTableUI.getColumnModel().getColumn(2).setCellRenderer(havingImportantRenderer);

        //为表格添加点击显示下方的消息动作
        basicHostTableAddActionSetMsgTabData();

        //为表的每一行添加右键菜单
        basicHostTableAddRightClickMenu(baseHostMsgTableUI, listSelectionModel);
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
                    List<String> rootUrls = UiUtils.geStringListAtActualRows(tableUI,selectedRows, 1);
                    if (!rootUrls.isEmpty())
                        UiUtils.copyToSystemClipboard(String.join("\n", rootUrls));
                }
            }
        });

        JMenuItem deleteItem = new JMenuItem("删除数据行", UiUtils.getImageIcon("/icon/deleteButton.png", 15, 15));
        // 添加 deleteItem 事件监听器
        deleteItem.setToolTipText("[多行]删除选定行对应的ReqDataTable表数据");
        deleteItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (selectModel >= 0){
                    int[] selectedRows = tableUI.getSelectedRows();
                    List<Integer> ids = UiUtils.getIdsAtActualRows(tableUI, selectedRows, 0);
                    // 使用SwingWorker来处理数据更新，避免阻塞EDT
                    new SwingWorker<Void, Void>() {
                        @Override
                        protected Void doInBackground() throws Exception {
                            CommonSql.deleteDataByIds(ids, AnalyseHostResultTable.tableName);
                            refreshBasicHostTableModel(false);
                            return null;
                        }
                    }.execute();
                }
            }
        });

        JMenuItem accessUnVisitedItem = new JMenuItem("访问当前未访问URL", UiUtils.getImageIcon("/icon/urlIcon.png", 15, 15));
        JMenuItem updateUnVisitedItem = new JMenuItem("刷新当前未访问URL", UiUtils.getImageIcon("/icon/refreshButton2.png", 15, 15));
        JMenuItem ClearUnVisitedItem = new JMenuItem("清空当前未访问URL", UiUtils.getImageIcon("/icon/deleteButton.png", 15, 15));
        JMenuItem IgnoreUnVisitedItem = new JMenuItem("忽略当前未访问URL", UiUtils.getImageIcon("/icon/editButton.png", 15, 15));

        JMenuItem removeHostFromPathTreeItem = new JMenuItem("清空HOST对应PathTree", UiUtils.getImageIcon("/icon/customizeIcon.png", 15, 15));
        JMenuItem addRootUrlToBlackUrlRootItem = new JMenuItem("添加到RootUrl黑名单", UiUtils.getImageIcon("/icon/noFindUrlFromJS.png", 15, 15));
        JMenuItem addRootUrlToNotAutoRecurseItem = new JMenuItem("添加到禁止自动递归目标", UiUtils.getImageIcon("/icon/noFindUrlFromJS.png", 15, 15));
        JMenuItem addRootUrlToAllowListenItem = new JMenuItem("添加到允许监听白名单", UiUtils.getImageIcon("/icon/findUrlFromJS.png", 15, 15));

        //提取当前API结果的单层节点 单层节点没有办法通过PATH树计算,必须手动拼接测试
        JMenuItem copySingleLayerNodeItem = new JMenuItem("提取当前PATH结果中的单层节点", UiUtils.getImageIcon("/icon/copyIcon.png", 15, 15));
        JMenuItem calcSingleLayerNodeItem = new JMenuItem("输入URL前缀生成单层节点对应URL", UiUtils.getImageIcon("/icon/copyIcon.png", 15, 15));
        JMenuItem removeFindApiIListItem = new JMenuItem("清空当前PATH拼接URL的结果内容", UiUtils.getImageIcon("/icon/deleteButton.png", 15, 15));

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

        popupMenu.add(copySingleLayerNodeItem);
        popupMenu.add(calcSingleLayerNodeItem);

        popupMenu.add(removeFindApiIListItem);

        // 将右键菜单添加到表格
        tableUI.setComponentPopupMenu(popupMenu);



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

        // 提取到URL的面板
        basicHostRespFindUrlTEditor = callbacks.createTextEditor();
        basicHostRespFindPathTEditor = callbacks.createTextEditor();
        basicHostDirectPath2UrlTEditor = callbacks.createTextEditor();
        basicHostSmartPath2UrlTEditor = callbacks.createTextEditor();
        basicHostUnvisitedUrlTEditor = callbacks.createTextEditor();
        basicHostPathTreeTEditor = callbacks.createTextEditor();

        tabs.addTab("RespFindInfo",null, basicHostFindInfoTextPane, "基于当前响应体提取的敏感信息"); //显示提取的信息
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
        baseHostMsgTableUI.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                // 只有在双击时才执行
                //if (e.getClickCount() == 2) {
                SwingUtilities.invokeLater(new Runnable() {
                    public void run() {
                        try {
                            int row = baseHostMsgTableUI.rowAtPoint(e.getPoint());
                            if (row >= 0) {
                                updateComponentsBasedOnSelectedRow(row);
                            }
                        }catch (Exception ef) {
                            BurpExtender.getStderr().println("[-] Error click table: " + baseHostMsgTableUI.rowAtPoint(e.getPoint()));
                            ef.printStackTrace(BurpExtender.getStderr());
                        }
                    }
                });
            }
        });

        //为表格 添加 键盘按键释放事件监听器
        //获取按键事件发生时鼠标所在行的索引 根据选中行的索引来更新其他组件的状态或内容。
        baseHostMsgTableUI.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                //关注向上 和向下 的按键事件
                if (e.getKeyCode() == KeyEvent.VK_UP || e.getKeyCode() == KeyEvent.VK_DOWN) {
                    SwingUtilities.invokeLater(new Runnable() {
                        public void run() {
                            try {
                                int row = baseHostMsgTableUI.getSelectedRow();
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
            rootUrl = UiUtils.getStringAtActualRow(baseHostMsgTableUI, row, 1);
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
        BasicHostTableTabDataModel tabDataModel = TableLineDataModelBasicHostSQL.fetchHostResultByRootUrl(rootUrl);
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
        if (checkAutoRefreshButtonStatus && baseHostAutoRefreshIsOpen) {
            if (Duration.between(baseHostOperationStartTime, LocalDateTime.now()).getSeconds() > 600) {
                BasicHostConfigPanel.setAutoRefreshOpen();
            }
            return;
        }

        // 获取搜索框和搜索选项
        final String searchText = BasicHostConfigPanel.getUrlSearchBoxText();
        final String selectedOption = BasicHostConfigPanel.getComboBoxSelectedOption();

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
                            baseHostMsgTableModel.fireTableDataChanged(); // 通知模型数据发生了变化
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
                baseHostMsgTableModel.setRowCount(0);

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
                        baseHostMsgTableModel.insertRow(baseHostMsgTableModel.getRowCount(), rowData); //插入到最后一行
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


}


