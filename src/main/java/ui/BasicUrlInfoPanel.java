package ui;

import burp.*;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import database.*;
import model.*;
import ui.MainTabRender.TableHeaderWithTips;
import ui.MainTabRender.importantCellRenderer;
import utils.*;

import javax.swing.*;
import javax.swing.Timer;
import javax.swing.border.EmptyBorder;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.*;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutionException;

import static utils.BurpPrintUtils.*;
import static utils.CastUtils.isEmptyObj;
import static utils.CastUtils.isNotEmptyObj;

public class BasicUrlInfoPanel extends JPanel implements IMessageEditorController {
    private static volatile BasicUrlInfoPanel instance; //实现单例模式

    private static JTable baseUrlMsgTableUI; //表格UI
    private static DefaultTableModel baseUrlMsgTableModel; // 存储表格数据

    private static JSplitPane msgInfoViewer;  //请求消息|响应消息 二合一 面板
    private static IMessageEditor requestTextEditor;  //请求消息面板
    private static IMessageEditor responseTextEditor; //响应消息面板

    private static JEditorPane baseUrlFindInfoTextPane;  //敏感信息文本面板

    private static ITextEditor baseUrlRespFindUrlTEditor; //显示找到的URL
    private static ITextEditor baseUrlRespFindPathTEditor; //显示找到的PATH
    private static ITextEditor baseUrlDirectPath2UrlTEditor; //基于PATH计算出的URL
    private static ITextEditor baseUrlSmartPath2UrlTEditor; //基于树算法计算出的URL
    private static ITextEditor baseUrlUnvisitedUrlTEditor; //未访问过的URL

    private static byte[] requestsData; //请求数据,设置为全局变量,便于IMessageEditorController函数调用
    private static byte[] responseData; //响应数据,设置为全局变量,便于IMessageEditorController函数调用
    private static IHttpService iHttpService; //请求服务信息,设置为全局变量,便于IMessageEditorController函数调用

    public static Timer baseUrlTimer;  //定时器 为线程调度提供了一个简单的时间触发机制，广泛应用于需要定时执行某些操作的场景，
    public static LocalDateTime baseUrlOperationStartTime = LocalDateTime.now(); //操作开始时间

    public static boolean baseUrlAutoRefreshUnvisitedIsOpenDefault = false;
    public static boolean baseUrlAutoRefreshUnvisitedIsOpen = baseUrlAutoRefreshUnvisitedIsOpenDefault; //自动刷新未访问URL

    public static boolean baseUrlAutoRefreshIsOpen = false;

    public static BasicUrlInfoPanel getInstance() {
        if (instance == null) {
            synchronized (BasicUrlInfoPanel.class) {
                if (instance == null) {
                    instance = new BasicUrlInfoPanel();
                }
            }
        }
        return instance;
    }

    public BasicUrlInfoPanel() {
        // EmptyBorder 四周各有了5像素的空白边距
        setBorder(new EmptyBorder(5, 5, 5, 5));
        ////BorderLayout 将容器分为五个区域：北 南 东 西 中 每个区域可以放置一个组件，
        setLayout(new BorderLayout(0, 0));

        // 主分隔面板
        // JSplitPane可以包含两个（或更多）子组件，允许用户通过拖动分隔条来改变两个子组件的相对大小。
        JSplitPane basicUrlMainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        // 首行配置面板
        //TODO 需要实现配置面板的整合
        BasicUrlConfigPanel baseUrlConfigPanel = new BasicUrlConfigPanel();

        // 数据表格
        initBaseUrlDataTableUI();

        // JScrollPane是一个可滚动的视图容器，通常用于包裹那些内容可能超出其显示区域的组件，比如表格(JTable)、文本区(JTextArea)等。
        //将包含table的滚动面板的upScrollPane 设置为另一个组件mainSplitPane的上半部分。
        basicUrlMainSplitPane.setTopComponent(new JScrollPane(baseUrlMsgTableUI));

        //获取下方的消息面板
        JTabbedPane baseUrlMsgInfoTabs = getBasicUrlMsgTabs();
        basicUrlMainSplitPane.setBottomComponent(baseUrlMsgInfoTabs);

        //组合最终的内容面板
        add(baseUrlConfigPanel, BorderLayout.NORTH);
        add(basicUrlMainSplitPane, BorderLayout.CENTER);

        //初始化表格数据
        initBasicUrlDataTableUIData(baseUrlMsgTableModel);

        // 初始化定时刷新页面函数 单位是毫秒
        initBaiscUrlTimer(BasicUrlConfigPanel.timerDelay * 1000);
    }

    /**
     * 查询 TableLineDataModelBasicUrlSQL 初始化 table 数据
     */
    private void initBasicUrlDataTableUIData(DefaultTableModel tableModel) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                //获取所有数据
                ArrayList<BasicUrlTableLineDataModel> allReqAnalyseData  = TableLineDataModelBasicUrlSQL.fetchUrlTableLineDataAll();
                //将数据赋值给表模型
                baseUrlPopulateModelFromList(tableModel, allReqAnalyseData);
            }
        });
    }

    /**
     * 把 jsonArray 赋值到 model 中
     * @param model
     * @param arrayList
     */
    private void baseUrlPopulateModelFromList(DefaultTableModel model, ArrayList<BasicUrlTableLineDataModel> arrayList) {
        if (isEmptyObj(arrayList)) return;

        Iterator<BasicUrlTableLineDataModel> iterator = arrayList.iterator();
        while (iterator.hasNext()) {
            BasicUrlTableLineDataModel apiDataModel = iterator.next();
            Object[] rowData = apiDataModel.toRowDataArray();
            model.addRow(rowData);
        }
        //刷新表数据模型
        model.fireTableDataChanged();
    }

    /**
     * 初始化Table
     */
    private void initBaseUrlDataTableUI() {
        // 数据展示面板
        baseUrlMsgTableModel = new DefaultTableModel(new Object[]{
                "id",
                "source",
                "hash",
                "url",
                "method",
                "status",
                "length",
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

        baseUrlMsgTableUI = UiUtils.creatTableUiWithTips(baseUrlMsgTableModel);

        // 设置列选中模式
        //  SINGLE_SELECTION：单行选择模式
        //  使用 int selectedRow = table.getSelectedRow(); 获取行号
        //  MULTIPLE_INTERVAL_SELECTION： 多行选定, 可以选择Shift连续|Ctrl不连续的区间。
        //  SINGLE_INTERVAL_SELECTION：   多行选定,但是必须选择连续的区间
        //  多选模式下调用应该调用 int[] rows = table.getSelectedRows(); 如果调用 getSelectedRow 只会获取第一个选项
        //int listSelectionModel = ListSelectionModel.SINGLE_SELECTION;
        int listSelectionModel = ListSelectionModel.MULTIPLE_INTERVAL_SELECTION;
        baseUrlMsgTableUI.setSelectionMode(listSelectionModel);

        //自己实现TableHeader 支持请求头提示
        String[] colHeaderTooltips = new String[]{
                "请求ID",
                "请求来源",
                "消息HASH",
                "请求URL",
                "请求方法",
                "响应状态码",
                "响应长度",
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
        TableHeaderWithTips basicUrlTableHeader = new TableHeaderWithTips(baseUrlMsgTableUI.getColumnModel(), colHeaderTooltips);
        baseUrlMsgTableUI.setTableHeader(basicUrlTableHeader);

        //添加表头排序功能
        UiUtils.tableAddActionSortByHeader(baseUrlMsgTableUI, baseUrlMsgTableModel);

        //设置表格每列的宽度
        UiUtils.tableSetColumnMaxWidth(baseUrlMsgTableUI, 0, 50);
        UiUtils.tableSetColumnMaxWidth(baseUrlMsgTableUI, 2, 100);
        UiUtils.tableSetColumnMinWidth(baseUrlMsgTableUI, 3, 300);

        //设置表格每列的对齐设置
        List<Integer> leftColumns = Arrays.asList(3);
        UiUtils.tableSetColumnsAlignRender(baseUrlMsgTableUI, leftColumns);

        //为重要信息列添加额外的渲染
        importantCellRenderer havingImportantRenderer = new importantCellRenderer();
        baseUrlMsgTableUI.getColumnModel().getColumn(7).setCellRenderer(havingImportantRenderer);

        //为表格添加点击显示下方的消息动作
        basicUrlTableAddActionSetMsgTabData();

        //为表的每一行添加右键菜单
        basicUrlTableAddRightClickMenu(listSelectionModel);
    }

    /**
     * 为 table 设置每一列的 右键菜单
     */
    private void basicUrlTableAddRightClickMenu(int listSelectionModel) {
        // 创建右键菜单
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem deleteItem = new JMenuItem("删除数据行", UiUtils.getImageIcon("/icon/deleteButton.png", 15, 15));

        JMenuItem copyUrlItem = new JMenuItem("复制请求URL", UiUtils.getImageIcon("/icon/copyIcon.png", 15, 15));

        JMenuItem accessUnVisitedItem = new JMenuItem("访问当前未访问URL", UiUtils.getImageIcon("/icon/urlIcon.png", 15, 15));
        JMenuItem updateUnVisitedItem = new JMenuItem("刷新当前未访问URL", UiUtils.getImageIcon("/icon/refreshButton2.png", 15, 15));
        JMenuItem ClearUnVisitedItem = new JMenuItem("清空当前未访问URL", UiUtils.getImageIcon("/icon/deleteButton.png", 15, 15));
        JMenuItem IgnoreUnVisitedItem = new JMenuItem("忽略当前未访问URL", UiUtils.getImageIcon("/icon/editButton.png", 15, 15));

        JMenuItem addUrlPathToRecordPathItem = new JMenuItem("添加ATH为有效路径", UiUtils.getImageIcon("/icon/customizeIcon.png", 15, 15));
        JMenuItem removeHostFromPathTreeItem = new JMenuItem("清空HOST对应PathTree", UiUtils.getImageIcon("/icon/customizeIcon.png", 15, 15));

        JMenuItem addRootUrlToBlackUrlRootItem = new JMenuItem("添加到RootUrl黑名单", UiUtils.getImageIcon("/icon/noFindUrlFromJS.png", 15, 15));
        JMenuItem addRootUrlToNotAutoRecurseItem = new JMenuItem("添加到禁止自动递归目标", UiUtils.getImageIcon("/icon/noFindUrlFromJS.png", 15, 15));
        JMenuItem addRootUrlToAllowListenItem = new JMenuItem("添加到允许监听白名单", UiUtils.getImageIcon("/icon/findUrlFromJS.png", 15, 15));
        JMenuItem genDynaPathFilterItem = new JMenuItem("基于当前URL生成动态过滤条件", UiUtils.getImageIcon("/icon/refreshButton2.png", 15, 15));

        JMenuItem pathTreeToPathListItem = new JMenuItem("提取当前HOST的所有PATH", UiUtils.getImageIcon("/icon/copyIcon.png", 15, 15));
        //提取当前API结果的单层节点 单层节点没有办法通过PATH树计算,必须手动拼接测试
        JMenuItem copySingleLayerNodeItem = new JMenuItem("提取当前PATH结果中的单层节点", UiUtils.getImageIcon("/icon/copyIcon.png", 15, 15));

        JMenuItem calcSingleLayerNodeItem = new JMenuItem("输入URL前缀生成单层节点对应URL", UiUtils.getImageIcon("/icon/copyIcon.png", 15, 15));

        JMenuItem removeFindApiIListItem = new JMenuItem("清空当前PATH拼接URL的结果内容", UiUtils.getImageIcon("/icon/deleteButton.png", 15, 15));

        JMenuItem CopyAllFindInfoItem = new JMenuItem("复制当前所有敏感信息", UiUtils.getImageIcon("/icon/copyIcon.png", 15, 15));
        JMenuItem CopyAllFindUrlsItem = new JMenuItem("复制当前所有提取URL", UiUtils.getImageIcon("/icon/copyIcon.png", 15, 15));
        JMenuItem CopyAllFindPathItem = new JMenuItem("复制当前所有提取PATH", UiUtils.getImageIcon("/icon/copyIcon.png", 15, 15));
        JMenuItem CopyAllFindApiItem = new JMenuItem("复制当前所有PATH拼接URL", UiUtils.getImageIcon("/icon/copyIcon.png", 15, 15));
        JMenuItem CopyAllPath2UrlsItem = new JMenuItem("复制当前所有PATH计算URL", UiUtils.getImageIcon("/icon/copyIcon.png", 15, 15));
        JMenuItem CopyAllUnVisitedUrlsItem = new JMenuItem("复制当前所有未访问URL", UiUtils.getImageIcon("/icon/copyIcon.png", 15, 15));

        popupMenu.add(copyUrlItem);
        popupMenu.add(deleteItem);

        popupMenu.add(accessUnVisitedItem);
        popupMenu.add(updateUnVisitedItem);
        popupMenu.add(ClearUnVisitedItem);
        popupMenu.add(IgnoreUnVisitedItem);

        popupMenu.add(addUrlPathToRecordPathItem);
        popupMenu.add(removeHostFromPathTreeItem);

        popupMenu.add(addRootUrlToBlackUrlRootItem);
        popupMenu.add(addRootUrlToNotAutoRecurseItem);
        popupMenu.add(addRootUrlToAllowListenItem);
        popupMenu.add(genDynaPathFilterItem);

        popupMenu.add(pathTreeToPathListItem);
        popupMenu.add(copySingleLayerNodeItem);
        popupMenu.add(calcSingleLayerNodeItem);

        popupMenu.add(removeFindApiIListItem);


        popupMenu.add(CopyAllFindUrlsItem);
        popupMenu.add(CopyAllFindPathItem);
        popupMenu.add(CopyAllFindApiItem);
        popupMenu.add(CopyAllPath2UrlsItem);
        popupMenu.add(CopyAllUnVisitedUrlsItem);
        popupMenu.add(CopyAllFindInfoItem);

        // 将右键菜单添加到表格
        baseUrlMsgTableUI.setComponentPopupMenu(popupMenu);


        // 添加 copyUrlItem 事件监听器
        copyUrlItem.setToolTipText("[多行]复制选定行对应的请求URL到剪贴板");
        copyUrlItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
/*
                //单行模式下的调用
                if (listSelectionModel == ListSelectionModel.SINGLE_SELECTION){
                    int selectedRow = table.getSelectedRow();
                    if (selectedRow != -1) {
                        String url = UiUtils.getUrlAtActualRow(table, selectedRow);
                        UiUtils.copyToSystemClipboard(url);
                    }
                }
*/
                //多行模式下的调用
                if (listSelectionModel >= 0){
                    int[] selectedRows = baseUrlMsgTableUI.getSelectedRows();
                    List<String> urls = UiUtils.geStringListAtActualRows(baseUrlMsgTableUI,selectedRows, 3);
                    if (!urls.isEmpty())
                        UiUtils.copyToSystemClipboard(String.join("\n", urls));
                }
            }
        });

        // 添加 deleteItem 事件监听器
        deleteItem.setToolTipText("[多行]删除选定行对应的ReqDataTable表数据");
        deleteItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
/*
                if (listSelectionModel == ListSelectionModel.SINGLE_SELECTION) {
                    int selectedRow = table.getSelectedRow();
                    if (selectedRow != -1) {
                        int id = UiUtils.getIdAtActualRow(table, selectedRow);
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                ReqDataTable.deleteReqDataById(id);
                                refreshTableModel(false);
                                return null;
                            }
                        }.execute();
                    }
                }
*/

                //多行选定模式
                if (listSelectionModel >= 0){
                    int[] selectedRows = baseUrlMsgTableUI.getSelectedRows();
                        List<Integer> ids = UiUtils.getIdsAtActualRows(baseUrlMsgTableUI, selectedRows, 0);

                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                CommonSql.deleteDataByIds(ids, ReqDataTable.tableName);
                                refreshTableModel(false);
                                return null;
                            }
                        }.execute();

                }
            }
        });

        // 添加 ClearUnVisitedItem 事件监听器
        ClearUnVisitedItem.setToolTipText("[多行]清空选定行对应的未访问URL");
        ClearUnVisitedItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
/*
                //行选择模式
                if (listSelectionModel == ListSelectionModel.SINGLE_SELECTION) {
                    int selectedRow = table.getSelectedRow();
                    if (selectedRow != -1) {
                        String msgHash = UiUtils.getMsgHashAtActualRow(table, selectedRow);
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                AnalyseUrlResultTable.clearUnVisitedUrlsByMsgHash(msgHash);
                                refreshTableModel(false);
                                return null;
                            }
                        }.execute();
                    }
                }
*/
                //多行选定模式
                if (listSelectionModel >= 0){
                    int[] selectedRows = baseUrlMsgTableUI.getSelectedRows();
                    List<String> msgHashList =  UiUtils.geStringListAtActualRows(baseUrlMsgTableUI, selectedRows, 2);
                    if (!msgHashList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                AnalyseUrlResultTable.clearUnVisitedUrlsByMsgHashList(msgHashList);
                                refreshTableModel(false);
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        // 添加 IgnoreUnVisitedItem 事件监听器
        IgnoreUnVisitedItem.setToolTipText("[多行]标记选定行对应的未访问URL为已访问 并清空 当访问URL后依然无法过滤时使用");
        IgnoreUnVisitedItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
/*
                if (listSelectionModel == ListSelectionModel.SINGLE_SELECTION) {
                    int selectedRow = table.getSelectedRow();
                    if (selectedRow != -1) {
                        String msgHash = UiUtils.getMsgHashAtActualRow(table, selectedRow);
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                UnVisitedUrlsModel unVisitedUrlsModel= AnalyseUrlResultTable.fetchUnVisitedUrlsByMsgHash(msgHash);
                                List<String> unvisitedUrls = unVisitedUrlsModel.getUnvisitedUrls();
                                RecordUrlTable.batchInsertOrUpdateAccessedUrls(unvisitedUrls, 299);
                                AnalyseUrlResultTable.clearUnVisitedUrlsByMsgHash(msgHash);
                                refreshTableModel(false);
                                return null;
                            }
                        }.execute();
                    }
                }
*/

                //多行选定模式
                if (listSelectionModel >= 0){
                    int[] selectedRows = baseUrlMsgTableUI.getSelectedRows();
                    List<String> msgHashList =  UiUtils.geStringListAtActualRows(baseUrlMsgTableUI, selectedRows, 2);
                    if (!msgHashList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                //获取所有msgHash相关的结果
                                List<UnVisitedUrlsModelBasicUrl> unVisitedUrlsModels = AnalyseUrlResultTable.fetchUnVisitedUrlsByMsgHashList(msgHashList);

                                //整合所有结果URL到一个Set
                                Set<String> unvisitedUrlsSet = new HashSet<>();
                                for (UnVisitedUrlsModelBasicUrl unVisitedUrlsModel:unVisitedUrlsModels){
                                    List<String> unvisitedUrls = unVisitedUrlsModel.getUnvisitedUrls();
                                    unvisitedUrlsSet.addAll(unvisitedUrls);
                                }

                                //批量插入所有URL
                                RecordUrlTable.batchInsertOrUpdateAccessedUrls(new ArrayList<>(unvisitedUrlsSet), 299);
                                //批量删除所有msgHashList
                                AnalyseUrlResultTable.clearUnVisitedUrlsByMsgHashList(msgHashList);
                                refreshTableModel(false);
                                return null;
                            }
                        }.execute();

                    }
                }
            }
        });

        // 添加 addUrlPathToRecordPathItem 事件监听器
        addUrlPathToRecordPathItem.setToolTipText("[多行]添加选定行对应的请求PATH到RecordPath表 用于计算PathTree");
        addUrlPathToRecordPathItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (listSelectionModel >= 0) {
                    int[] selectedRows = baseUrlMsgTableUI.getSelectedRows();
                    List<String> urlList =  UiUtils.geStringListAtActualRows(baseUrlMsgTableUI, selectedRows, 3);
                    if (!urlList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                RecordPathTable.batchInsertOrUpdateRecordPath(urlList, 299);
                                refreshTableModel(false);
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        // 添加 removeHostFromPathTreeItem 事件监听器
        removeHostFromPathTreeItem.setToolTipText("[多行]清空选定行对应的HOST在PathTree及RecordPath中的数据");
        removeHostFromPathTreeItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (listSelectionModel>=0) {
                    int[] selectedRows = baseUrlMsgTableUI.getSelectedRows();
                    List<String> urlList =  UiUtils.geStringListAtActualRows(baseUrlMsgTableUI, selectedRows, 3);
                    if (!urlList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                CommonSql.deleteDataByUrlToRootUrls(urlList, PathTreeTable.tableName);
                                CommonSql.deleteDataByUrlToRootUrls(urlList, RecordPathTable.tableName);
                                refreshTableModel(false);
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        // 添加 updateUnVisitedItem 事件监听器
        updateUnVisitedItem.setToolTipText("[多行]更新选定行对应的未访问URL情况");
        updateUnVisitedItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (listSelectionModel >= 0) {
                    int[] selectedRows = baseUrlMsgTableUI.getSelectedRows();
                    List<String> msgHashList =  UiUtils.geStringListAtActualRows(baseUrlMsgTableUI, selectedRows, 2);
                    if (!msgHashList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                updateUnVisitedUrlsByMsgHashList(msgHashList);
                                refreshTableModel(false);
                                return null;
                            }
                        }.execute();

                    }
                }
            }
        });

        // 添加 addRootUrlToBlackUrlRootItem 事件监听器
        addRootUrlToBlackUrlRootItem.setToolTipText("[多行]添加选定行对应的RootUrl到禁止扫描黑名单 CONF_BLACK_URL_ROOT");
        addRootUrlToBlackUrlRootItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (listSelectionModel>=0) {
                    int[] selectedRows = baseUrlMsgTableUI.getSelectedRows();
                    List<String> urlList =  UiUtils.geStringListAtActualRows(baseUrlMsgTableUI, selectedRows, 3);
                    if (!urlList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                //0、获取所有rootUrl
                                Set<String> rootUrlSet = new HashSet<>();
                                for (String url:urlList){
                                    HttpUrlInfo urlInfo = new HttpUrlInfo(url);
                                    rootUrlSet.add(urlInfo.getRootUrlUsual());
                                }
                                ArrayList<String> rootUrlList = new ArrayList<>(rootUrlSet);

                                //1、加入到黑名单列表
                                //合并原来的列表
                                rootUrlSet.addAll(BurpExtender.CONF_BLACK_URL_ROOT);
                                BurpExtender.CONF_BLACK_URL_ROOT = new ArrayList<>(rootUrlSet);
                                //保存Json
                                RuleConfigPanel.saveConfigToDefaultJson();

                                //2、删除 Root URL 对应的 结果数据
                                int count1 = CommonSql.batchDeleteDataByLikeRootUrlList(rootUrlList, ReqDataTable.tableName);
                                int count2 = CommonSql.batchDeleteDataByLikeRootUrlList(rootUrlList, AnalyseUrlResultTable.tableName);
                                stdout_println(LOG_DEBUG, String.format("deleteReqDataCount：%s , deleteAnalyseResultCount:%s", count1, count2));

                                //3、刷新表格
                                refreshTableModel(false);
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });


//TODO 需要移动到基于主机的面板的右键功能中
//        // 添加 accessUnVisitedItem 事件监听器
//        accessUnVisitedItem.setToolTipText("[多行]访问选定行对应的当前所有未访问URL");
//        accessUnVisitedItem.addActionListener(new ActionListener() {
//            @Override
//            public void actionPerformed(ActionEvent e) {
//                //多行选定模式
//                if (listSelectionModel >= 0) {
//                    int[] selectedRows = msgTableUI.getSelectedRows();
//                    List<String> msgHashList =  UiUtils.getMsgHashListAtActualRows(msgTableUI, selectedRows);
//                    if (!msgHashList.isEmpty()){
//                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
//                        new SwingWorker<Void, Void>() {
//                            @Override
//                            protected Void doInBackground() throws Exception {
//                                //获取所有msgHash相关的结果
//                                List<UnVisitedUrlsModelBasicUrl> unVisitedUrlsModels = AnalyseUrlResultTable.fetchUnVisitedUrlsByMsgHashList(msgHashList);
//                                //批量访问所有URL模型
//                                for (UnVisitedUrlsModelBasicUrl unVisitedUrlsModel: unVisitedUrlsModels){
//                                    IProxyScanner.accessUnVisitedUrlsModel(unVisitedUrlsModel, false);
//                                }
//                                //标记所有扫描结果数据为空
//                                AnalyseUrlResultTable.clearUnVisitedUrlsByMsgHashList(msgHashList);
//                                refreshTableModel(false);
//                                return null;
//                            }
//                        }.execute();
//
//                    }
//                }
//            }
//        });

        // 添加 addRootUrlToNotAutoRecurseItem 事件监听器
        addRootUrlToNotAutoRecurseItem.setToolTipText("[多行]添加选定行对应的RootUrl加入到禁止自动递归列表 CONF_BLACK_AUTO_RECURSE_SCAN");
        addRootUrlToNotAutoRecurseItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (listSelectionModel>=0) {
                    int[] selectedRows = baseUrlMsgTableUI.getSelectedRows();
                    List<String> urlList =  UiUtils.geStringListAtActualRows(baseUrlMsgTableUI, selectedRows, 3);
                    if (!urlList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                //0、获取所有rootUrl
                                BurpExtender.CONF_BLACK_AUTO_RECURSE_SCAN = CastUtils.addRootUrlToList(urlList, BurpExtender.CONF_BLACK_AUTO_RECURSE_SCAN);
                                RuleConfigPanel.saveConfigToDefaultJson();
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        // 添加 addRootUrlToAllowListenItem 事件监听器
        addRootUrlToAllowListenItem.setToolTipText("[多行]添加选定行对应的RootUrl到仅监听的白名单 CONF_WHITE_URL_ROOT");
        addRootUrlToAllowListenItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (listSelectionModel>=0) {
                    int[] selectedRows = baseUrlMsgTableUI.getSelectedRows();
                    List<String> urlList =  UiUtils.geStringListAtActualRows(baseUrlMsgTableUI, selectedRows, 3);
                    if (!urlList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                BurpExtender.CONF_WHITE_URL_ROOT = CastUtils.addRootUrlToList(urlList, BurpExtender.CONF_WHITE_URL_ROOT);
                                //保存Json
                                RuleConfigPanel.saveConfigToDefaultJson();
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        // 添加 genDynaPathFilterItem 事件监听器
        genDynaPathFilterItem.setToolTipText("[多行]基于选定行对应的URL生成对应HOST的动态响应过滤条件 过滤无效响应不完善时使用");
        genDynaPathFilterItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (listSelectionModel >= 0) {
                    int[] selectedRows = baseUrlMsgTableUI.getSelectedRows();
                    List<String> msgHashList =  UiUtils.geStringListAtActualRows(baseUrlMsgTableUI, selectedRows, 2);
                    if (!msgHashList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                //1、获取 msgHash 对应 请求数据
                                List<ReqMsgDataModel> reqMsgDataModelList = ReqMsgDataTable.fetchMsgDataByMsgHashList(msgHashList);
                                for (ReqMsgDataModel msgDataModel : reqMsgDataModelList){
                                    //2、将请求数据组合成 MsgInfo
                                    HttpMsgInfo msgInfo = new HttpMsgInfo(
                                            msgDataModel.getReqUrl(),
                                            msgDataModel.getReqBytes(),
                                            msgDataModel.getRespBytes(),
                                            msgDataModel.getMsgHash()
                                    );
                                    //3、进行动态过滤器生成
                                    try {
                                        Map<String, Object> dynamicFilterMap = RespFieldCompareutils.generateDynamicFilterMap(msgInfo,true);
                                        IProxyScanner.urlCompareMap.put(msgInfo.getUrlInfo().getRootUrlUsual(), dynamicFilterMap);
                                        System.out.println(String.format("主动动态规则生成完毕:%s", CastUtils.toJsonString(dynamicFilterMap)));
                                    } catch (Exception e){
                                        e.printStackTrace();
                                    }
                                }
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        //pathTreeToPathListItem
        pathTreeToPathListItem.setToolTipText("[多行]复制选定行对应的RootUrl在PathTree中的路径数据到剪贴板 并弹框");
        pathTreeToPathListItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (listSelectionModel>=0) {
                    int[] selectedRows = baseUrlMsgTableUI.getSelectedRows();
                    List<String> urlList =  UiUtils.geStringListAtActualRows(baseUrlMsgTableUI, selectedRows, 3);
                    if (!urlList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                Set<String> pathSet = new LinkedHashSet<>();

                                //解析URL列表, 生成 rootUrls 列表
                                Set<String> rootUrls = new LinkedHashSet<>();
                                for (String url :urlList){
                                    rootUrls.add(new HttpUrlInfo(url).getRootUrlUsual());
                                }

                                for (String rootUrl:rootUrls){
                                    //查询host 对应的树
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

        //copySingleLayerNodeItem
        copySingleLayerNodeItem.setToolTipText("[多行]复制选定行对应的提取PATH中的单层(无目录)路径到剪贴板 并弹框");
        copySingleLayerNodeItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (listSelectionModel >= 0) {
                    int[] selectedRows = baseUrlMsgTableUI.getSelectedRows();
                    List<String> msgHashList =  UiUtils.geStringListAtActualRows(baseUrlMsgTableUI, selectedRows, 2);
                    if (!msgHashList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                Set<String> pathSet = fetchSingleLayerFindPathSet(msgHashList);
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

        //calcSingleLayerNodeItem
        calcSingleLayerNodeItem.setToolTipText("[多行]基于选定行对应的提取PATH中的单层(无目录)PATH和用户输入的URL前缀计算新的URL");
        calcSingleLayerNodeItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (listSelectionModel >= 0) {
                    int[] selectedRows = baseUrlMsgTableUI.getSelectedRows();
                    List<String> msgHashList =  UiUtils.geStringListAtActualRows(baseUrlMsgTableUI, selectedRows, 2);
                    if (!msgHashList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                showInputBoxAndHandle(msgHashList, "calcSingleLayerNodeItem", "指定PATH生成单层节点URL");
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        //removeFindApiIListItem
        removeFindApiIListItem.setToolTipText("[多行]移除选定行对应的PATH拼接URL内容及当前未访问URL中对应的内容 前后端分离时使用");
        removeFindApiIListItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (listSelectionModel >= 0) {
                    int[] selectedRows = baseUrlMsgTableUI.getSelectedRows();
                    List<String> msgHashList =  UiUtils.geStringListAtActualRows(baseUrlMsgTableUI, selectedRows, 2);
                    if (!msgHashList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                for (String msgHash:msgHashList){
                                    //逐个清理 UnvisitedURls 中的 findApiUrl

                                    //根据 msgHash值 查询api分析结果数据
                                    BasicUrlTableTabDataModel tabDataModel = AnalyseUrlResultTable.fetchResultByMsgHash(msgHash);
                                    if (tabDataModel != null) {

                                        //1、获取 msgHash 对应的 UnvisitedURls
                                        String unvisitedUrl = tabDataModel.getUnvisitedUrl();
                                        List<String> unvisitedUrlList = CastUtils.toStringList(unvisitedUrl);
                                        //跳过处理未访问列表为空的情况
                                        if (unvisitedUrlList.isEmpty()) continue;

                                        //2、获取 msgHash 对应的 findApiUrl
                                        String findApi = tabDataModel.getFindApi();
                                        List<String> findApiList = CastUtils.toStringList(findApi);
                                        //跳过处理findApi列表为空的情况
                                        if (findApiList.isEmpty()) continue;

                                        //3、计算差值 UnvisitedURls - findApiUrl
                                        unvisitedUrlList = CastUtils.listReduceList(unvisitedUrlList, findApiList);

                                        //4、更新 UnvisitedURls 到数据库
                                        UnVisitedUrlsModelBasicUrl unVisitedUrlsModel = new UnVisitedUrlsModelBasicUrl(-1, msgHash, null, unvisitedUrlList);
                                        AnalyseUrlResultTable.updateUnVisitedUrlsByMsgHash(unVisitedUrlsModel);
                                    }
                                }
                                //删除所有findApi
                                AnalyseUrlResultTable.clearFindApiUrlsByMsgHashList(msgHashList);
                                //刷新表单
                                refreshTableModel(false);
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        //复制当前所有提取URL
        CopyAllFindUrlsItem.setToolTipText("[多行]复制选定行对应的提取URL到剪贴板 并弹框");
        CopyAllFindUrlsItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (listSelectionModel >= 0) {
                    int[] selectedRows = baseUrlMsgTableUI.getSelectedRows();
                    List<String> msgHashList =  UiUtils.geStringListAtActualRows(baseUrlMsgTableUI, selectedRows, 2);
                    if (!msgHashList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                String columnName = "find_url";
                                Set<String> stringSet =  AnalyseUrlResultTable.fetchSpecialUrlsByMsgHashList(columnName, msgHashList);
                                //直接复制到用户的粘贴板
                                UiUtils.copyToSystemClipboard(String.join("\n", stringSet));
                                //弹框让用户查看
                                UiUtils.showOneMsgBoxToCopy(String.join("\n",stringSet), columnName + String.format(" => NUM %s", stringSet.size()));
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        //复制当前所有提取PATH
        CopyAllFindPathItem.setToolTipText("[多行]复制选定行对应的提取PATH到剪贴板 并弹框");
        CopyAllFindPathItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (listSelectionModel >= 0) {
                    int[] selectedRows = baseUrlMsgTableUI.getSelectedRows();
                    List<String> msgHashList =  UiUtils.geStringListAtActualRows(baseUrlMsgTableUI, selectedRows, 2);
                    if (!msgHashList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                String columnName = "find_path";
                                Set<String> stringSet =  AnalyseUrlResultTable.fetchSpecialUrlsByMsgHashList(columnName, msgHashList);
                                //直接复制到用户的粘贴板
                                UiUtils.copyToSystemClipboard(String.join("\n", stringSet));
                                //弹框让用户查看
                                UiUtils.showOneMsgBoxToCopy(String.join("\n",stringSet), columnName + String.format(" => NUM %s", stringSet.size()));
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        //复制当前所有PATH拼接URL
        CopyAllFindApiItem.setToolTipText("[多行]复制选定行对应的PATH拼接URL到剪贴板 并弹框");
        CopyAllFindApiItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (listSelectionModel >= 0) {
                    int[] selectedRows = baseUrlMsgTableUI.getSelectedRows();
                    List<String> msgHashList =  UiUtils.geStringListAtActualRows(baseUrlMsgTableUI, selectedRows, 2);
                    if (!msgHashList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                String columnName = "find_api";
                                Set<String> stringSet =  AnalyseUrlResultTable.fetchSpecialUrlsByMsgHashList(columnName, msgHashList);
                                //直接复制到用户的粘贴板
                                UiUtils.copyToSystemClipboard(String.join("\n", stringSet));
                                //弹框让用户查看
                                UiUtils.showOneMsgBoxToCopy(String.join("\n",stringSet), columnName + String.format(" => NUM %s", stringSet.size()));
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        //复制当前所有PATH计算URL
        CopyAllPath2UrlsItem.setToolTipText("[多行]复制选定行对应的PATH计算URL到剪贴板 并弹框");
        CopyAllPath2UrlsItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (listSelectionModel >= 0) {
                    int[] selectedRows = baseUrlMsgTableUI.getSelectedRows();
                    List<String> msgHashList =  UiUtils.geStringListAtActualRows(baseUrlMsgTableUI, selectedRows, 2);
                    if (!msgHashList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                String columnName = "path_to_url";
                                Set<String> stringSet =  AnalyseUrlResultTable.fetchSpecialUrlsByMsgHashList(columnName, msgHashList);
                                //直接复制到用户的粘贴板
                                UiUtils.copyToSystemClipboard(String.join("\n", stringSet));
                                //弹框让用户查看
                                UiUtils.showOneMsgBoxToCopy(String.join("\n",stringSet), columnName + String.format(" => NUM %s", stringSet.size()));
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        //复制当前所有未访问URL
        CopyAllUnVisitedUrlsItem.setToolTipText("[多行]复制选定行对应的未访问URL到剪贴板 并弹框");
        CopyAllUnVisitedUrlsItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (listSelectionModel >= 0) {
                    int[] selectedRows = baseUrlMsgTableUI.getSelectedRows();
                    List<String> msgHashList =  UiUtils.geStringListAtActualRows(baseUrlMsgTableUI, selectedRows, 2);
                    if (!msgHashList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                String columnName = "unvisited_url";
                                Set<String> stringSet =  AnalyseUrlResultTable.fetchSpecialUrlsByMsgHashList(columnName, msgHashList);
                                //直接复制到用户的粘贴板
                                UiUtils.copyToSystemClipboard(String.join("\n", stringSet));
                                //弹框让用户查看
                                UiUtils.showOneMsgBoxToCopy(String.join("\n",stringSet), columnName + String.format(" => NUM %s", stringSet.size()));
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        //复制当前所有敏感信息
        CopyAllFindInfoItem.setToolTipText("[多行]复制选定行对应的敏感信息到剪贴板 并弹框");
        CopyAllFindInfoItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (listSelectionModel >= 0) {
                    int[] selectedRows = baseUrlMsgTableUI.getSelectedRows();
                    List<String> msgHashList =  UiUtils.geStringListAtActualRows(baseUrlMsgTableUI, selectedRows, 2);
                    if (!msgHashList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                String columnName = "find_info";
                                Set<String> stringSet =  AnalyseUrlResultTable.fetchSpecialUrlsByMsgHashList(columnName, msgHashList);
                                String infoJsonStringSetFormatText = CastUtils.infoJsonStringSetFormatText(stringSet);
                                //直接复制到用户的粘贴板
                                UiUtils.copyToSystemClipboard(infoJsonStringSetFormatText);
                                //弹框让用户查看
                                UiUtils.showOneMsgBoxToCopy(infoJsonStringSetFormatText, columnName + String.format(" => NUM %s", stringSet.size()));
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });
    }

    /**
     * 弹框 读取用户输入 弹框 输出到用户
     * @param msgHashList
     * @param itemType
     * @param title
     */
    private void showInputBoxAndHandle(List<String> msgHashList, String itemType, String title) {
        //弹出框,等待用户输入
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

        JTextArea customParentPathArea = new JTextArea(15, 35);
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
                            switch (itemType){
                                case "calcSingleLayerNodeItem":
                                    //基于pathSet和用户输入组合URL
                                    Set<String> urlSet = new LinkedHashSet<>();
                                    Set<String> pathSet = fetchSingleLayerFindPathSet(msgHashList);
                                    for (String prefix : urlList) {
                                        List<String> urls = AnalyseInfoUtils.concatUrlAddPath(prefix, new ArrayList<>(pathSet));
                                        if (urls.size() > 0) urlSet.addAll(urls);
                                    }
                                    //直接复制到用户的粘贴板
                                    UiUtils.copyToSystemClipboard(String.join("\n", urlSet));
                                    //弹框让用户查看
                                    UiUtils.showOneMsgBoxToCopy(String.join("\n", urlSet), "单层路径生成URL");
                                    break;
                            }
                            return null;
                        }
                    }.execute();
                }
            }
        });
    }

    /**
     * 复制 msgHashList 对应的 提取PATH 中的 单层（无目录）路径
     */
    private Set<String> fetchSingleLayerFindPathSet(List<String> msgHashList) {
        Set<String> pathSet = new LinkedHashSet<>();
        //查询msgHash列表对应的所有数据find path 数据
        List<FindPathModel> findPathModelList = AnalyseUrlResultTable.fetchPathDataByMsgHashList(msgHashList);
        for (FindPathModel findPathModel:findPathModelList){
            //逐个提取PATH 并 加入 pathSet
            JSONArray findPaths = findPathModel.getFindPath();
            if (!findPaths.isEmpty()){
                // 提取 path中的单层路径
                for (Object uriPath : findPaths){
                    List<String> uriPart = PathTreeUtils.getUrlPart((String) uriPath);
                    if (uriPart.size() == 1){
                        pathSet.add(PathTreeUtils.formatUriPath((String) uriPath));
                    }
                }
            }
        }
        return pathSet;
    }

    /**
     * 初始化任务定时器
     * @param delay
     */
    private void initBaiscUrlTimer(int delay) {
        // 创建一个每10秒触发一次的定时器
        //int delay = 10000; // 延迟时间，单位为毫秒
        baseUrlTimer = new Timer(delay, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (IProxyScanner.executorService == null || IProxyScanner.executorService.getActiveCount() < 3) {
                    //stdout_println(LOG_DEBUG, String.format(String.format("[*] 当前进程数量[%s]", IProxyScanner.executorService.getActiveCount())) );
                    refreshAllUnVisitedUrlsAndTableUI(true, baseUrlAutoRefreshUnvisitedIsOpen);
                }
            }
        });

        // 启动定时器
        baseUrlTimer.start();
    }

    /**
     * 初始化创建表格下方的消息内容面板
     */
    private JTabbedPane getBasicUrlMsgTabs() {
        IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();

        // 将 结果消息面板 添加到窗口下方
        JTabbedPane tabs = new JTabbedPane();

        // 请求的面板
        requestTextEditor = callbacks.createMessageEditor(this, false);
        // 响应的面板
        responseTextEditor = callbacks.createMessageEditor(this, false);
        //添加请求和响应信息面板到一个面板中
        msgInfoViewer = new JSplitPane(1);
        msgInfoViewer.setLeftComponent(requestTextEditor.getComponent());
        msgInfoViewer.setRightComponent(responseTextEditor.getComponent());

        //敏感信息结果面板 使用 "text/html" 可用于 html 渲染颜色
        baseUrlFindInfoTextPane = new JEditorPane("text/html", "");

        // 提取到URL的面板
        baseUrlRespFindUrlTEditor = callbacks.createTextEditor();
        baseUrlRespFindPathTEditor = callbacks.createTextEditor();
        baseUrlDirectPath2UrlTEditor = callbacks.createTextEditor();
        baseUrlSmartPath2UrlTEditor = callbacks.createTextEditor();
        baseUrlUnvisitedUrlTEditor = callbacks.createTextEditor();

        tabs.addTab("MsgInfoViewer",null, msgInfoViewer, "原始请求响应信息"); //同时显示原始请求+原始响应
        tabs.addTab("RespFindInfo",null, baseUrlFindInfoTextPane, "基于当前响应体提取的敏感信息"); //显示提取的信息
        tabs.addTab("RespFindUrl",null, baseUrlRespFindUrlTEditor.getComponent(), "基于当前响应体提取的URL"); //显示在这个URL中找到的PATH
        tabs.addTab("RespFindPath",null, baseUrlRespFindPathTEditor.getComponent(), "基于当前响应体提取的PATH"); //显示在这个URL中找到的PATH
        tabs.addTab("DirectPath2Url",null, baseUrlDirectPath2UrlTEditor.getComponent(), "基于当前请求URL目录 拼接 提取的PATH"); //显示在这个URL中找到的PATH
        tabs.addTab("SmartPath2Url",null, baseUrlSmartPath2UrlTEditor.getComponent(), "基于当前网站有效目录 和 提取的PATH 动态计算出的URL"); //显示在这个URL中找到的PATH
        tabs.addTab("UnvisitedUrl",null, baseUrlUnvisitedUrlTEditor.getComponent(), "当前URL所有提取URL 减去 已经访问过的URL"); //显示在这个URL中找到的Path 且还没有访问过的URL

        return tabs;
    }

    /**
     * 清空当前Msg tabs中显示的数据
     */
    private static void clearBasicUrlMsgTabsData() {
        iHttpService = null; // 清空当前显示的项
        requestsData = null;
        responseData = null;

        requestTextEditor.setMessage(new byte[0], true); // 清空请求编辑器
        responseTextEditor.setMessage(new byte[0], false); // 清空响应编辑器

        baseUrlFindInfoTextPane.setText("");
        baseUrlRespFindUrlTEditor.setText(new byte[0]);
        baseUrlRespFindPathTEditor.setText(new byte[0]);
        baseUrlDirectPath2UrlTEditor.setText(new byte[0]);
        baseUrlSmartPath2UrlTEditor.setText(new byte[0]);
        baseUrlUnvisitedUrlTEditor.setText(new byte[0]);
    }


    /**
     * 鼠标点击或键盘移动到行时,自动更新下方的msgTab
     */
    private void basicUrlTableAddActionSetMsgTabData() {
        //为表格 添加 鼠标监听器
        //获取点击事件发生时鼠标所在行的索引 根据选中行的索引来更新其他组件的状态或内容。
        baseUrlMsgTableUI.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                // 只有在双击时才执行
                //if (e.getClickCount() == 2) {
                SwingUtilities.invokeLater(new Runnable() {
                    public void run() {
                        try {
                            int row = baseUrlMsgTableUI.rowAtPoint(e.getPoint());
                            if (row >= 0) {
                                updateComponentsBasedOnSelectedRow(row);
                            }
                        }catch (Exception ef) {
                            BurpExtender.getStderr().println("[-] Error click table: " + baseUrlMsgTableUI.rowAtPoint(e.getPoint()));
                            ef.printStackTrace(BurpExtender.getStderr());
                        }
                    }
                });
            }
        });

        //为表格 添加 键盘按键释放事件监听器
        //获取按键事件发生时鼠标所在行的索引 根据选中行的索引来更新其他组件的状态或内容。
        baseUrlMsgTableUI.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                //关注向上 和向下 的按键事件
                if (e.getKeyCode() == KeyEvent.VK_UP || e.getKeyCode() == KeyEvent.VK_DOWN) {
                    SwingUtilities.invokeLater(new Runnable() {
                        public void run() {
                            try {
                                int row = baseUrlMsgTableUI.getSelectedRow();
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
        clearBasicUrlMsgTabsData();

        //动态设置UI宽度
        msgViewerAutoSetSplitCenter();

        //1、获取当前行的msgHash
        String msgHash = null;
        try {
            //msgHash = (String) table.getModel().getValueAt(row, 1);
            //stdout_println(String.format("当前点击第[%s]行 获取 msgHash [%s]",row, msgHash));

            //实现排序后 视图行 数据的正确获取
            msgHash = UiUtils.getStringAtActualRow(baseUrlMsgTableUI, row, 2);
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[!] Table get Value At Row [%s] Error:%s", row, e.getMessage() ));
        }

        if (CastUtils.isEmptyObj(msgHash)) return;

        //根据 msgHash值 查询对应的请求体响应体数据
        ReqMsgDataModel msgData = ReqMsgDataTable.fetchMsgDataByMsgHash(msgHash);
        if (CastUtils.isNotEmptyObj(msgData)) {
            String requestUrl = msgData.getReqUrl();
            requestsData = msgData.getReqBytes();
            responseData = msgData.getRespBytes();
            //显示在UI中
            iHttpService = BurpHttpUtils.getHttpService(requestUrl);
            requestTextEditor.setMessage(requestsData, false);
            responseTextEditor.setMessage(responseData, false);
        } else {
            stderr_println(LOG_ERROR, String.format("[!] fetch Msg Data By MsgHash [%s] is null", msgHash));
            return;
        }

        //根据 msgHash值 查询api分析结果数据
        BasicUrlTableTabDataModel tabDataModel = AnalyseUrlResultTable.fetchResultByMsgHash(msgHash);
        if (tabDataModel != null) {
            //格式化为可输出的类型
            String findInfo = CastUtils.infoJsonArrayFormatHtml(tabDataModel.getFindInfo());
            String findUrl = CastUtils.stringJsonArrayFormat(tabDataModel.getFindUrl());
            String findPath = CastUtils.stringJsonArrayFormat(tabDataModel.getFindPath());
            String findApi = CastUtils.stringJsonArrayFormat(tabDataModel.getFindApi());
            String pathToUrl = CastUtils.stringJsonArrayFormat(tabDataModel.getPathToUrl());
            String unvisitedUrl = CastUtils.stringJsonArrayFormat(tabDataModel.getUnvisitedUrl());

            baseUrlFindInfoTextPane.setText(findInfo);
            baseUrlRespFindUrlTEditor.setText(findUrl.getBytes());
            baseUrlRespFindPathTEditor.setText(findPath.getBytes());
            baseUrlDirectPath2UrlTEditor.setText(findApi.getBytes());
            baseUrlSmartPath2UrlTEditor.setText(pathToUrl.getBytes());
            baseUrlUnvisitedUrlTEditor.setText(unvisitedUrl.getBytes());
        }
    }

    /**
     * 当左边极小时 设置请求体和响应体各占一半空间
     */
    private void msgViewerAutoSetSplitCenter() {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                if (msgInfoViewer.getLeftComponent().getWidth() <= 20)
                    msgInfoViewer.setDividerLocation(msgInfoViewer.getParent().getWidth() / 2);
            }
        });
    }

    /**
     * 清理所有数据
     */
    public static void clearModelData(boolean clearAllTable){
        synchronized (baseUrlMsgTableModel) {
            // 清空model
            baseUrlMsgTableModel.setRowCount(0);

            //清空记录变量的内容
            IProxyScanner.urlScanRecordMap = new RecordHashMap();

            BasicUrlConfigPanel.lbRequestCount.setText("0");
            BasicUrlConfigPanel.lbTaskerCount.setText("0");
            BasicUrlConfigPanel.lbAnalysisEndCount.setText("0/0");


            //置空 过滤数据
            IProxyScanner.urlCompareMap.clear();

            //清空数据库内容
            if (clearAllTable) {
                DBService.clearAllTables();
            } else {
                DBService.clearModelTables();
            }
            // 清空检索框的内容
            SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    BasicUrlConfigPanel.setUrlSearchBoxText("");
                }
            });

            // 还可以清空编辑器中的数据
            clearBasicUrlMsgTabsData();
        }
    }

    /**
     * 基于过滤选项 和 搜索框内容 显示结果
     * @param selectOption
     * @param searchText
     */
    public static void showDataTableByFilter(String selectOption, String searchText) {
        // 在后台线程获取数据，避免冻结UI
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                // 构建一个新的表格模型
                baseUrlMsgTableModel.setRowCount(0);

                // 获取数据库中的所有ApiDataModels
                ArrayList<BasicUrlTableLineDataModel> apiDataModels =null;

                switch (selectOption) {
                    case "显示有效内容":
                        apiDataModels = TableLineDataModelBasicUrlSQL.fetchUrlTableLineDataHasData();
                        break;
                    case "显示敏感内容":
                        apiDataModels = TableLineDataModelBasicUrlSQL.fetchTableLineDataHasInfo();
                        break;
                    case "显示未访问路径":
                        apiDataModels = TableLineDataModelBasicUrlSQL.fetchTableLineDataHasUnVisitedUrls();
                        break;
                    case "显示无效内容":
                        apiDataModels = TableLineDataModelBasicUrlSQL.fetchTableLineDataIsNull();
                        break;
                    case "显示全部内容":
                    default:
                        apiDataModels = TableLineDataModelBasicUrlSQL.fetchUrlTableLineDataAll();
                        break;
                }

                // 遍历apiDataModelMap
                for (BasicUrlTableLineDataModel apiDataModel : apiDataModels) {
                    String url = apiDataModel.getReqUrl();
                    //是否包含关键字,当输入了关键字时,使用本函数再次进行过滤
                    if (url.toLowerCase().contains(searchText.toLowerCase())) {
                        Object[] rowData = apiDataModel.toRowDataArray();
                        //model.insertRow(0, rowData); //插入到首行
                        baseUrlMsgTableModel.insertRow(baseUrlMsgTableModel.getRowCount(), rowData); //插入到最后一行
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
     * 刷新未访问的URL和数据表模型, 费内存的操作
     * @param checkAutoRefreshButtonStatus 是否检查自动更新按钮的状态
     * @param updateAllUnVisitedUrls 是否开启 updateUnVisitedUrls 函数的调用
     */
    public void refreshAllUnVisitedUrlsAndTableUI(boolean checkAutoRefreshButtonStatus, boolean updateAllUnVisitedUrls) {
        // 调用更新未访问URL列的数据
        if (updateAllUnVisitedUrls)
            try{
                //当添加进程还比较多的时候,暂时不进行响应数据处理
                updateAllUnVisitedUrls();
            } catch (Exception ep){
                stderr_println(LOG_ERROR, String.format("[!] 更新未访问URL发生错误：%s", ep.getMessage()) );
            }

        // 调用刷新表格的方法
        try{
            BasicUrlInfoPanel.getInstance().refreshTableModel(checkAutoRefreshButtonStatus);
        } catch (Exception ep){
            stderr_println(LOG_ERROR, String.format("[!] 刷新表格发生错误：%s", ep.getMessage()) );
        }

        //建议JVM清理内存
        System.gc();
    }

    //复用 updateUnVisitedUrls
    private void updateAllUnVisitedUrls(){
        updateUnVisitedUrlsByMsgHashList(null);
    }

    /**
     * 查询所有UnVisitedUrls并逐个进行过滤, 费内存的操作
     * @param msgHashList updateUnVisitedUrls 目标列表, 为空 为Null时更新全部
     */
    private void updateUnVisitedUrlsByMsgHashList(List<String> msgHashList) {
        // 使用SwingWorker来处理数据更新，避免阻塞EDT
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                // 获取所有未访问URl 注意需要大于0
                List<UnVisitedUrlsModelBasicUrl> unVisitedUrlsModels;
                if (msgHashList == null || msgHashList.isEmpty()) {
                    //更新所有的结果
                    unVisitedUrlsModels = AnalyseUrlResultTable.fetchAllUnVisitedUrls();
                }else {
                    //仅更新指定 msgHash 对应的未访问URL
                    unVisitedUrlsModels = AnalyseUrlResultTable.fetchUnVisitedUrlsByMsgHashList(msgHashList);
                }

                if (unVisitedUrlsModels.size() > 0) {
                    // 获取所有 已经被访问过得URL列表
                    //List<String> accessedUrls = RecordUrlTable.fetchAllAccessedUrls();
                    //获取所有由reqHash组成的字符串
                    String accessedUrlHashes = CommonSql.fetchConcatColumnToString(RecordUrlTable.tableName, RecordUrlTable.urlHashName);
                    // 遍历 unVisitedUrlsModels 进行更新
                    for (UnVisitedUrlsModelBasicUrl urlsModel : unVisitedUrlsModels) {
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
                        newUnVisitedUrls = AnalyseInfo.filterFindUrls(urlsModel.getReqUrl(), newUnVisitedUrls, BurpExtender.onlyScopeDomain);
                        urlsModel.setUnvisitedUrls(newUnVisitedUrls);

                        // 执行更新插入数据操作
                        try {
                            AnalyseUrlResultTable.updateUnVisitedUrlsById(urlsModel);
                        } catch (Exception ex) {
                            stderr_println(String.format("[!] Updating unvisited URL Error:%s", ex.getMessage()));
                        }
                    }
                }
                return null;
            }
        }.execute();
    }

    /**
     * 定时刷新表数据
     */
    public void refreshTableModel(boolean checkAutoRefreshButtonStatus) {
        //当已经卸载插件时,不要再进行刷新UI
        if (!BurpExtender.EXTENSION_IS_LOADED)
            return;

        //设置已加入数据库的数量
        BasicUrlConfigPanel.lbTaskerCount.setText(String.valueOf(CommonSql.getTableCounts(ReqDataTable.tableName)));
        //设置成功分析的数量
        BasicUrlConfigPanel.lbAnalysisEndCount.setText(String.valueOf(ReqDataTable.getReqDataCountWhereStatusIsEnd()));

        // 刷新页面, 如果自动更新关闭，则不刷新页面内容
        if (checkAutoRefreshButtonStatus && baseUrlAutoRefreshIsOpen) {
            if (Duration.between(baseUrlOperationStartTime, LocalDateTime.now()).getSeconds() > 600) {
                BasicUrlConfigPanel.setAutoRefreshOpen();
            }
            return;
        }

        // 获取搜索框和搜索选项
        final String searchText = BasicUrlConfigPanel.getUrlSearchBoxText();
        final String selectedOption = BasicUrlConfigPanel.getComboBoxSelectedOption();

        // 使用SwingWorker来处理数据更新，避免阻塞EDT
        SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                try {
                    // 执行耗时的数据操作
                    BasicUrlInfoPanel.showDataTableByFilter(selectedOption, searchText.isEmpty() ? "" : searchText);
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
                            baseUrlMsgTableModel.fireTableDataChanged(); // 通知模型数据发生了变化
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

    @Override
    public byte[] getRequest() {
        return requestsData;
    }

    @Override
    public byte[] getResponse() {
        return responseData;
    }

    @Override
    public IHttpService getHttpService() {
        return iHttpService;
    }
}


