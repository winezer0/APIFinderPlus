package ui;

import burp.*;
import database.*;
import model.*;
import ui.MainTabRender.RunStatusCellRenderer;
import ui.MainTabRender.TableHeaderWithTips;
import ui.MainTabRender.HasImportantCellRenderer;
import utils.*;

import javax.swing.*;
import javax.swing.Timer;
import javax.swing.border.EmptyBorder;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutionException;

import static utils.BurpPrintUtils.*;
import static utils.CastUtils.isEmptyObj;
import static utils.CastUtils.isNotEmptyObj;

public class BasicUrlInfoPanel extends JPanel implements IMessageEditorController {
    private static volatile BasicUrlInfoPanel instance; //实现单例模式

    private static JTable basicUrlMsgTableUI; //表格UI
    private static DefaultTableModel basicUrlMsgTableModel; // 存储表格数据

    private static JSplitPane msgInfoViewer;  //请求消息|响应消息 二合一 面板
    private static IMessageEditor requestTextEditor;  //请求消息面板
    private static IMessageEditor responseTextEditor; //响应消息面板

    private static JEditorPane basicUrlFindInfoTextPane;  //敏感信息文本面板

    private static ITextEditor basicUrlRespFindUrlTEditor; //显示找到的URL
    private static ITextEditor basicUrlRespFindPathTEditor; //显示找到的PATH
    private static ITextEditor basicUrlDirectPath2UrlTEditor; //基于PATH计算出的URL

    private static byte[] requestsData; //请求数据,设置为全局变量,便于IMessageEditorController函数调用
    private static byte[] responseData; //响应数据,设置为全局变量,便于IMessageEditorController函数调用
    private static IHttpService iHttpService; //请求服务信息,设置为全局变量,便于IMessageEditorController函数调用

    private static Timer basicUrlTimer;  //定时器 为线程调度提供了一个简单的时间触发机制，广泛应用于需要定时执行某些操作的场景，

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
        BasicUrlConfigPanel basicUrlConfigPanel = new BasicUrlConfigPanel();

        // 数据表格
        initBasicUrlDataTableUI();

        // JScrollPane是一个可滚动的视图容器，通常用于包裹那些内容可能超出其显示区域的组件，比如表格(JTable)、文本区(JTextArea)等。
        //将包含table的滚动面板的upScrollPane 设置为另一个组件mainSplitPane的上半部分。
        basicUrlMainSplitPane.setTopComponent(new JScrollPane(basicUrlMsgTableUI));

        //获取下方的消息面板
        JTabbedPane basicUrlMsgInfoTabs = getBasicUrlMsgTabs();
        basicUrlMainSplitPane.setBottomComponent(basicUrlMsgInfoTabs);

        //组合最终的内容面板
        add(basicUrlConfigPanel, BorderLayout.NORTH);
        add(basicUrlMainSplitPane, BorderLayout.CENTER);

        //初始化表格数据
        initBasicUrlDataTableUIData(basicUrlMsgTableModel);

        // 初始化定时刷新页面函数 单位是毫秒
        stopTimerBasicUrl();
        startTimerBasicUrl();
    }

    /**
     * 查询 TableLineDataModelBasicUrlSQL 初始化 table 数据
     */
    private void initBasicUrlDataTableUIData(DefaultTableModel tableModel) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                //获取所有数据
                ArrayList<BasicUrlTableLineDataModel> allReqAnalyseData  = TableLineDataModelBasicUrlSQL.fetchUrlTableLineAll();
                //将数据赋值给表模型
                basicUrlPopulateModelFromList(tableModel, allReqAnalyseData);
            }
        });
    }

    /**
     * 把 jsonArray 赋值到 model 中
     * @param model
     * @param arrayList
     */
    private void basicUrlPopulateModelFromList(DefaultTableModel model, ArrayList<BasicUrlTableLineDataModel> arrayList) {
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
    private void initBasicUrlDataTableUI() {
        // 数据展示面板
        basicUrlMsgTableModel = new DefaultTableModel(new Object[]{
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
                "run_status"
        }, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                //在数据模型层面禁止编辑行数据
                return false;
            }
        };

        basicUrlMsgTableUI = UiUtils.creatTableUiWithTips(basicUrlMsgTableModel);

        // 设置列选中模式
        //  SINGLE_SELECTION：单行选择模式
        //  使用 int selectedRow = table.getSelectedRow(); 获取行号
        //  MULTIPLE_INTERVAL_SELECTION： 多行选定, 可以选择Shift连续|Ctrl不连续的区间。
        //  SINGLE_INTERVAL_SELECTION：   多行选定,但是必须选择连续的区间
        //  多选模式下调用应该调用 int[] rows = table.getSelectedRows(); 如果调用 getSelectedRow 只会获取第一个选项
        //int listSelectionModel = ListSelectionModel.SINGLE_SELECTION;
        int listSelectionModel = ListSelectionModel.MULTIPLE_INTERVAL_SELECTION;
        basicUrlMsgTableUI.setSelectionMode(listSelectionModel);

        //自己实现TableHeader 支持请求头提示
        String[] basicUrlColHeaderTooltips = new String[]{
                "【请求ID】",
                "【请求来源】",
                "【消息HASH】",
                "【请求URL】",
                "【请求方法】",
                "【响应状态】",
                "【响应长度】",
                "【是否重要信息】",
                "【敏感信息数量】 == 当前URL响应中的敏感信息",
                "【直接URL数量】 == 当前URL响应中提取的URL",
                "【网站PATH数量】 == 当前网站URL响应中提取的PATH",
                "【拼接URL数量】 == 当前请求目录 直接组合 已提取PATH（已过滤）",
                "【请求上下文分析状态】(不为 Waiting 表示已提取[敏感信息|URL信息|PATH信息])"
        };
        TableHeaderWithTips basicUrlTableHeader = new TableHeaderWithTips(basicUrlMsgTableUI.getColumnModel(), basicUrlColHeaderTooltips);
        basicUrlMsgTableUI.setTableHeader(basicUrlTableHeader);

        //添加表头排序功能
        UiUtils.tableAddActionSortByHeader(basicUrlMsgTableUI, basicUrlMsgTableModel);

        //设置表格每列的宽度
        UiUtils.tableSetColumnMaxWidth(basicUrlMsgTableUI, 0, 50);
        UiUtils.tableSetColumnMaxWidth(basicUrlMsgTableUI, 2, 100);
        UiUtils.tableSetColumnMinWidth(basicUrlMsgTableUI, 3, 300);

        //设置表格每列的对齐设置
        List<Integer> leftColumns = Arrays.asList(3);
        UiUtils.tableSetColumnsAlignRender(basicUrlMsgTableUI, leftColumns);

        //为重要信息列添加额外的渲染
        HasImportantCellRenderer havingImportantRenderer = new HasImportantCellRenderer();
        int ImportantColumnIndex = 7; //重要信息列所在的列号减1
        basicUrlMsgTableUI.getColumnModel().getColumn(ImportantColumnIndex).setCellRenderer(havingImportantRenderer);

        //为状态信息列添加额外的渲染 在最后一列,可以设置为动态值
        RunStatusCellRenderer runStatusCellRenderer = new RunStatusCellRenderer();
        int runStatusColumnIndex = basicUrlMsgTableUI.getColumnCount() - 1;
        basicUrlMsgTableUI.getColumnModel().getColumn(runStatusColumnIndex).setCellRenderer(runStatusCellRenderer);

        //为表格添加点击显示下方的消息动作
        basicUrlTableAddActionSetMsgTabData();

        //为表的每一行添加右键菜单
        basicUrlTableAddRightClickMenu(basicUrlMsgTableUI, listSelectionModel);
    }

    /**
     * 为 table 设置每一列的 右键菜单
     */
    private void basicUrlTableAddRightClickMenu(JTable tableUI, int selectModel) {
        // 创建右键菜单
        JPopupMenu popupMenu = new JPopupMenu();

        JMenuItem copyUrlItem = new JMenuItem("复制请求URL", UiUtils.getImageIcon("/icon/copyIcon.png", 15, 15));
        // 添加 copyUrlItem 事件监听器
        copyUrlItem.setToolTipText("[多行]复制选定行对应的请求URL到剪贴板");
        copyUrlItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行模式下的调用
                if (selectModel >= 0){
                    int[] selectedRows = tableUI.getSelectedRows();
                    List<String> urls = getUrlsAtActualRows(tableUI, selectedRows);
                    if (!urls.isEmpty())
                        UiUtils.copyToSystemClipboard(String.join("\n", urls));
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
                    List<Integer> ids = getIdsAtActualRows(tableUI, selectedRows);

                    // 使用SwingWorker来处理数据更新，避免阻塞EDT
                    new SwingWorker<Void, Void>() {
                        @Override
                        protected Void doInBackground() throws Exception {
                            CommonDeleteLine.deleteLineByIds(ReqDataTable.tableName, ids);
                            refreshBasicUrlTableModel(false);
                            return null;
                        }
                    }.execute();

                }
            }
        });

        JMenuItem addUrlPathToRecordPathItem = new JMenuItem("添加PATH为有效路径", UiUtils.getImageIcon("/icon/customizeIcon.png", 15, 15));
        // 添加 addUrlPathToRecordPathItem 事件监听器
        addUrlPathToRecordPathItem.setToolTipText("[多行]添加选定行对应的请求PATH到RecordPath表 用于计算PathTree");
        addUrlPathToRecordPathItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (selectModel >= 0) {
                    int[] selectedRows = tableUI.getSelectedRows();
                    List<String> urlList = getUrlsAtActualRows(tableUI, selectedRows);
                    if (!urlList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                RecordPathTable.insertOrUpdateRecordPathsBatch(urlList, 299);
                                refreshBasicUrlTableModel(false);
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        JMenuItem genDynaPathFilterItem = new JMenuItem("基于当前URL生成动态过滤条件", UiUtils.getImageIcon("/icon/refreshButton2.png", 15, 15));
        // 添加 genDynaPathFilterItem 事件监听器
        genDynaPathFilterItem.setToolTipText("[多行]基于选定行对应的URL生成对应HOST的动态响应过滤条件 过滤无效响应不完善时使用");
        genDynaPathFilterItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (selectModel >= 0) {
                    int[] selectedRows = tableUI.getSelectedRows();
                    List<String> msgHashList = getMsgHashListAtActualRows(tableUI, selectedRows);
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
                                        stdout_println(LOG_DEBUG, String.format("主动动态规则生成完毕:%s", CastUtils.toJsonString(dynamicFilterMap)));
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
                    List<String> msgHashList = getMsgHashListAtActualRows(tableUI, selectedRows);
                    if (!msgHashList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                List<FindPathModel> findPathModelList = AnalyseUrlResultTable.fetchPathDataByMsgHashList(msgHashList);
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

        JMenuItem calcSingleLayerNodeItemOnUrl = new JMenuItem("输入URL前缀生成单层节点对应URL", UiUtils.getImageIcon("/icon/copyIcon.png", 15, 15));
        //calcSingleLayerNodeItem
        calcSingleLayerNodeItemOnUrl.setToolTipText("[多行]基于选定行对应的提取PATH中的单层(无目录)PATH和用户输入的URL前缀计算新的URL");
        calcSingleLayerNodeItemOnUrl.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (selectModel >= 0) {
                    int[] selectedRows = tableUI.getSelectedRows();
                    List<String> msgHashList = getMsgHashListAtActualRows(tableUI, selectedRows);
                    if (!msgHashList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                UiUtils.showInputBoxAndHandle(msgHashList, "calcSingleLayerNodeItemOnUrl", "指定PATH生成单层节点URL");
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        JMenuItem addRootUrlToBlackUrlRootItem = new JMenuItem("添加到RootUrl黑名单", UiUtils.getImageIcon("/icon/noFindUrlFromJS.png", 15, 15));
        // 添加 addRootUrlToBlackUrlRootItem 事件监听器
        addRootUrlToBlackUrlRootItem.setToolTipText("[多行]添加选定行对应的RootUrl到禁止扫描黑名单 CONF_BLACK_ROOT_URL");
        addRootUrlToBlackUrlRootItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (selectModel>=0) {
                    int[] selectedRows = tableUI.getSelectedRows();
                    List<String> urlList = getUrlsAtActualRows(tableUI, selectedRows);
                    if (!urlList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                //获取所有URL的HOST列表
                                Set<String> set = new HashSet<>();
                                for (String url: urlList){set.add(new HttpUrlInfo(url).getRootUrlUsual());}
                                ArrayList<String> rootUrls = new ArrayList<>(set);

                                // 合并 rootUrls 到 BurpExtender.CONF_BLACK_ROOT_URL 保持唯一性
                                BurpExtender.CONF_BLACK_ROOT_URL =CastUtils.listAddList(rootUrls, BurpExtender.CONF_BLACK_ROOT_URL);

                                //保存Json
                                RuleConfigPanel.saveConfigToDefaultJson();

                                //2、删除 Root URL 对应的 结果数据
                                int countReq = CommonDeleteLine.deleteLineByUrlLikeRootUrls(ReqDataTable.tableName, rootUrls);
                                int countUrl = CommonDeleteLine.deleteLineByRootUrls(AnalyseUrlResultTable.tableName, rootUrls);
                                int countHost = CommonDeleteLine.deleteLineByRootUrls(AnalyseHostResultTable.tableName, rootUrls);
                                stdout_println(LOG_DEBUG, String.format("delete ReqData Count：%s , delete Analyse Host Result Count:%s, delete Analyse Url Result Count:%s", countReq, countHost, countUrl));

                                //3、刷新表格
                                refreshBasicUrlTableModel(false);
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        //标记选中消息 状态为等待自动处理 Constants.ANALYSE_WAIT
        JMenuItem setRunStatusAnalyseWaitItem = new JMenuItem("修改状态为等待自动分析", UiUtils.getImageIcon("/icon/customizeIcon.png", 15, 15));
        // 添加 setRunStatusAnalyseWaitItem 事件监听器
        setRunStatusAnalyseWaitItem.setToolTipText("[多行]修改所选消息状态为等待自动分析");
        setRunStatusAnalyseWaitItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (selectModel >= 0) {
                    int[] selectedRows = tableUI.getSelectedRows();
                    List<String> msgHashList = getMsgHashListAtActualRows(tableUI, selectedRows);
                    if (!msgHashList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                CommonUpdateStatus.updateStatusByMsgHashList(ReqDataTable.tableName, msgHashList, Constants.ANALYSE_WAIT);
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });


        //标记选中消息 状态为自动分析完成 Constants.ANALYSE_END
        JMenuItem setRunStatusAnalyseEndItem = new JMenuItem("修改状态为等待手动验证", UiUtils.getImageIcon("/icon/customizeIcon.png", 15, 15));
        // 添加 setRunStatusAnalyseEndItem 事件监听器
        setRunStatusAnalyseEndItem.setToolTipText("[多行]修改所选消息状态为等待手动验证");
        setRunStatusAnalyseEndItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (selectModel >= 0) {
                    int[] selectedRows = tableUI.getSelectedRows();
                    List<String> msgHashList = getMsgHashListAtActualRows(tableUI, selectedRows);
                    if (!msgHashList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                CommonUpdateStatus.updateStatusByMsgHashList(ReqDataTable.tableName, msgHashList, Constants.ANALYSE_END);
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        //标记选中消息 状态为手动分析完成  Constants.HANDLE_END
        JMenuItem setRunStatusHandleEndItem = new JMenuItem("修改状态为手动验证完成", UiUtils.getImageIcon("/icon/customizeIcon.png", 15, 15));
        // 添加 setRunStatusHandleEndItem 事件监听器
        setRunStatusHandleEndItem.setToolTipText("[多行]修改所选消息状态为手动验证完成");
        setRunStatusHandleEndItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (selectModel >= 0) {
                    int[] selectedRows = tableUI.getSelectedRows();
                    List<String> msgHashList = getMsgHashListAtActualRows(tableUI, selectedRows);
                    if (!msgHashList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                CommonUpdateStatus.updateStatusByMsgHashList(ReqDataTable.tableName, msgHashList, Constants.HANDLE_END);
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });


        //复制URL
        popupMenu.add(copyUrlItem);
        //删除航数据
        popupMenu.add(deleteItem);
        //添加到有效PATHTree
        popupMenu.add(addUrlPathToRecordPathItem);
        //更新数据处理状态
        popupMenu.add(setRunStatusAnalyseWaitItem);
        popupMenu.add(setRunStatusAnalyseEndItem);
        popupMenu.add(setRunStatusHandleEndItem);
        //添加Url对应的RootUrl到黑名单
        popupMenu.add(addRootUrlToBlackUrlRootItem);
        //生成动态过滤条件
        popupMenu.add(genDynaPathFilterItem);
        //仅复制单层路径
        popupMenu.add(copySingleLayerNodeItem);
        //输入指定根URL 计算单层路径的根URL
        popupMenu.add(calcSingleLayerNodeItemOnUrl);

        // 将右键菜单添加到表格
        tableUI.setComponentPopupMenu(popupMenu);
    }

    /**
     * 初始化任务定时器
     */
    public static void initTimerBasicUrl() {
        // 创建一个每 delay 秒触发一次的定时器
        int delay = BasicUrlConfigPanel.timerDelayOnUrl * 1000;
        basicUrlTimer = new Timer(delay, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (IProxyScanner.autoRefreshUiIsOpen && basicUrlTimer.isRunning()) {
                    try{
                        stdout_println(LOG_DEBUG, String.format("[*] Timer Refresh UI Basic Url On [%s]", delay));
                        // 调用刷新表格的方法
                        BasicUrlInfoPanel.getInstance().refreshBasicUrlTableModel(false);
                        //建议JVM清理内存
                        System.gc();
                    } catch (Exception exception){
                        stderr_println(LOG_ERROR, String.format("[!] Timer Refresh UI Basic Url Error: %s", exception.getMessage()) );
                    }
                }
            }
        });
        stdout_println(LOG_DEBUG, "[*] Init Timer Basic Url");
    }

    // 启动定时器
    public static void startTimerBasicUrl() {
        if (basicUrlTimer != null) {
            if (!basicUrlTimer.isRunning()){
                basicUrlTimer.start();
                stdout_println(LOG_DEBUG, "[*] Start Timer Basic Url");
            }
        } else {
            initTimerBasicUrl();
        }
    }

    // 定义一个方法来停止定时器
    public static void stopTimerBasicUrl() {
        if (basicUrlTimer != null && basicUrlTimer.isRunning()) {
            basicUrlTimer.stop();
            stdout_println(LOG_DEBUG, "[*] Stop Timer Basic Url");
        }
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
        basicUrlFindInfoTextPane = new JEditorPane("text/html", "");
        JScrollPane basicUrlFindInfoTextScrollPane = new JScrollPane(basicUrlFindInfoTextPane);
        basicUrlFindInfoTextScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);

        // 提取到URL的面板
        basicUrlRespFindUrlTEditor = callbacks.createTextEditor();
        basicUrlRespFindPathTEditor = callbacks.createTextEditor();
        basicUrlDirectPath2UrlTEditor = callbacks.createTextEditor();

        tabs.addTab("MsgInfoViewer",null, msgInfoViewer, "原始请求响应信息"); //同时显示原始请求+原始响应
        tabs.addTab("RespFindInfo",null, basicUrlFindInfoTextScrollPane, "基于当前响应体提取的敏感信息"); //显示提取的信息
        tabs.addTab("RespFindUrl",null, basicUrlRespFindUrlTEditor.getComponent(), "基于当前响应体提取的URL"); //显示在这个URL中找到的PATH
        tabs.addTab("RespFindPath",null, basicUrlRespFindPathTEditor.getComponent(), "基于当前响应体提取的PATH"); //显示在这个URL中找到的PATH
        tabs.addTab("DirectPath2Url",null, basicUrlDirectPath2UrlTEditor.getComponent(), "基于当前请求URL目录 拼接 提取的PATH"); //显示在这个URL中找到的PATH

        return tabs;
    }

    /**
     * 清空当前Msg tabs中显示的数据
     */
    public static void clearBasicUrlMsgTabsData() {
        iHttpService = null; // 清空当前显示的项
        requestsData = null;
        responseData = null;

        requestTextEditor.setMessage(new byte[0], true); // 清空请求编辑器
        responseTextEditor.setMessage(new byte[0], false); // 清空响应编辑器

        basicUrlFindInfoTextPane.setText("");
        basicUrlRespFindUrlTEditor.setText(new byte[0]);
        basicUrlRespFindPathTEditor.setText(new byte[0]);
        basicUrlDirectPath2UrlTEditor.setText(new byte[0]);
    }

    /**
     * 鼠标点击或键盘移动到行时,自动更新下方的msgTab
     */
    private void basicUrlTableAddActionSetMsgTabData() {
        //为表格 添加 鼠标监听器
        //获取点击事件发生时鼠标所在行的索引 根据选中行的索引来更新其他组件的状态或内容。
        basicUrlMsgTableUI.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                // 只有在双击时才执行
                //if (e.getClickCount() == 2) {
                SwingUtilities.invokeLater(new Runnable() {
                    public void run() {
                        try {
                            int row = basicUrlMsgTableUI.rowAtPoint(e.getPoint());
                            if (row >= 0) {
                                updateComponentsBasedOnSelectedRow(row);
                            }
                        }catch (Exception ef) {
                            BurpExtender.getStderr().println("[-] Error click table: " + basicUrlMsgTableUI.rowAtPoint(e.getPoint()));
                            ef.printStackTrace(BurpExtender.getStderr());
                        }
                    }
                });
            }
        });

        //为表格 添加 键盘按键释放事件监听器
        //获取按键事件发生时鼠标所在行的索引 根据选中行的索引来更新其他组件的状态或内容。
        basicUrlMsgTableUI.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                //关注向上 和向下 的按键事件
                if (e.getKeyCode() == KeyEvent.VK_UP || e.getKeyCode() == KeyEvent.VK_DOWN) {
                    SwingUtilities.invokeLater(new Runnable() {
                        public void run() {
                            try {
                                int row = basicUrlMsgTableUI.getSelectedRow();
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

    //记录当前所处的行号
    private String recordMsgHash = null;

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
        String currentMsgHash = null;
        try {
            //msgHash = (String) table.getModel().getValueAt(row, 1);
            //stdout_println(String.format("当前点击第[%s]行 获取 msgHash [%s]",row, msgHash));

            //实现排序后 视图行 数据的正确获取
            currentMsgHash = UiUtils.getStringAtActualRow(basicUrlMsgTableUI, row, 2);
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[!] Table get Value At Row [%s] Error:%s", row, e.getMessage() ));
        }

        //更新之前 msgHash Date为 处理中 注意 要修改 ReqDataTable
        if (isNotEmptyObj(recordMsgHash)){
            //当原来的状态是手动处理中时，就修改状态为处理完成
            CommonUpdateStatus.updateStatusWhenStatusByMsgHash(ReqDataTable.tableName, recordMsgHash, Constants.HANDLE_END, Constants.HANDLE_ING);
        }

        //更新当前 msgHash Date为 处理中
        if (isNotEmptyObj(currentMsgHash) ){
            //当原来的状态是自动分析完成时,就修改请求状态为手工处理中
            CommonUpdateStatus.updateStatusWhenStatusByMsgHash(ReqDataTable.tableName, currentMsgHash, Constants.HANDLE_ING, Constants.ANALYSE_END);
            recordMsgHash = currentMsgHash;
        } else {
            return;
        }

        //根据 msgHash值 查询对应的请求体响应体数据
        ReqMsgDataModel msgData = ReqMsgDataTable.fetchMsgDataByMsgHash(currentMsgHash);
        if (CastUtils.isNotEmptyObj(msgData)) {
            String requestUrl = msgData.getReqUrl();
            requestsData = msgData.getReqBytes();
            responseData = msgData.getRespBytes();
            //显示在UI中
            iHttpService = BurpHttpUtils.getHttpService(requestUrl);
            requestTextEditor.setMessage(requestsData, false);
            responseTextEditor.setMessage(responseData, false);
        } else {
            stderr_println(LOG_ERROR, String.format("[!] fetch Msg Data By MsgHash [%s] is null", currentMsgHash));
            return;
        }

        //根据 msgHash值 查询api分析结果数据
        BasicUrlTableTabDataModel tabDataModel = AnalyseUrlResultTable.fetchUrlResultByMsgHash(currentMsgHash);
        if (tabDataModel != null) {
            //格式化为可输出的类型
            String findInfo = CastUtils.infoJsonArrayFormatHtml(tabDataModel.getFindInfo());
            String findUrl = CastUtils.stringJsonArrayFormat(tabDataModel.getFindUrl());
            String findPath = CastUtils.stringJsonArrayFormat(tabDataModel.getFindPath());
            String findApi = CastUtils.stringJsonArrayFormat(tabDataModel.getFindApi());

            basicUrlFindInfoTextPane.setText(findInfo);
            basicUrlRespFindUrlTEditor.setText(findUrl.getBytes());
            basicUrlRespFindPathTEditor.setText(findPath.getBytes());
            basicUrlDirectPath2UrlTEditor.setText(findApi.getBytes());
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
     * 基于过滤选项 和 搜索框内容 显示结果
     * @param selectOption
     * @param searchText
     */
    public static void showDataUrlTableByFilter(String selectOption, String searchText) {
        // 在后台线程获取数据，避免冻结UI
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                // 构建一个新的表格模型
                basicUrlMsgTableModel.setRowCount(0);

                // 获取数据库中的所有ApiDataModels
                ArrayList<BasicUrlTableLineDataModel> apiDataModels;

                switch (selectOption) {
                    case "显示有效内容":
                        apiDataModels = TableLineDataModelBasicUrlSQL.fetchUrlTableLineHasInfoOrUri();
                        break;
                    case "待处理有效内容":
                        apiDataModels = TableLineDataModelBasicUrlSQL.fetchUrlTableLineHasInfoOrUriNotHandle();
                        break;
                    case "显示敏感内容":
                        apiDataModels = TableLineDataModelBasicUrlSQL.fetchUrlTableLineHasInfo();
                        break;
                    case "待处理敏感内容":
                        apiDataModels = TableLineDataModelBasicUrlSQL.fetchUrlTableLineHasInfoNotHandle();
                        break;
                    case "显示无效内容":
                        apiDataModels = TableLineDataModelBasicUrlSQL.fetchUrlTableLineAnyIsNull();
                        break;
                    case "显示全部内容":
                    default:
                        apiDataModels = TableLineDataModelBasicUrlSQL.fetchUrlTableLineAll();
                        break;
                }

                // 遍历apiDataModelMap
                for (BasicUrlTableLineDataModel apiDataModel : apiDataModels) {
                    String url = apiDataModel.getReqUrl();
                    //是否包含关键字,当输入了关键字时,使用本函数再次进行过滤
                    if (url.toLowerCase().contains(searchText.toLowerCase())) {
                        Object[] rowData = apiDataModel.toRowDataArray();
                        //model.insertRow(0, rowData); //插入到首行
                        basicUrlMsgTableModel.insertRow(basicUrlMsgTableModel.getRowCount(), rowData); //插入到最后一行
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
     * 定时刷新表数据
     */
    public void refreshBasicUrlTableModel(boolean checkAutoRefreshButtonStatus) {
        //设置已加入数据库的数量
        BasicUrlConfigPanel.lbTaskerCountOnUrl.setText(String.valueOf(CommonFetchData.fetchTableCounts(ReqDataTable.tableName)));
        //设置成功分析的数量
        BasicUrlConfigPanel.lbAnalysisEndCountOnUrl.setText(String.valueOf(CommonFetchData.fetchTableCountsByStatus(Constants.ANALYSE_END)));

        // 获取搜索框和搜索选项
        final String searchText = BasicUrlConfigPanel.getUrlSearchBoxTextOnUrl();
        final String selectedOption = BasicUrlConfigPanel.getComboBoxSelectedOptionOnUrl();

        // 使用SwingWorker来处理数据更新，避免阻塞EDT
        SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                try {
                    // 执行耗时的数据操作
                    BasicUrlInfoPanel.showDataUrlTableByFilter(selectedOption, searchText.isEmpty() ? "" : searchText);
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
                            basicUrlMsgTableModel.fireTableDataChanged(); // 通知模型数据发生了变化
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

    private List<String> getUrlsAtActualRows(JTable tableUI, int[] selectedRows) {
        return UiUtils.getStringListAtActualRows(tableUI, selectedRows, 3);
    }

    private List<String> getMsgHashListAtActualRows(JTable tableUI,int[] selectedRows) {
        return UiUtils.getStringListAtActualRows(tableUI, selectedRows, 2);
    }

    private List<Integer> getIdsAtActualRows(JTable tableUI, int[] selectedRows) {
        return UiUtils.getIdsAtActualRows(tableUI, selectedRows, 0);
    }

    public static void clearBasicUrlMsgTableModel(){
        basicUrlMsgTableModel.setRowCount(0);
    }
}


