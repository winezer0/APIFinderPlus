package ui;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.ITextEditor;
import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;
import database.PathTreeTable;
import database.TableLineDataModelBasicHostSQL;
import model.PathTreeModel;
import model.TableLineDataModelBasicHost;
import model.TableTabDataModelBasicHost;
import ui.MainTabRender.TableHeaderWithTips;
import ui.MainTabRender.importantCellRenderer;
import utils.CastUtils;
import utils.UiUtils;

import javax.swing.Timer;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.time.LocalDateTime;
import java.util.List;
import java.util.*;

import static utils.BurpPrintUtils.LOG_ERROR;
import static utils.BurpPrintUtils.stderr_println;
import static utils.CastUtils.isEmptyObj;

public class BasicHostInfoPanel extends JPanel {
    private static volatile BasicHostInfoPanel instance; //实现单例模式

    private static JTable baseHostMsgTableUI; //表格UI
    private static DefaultTableModel baseHostMsgTableModel; // 存储表格数据

    private static JEditorPane findInfoTextPane;  //敏感信息文本面板
    private static ITextEditor respFindUrlTEditor; //显示找到的URL
    private static ITextEditor respFindPathTEditor; //显示找到的PATH
    private static ITextEditor directPath2UrlTEditor; //基于PATH计算出的URL
    private static ITextEditor smartPath2UrlTEditor; //基于树算法计算出的URL
    private static ITextEditor unvisitedUrlTEditor; //未访问过的URL

    private static ITextEditor hostPathTreeTEditor; //当前目标的路径树信息

    public static Timer timer;  //定时器 为线程调度提供了一个简单的时间触发机制，广泛应用于需要定时执行某些操作的场景，
    public static LocalDateTime operationStartTime = LocalDateTime.now(); //操作开始时间

    public static boolean autoRefreshUnvisitedIsOpenDefault = false;
    public static boolean autoRefreshUnvisitedIsOpen = autoRefreshUnvisitedIsOpenDefault; //自动刷新未访问URL

    public static boolean autoRefreshIsOpen = false;

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
                ArrayList<TableLineDataModelBasicHost> allReqAnalyseData  = TableLineDataModelBasicHostSQL.fetchHostTableLineDataAll();
                //将数据赋值给表模型
                populateModelFromJsonArray(tableModel, allReqAnalyseData);
            }
        });
    }

    /**
     * 把 jsonArray 赋值到 model 中
     * @param model
     * @param jsonArray
     */
    private static void populateModelFromJsonArray(DefaultTableModel model, ArrayList<TableLineDataModelBasicHost> jsonArray) {
        if (isEmptyObj(jsonArray)) return;

        Iterator<TableLineDataModelBasicHost> iterator = jsonArray.iterator();
        while (iterator.hasNext()) {
            TableLineDataModelBasicHost apiDataModel = iterator.next();
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
        String[] colHeaderTooltips = new String[]{
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

        TableHeaderWithTips headerWithTooltips = new TableHeaderWithTips(baseHostMsgTableUI.getColumnModel(), colHeaderTooltips);
        baseHostMsgTableUI.setTableHeader(headerWithTooltips);

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
        hostTableAddActionSetMsgTabData();

        //为表的每一行添加右键菜单
        tableAddRightClickMenu(listSelectionModel);
    }


    //TODO 实现添加右键菜单
    private void tableAddRightClickMenu(int listSelectionModel) {
    }

    /**
     * 初始化创建表格下方的消息内容面板
     */
    private JTabbedPane getBasicHostMsgTabs() {
        IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();

        // 将 结果消息面板 添加到窗口下方
        JTabbedPane tabs = new JTabbedPane();

        //敏感信息结果面板 使用 "text/html" 可用于 html 渲染颜色
        findInfoTextPane = new JEditorPane("text/html", "");

        // 提取到URL的面板
        respFindUrlTEditor = callbacks.createTextEditor();
        respFindPathTEditor = callbacks.createTextEditor();
        directPath2UrlTEditor = callbacks.createTextEditor();
        smartPath2UrlTEditor = callbacks.createTextEditor();
        unvisitedUrlTEditor = callbacks.createTextEditor();
        hostPathTreeTEditor = callbacks.createTextEditor();

        tabs.addTab("RespFindInfo",null, findInfoTextPane, "基于当前响应体提取的敏感信息"); //显示提取的信息
        tabs.addTab("RespFindUrl",null, respFindUrlTEditor.getComponent(), "基于当前响应体提取的URL"); //显示在这个URL中找到的PATH
        tabs.addTab("RespFindPath",null, respFindPathTEditor.getComponent(), "基于当前响应体提取的PATH"); //显示在这个URL中找到的PATH
        tabs.addTab("DirectPath2Url",null, directPath2UrlTEditor.getComponent(), "基于当前请求URL目录 拼接 提取的PATH"); //显示在这个URL中找到的PATH
        tabs.addTab("SmartPath2Url",null, smartPath2UrlTEditor.getComponent(), "基于当前网站有效目录 和 提取的PATH 动态计算出的URL"); //显示在这个URL中找到的PATH
        tabs.addTab("UnvisitedUrl",null, unvisitedUrlTEditor.getComponent(), "当前URL所有提取URL 减去 已经访问过的URL"); //显示在这个URL中找到的Path 且还没有访问过的URL
        tabs.addTab("PathTreeInfo",null, hostPathTreeTEditor.getComponent(), "当前目前的路径树信息");
        return tabs;
    }

    /**
     * 清空当前Msg tabs中显示的数据
     */
    private static void clearTabsMsgData() {
        findInfoTextPane.setText("");
        respFindUrlTEditor.setText(new byte[0]);
        respFindPathTEditor.setText(new byte[0]);
        directPath2UrlTEditor.setText(new byte[0]);
        smartPath2UrlTEditor.setText(new byte[0]);
        unvisitedUrlTEditor.setText(new byte[0]);
        hostPathTreeTEditor.setText(new byte[0]);
    }


    /**
     * 鼠标点击或键盘移动到行时,自动更新下方的msgTab
     */
    private void hostTableAddActionSetMsgTabData() {
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
        clearTabsMsgData();

        //1、获取当前行的 id 号
        String rootUrl = null;
        try {
            //实现排序后 视图行 数据的正确获取
            rootUrl = UiUtils.getStringAtActualRow(baseHostMsgTableUI, row, 1);
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[!] Table get Value At Row [%s] Error:%s", row, e.getMessage() ));
        }

        if (CastUtils.isEmptyObj(rootUrl)) return;

        //查询路径树信息 并美化输出
        PathTreeModel pathTreeModel = PathTreeTable.fetchPathTreeByRootUrl(rootUrl);
        if (pathTreeModel!=null){
            JSONObject pathTree = pathTreeModel.getPathTree();
            String prettyJson = JSON.toJSONString(pathTree, JSONWriter.Feature.PrettyFormat);
            hostPathTreeTEditor.setText(prettyJson.getBytes());
        }

        //查询详细数据
        TableTabDataModelBasicHost tabDataModel = TableLineDataModelBasicHostSQL.fetchResultByRootUrl(rootUrl);
        if (tabDataModel != null) {
            //格式化为可输出的类型
            String findInfo = CastUtils.infoJsonArrayFormatHtml(tabDataModel.getFindInfo());
            String findUrl = CastUtils.stringJsonArrayFormat(tabDataModel.getFindUrl());
            String findPath = CastUtils.stringJsonArrayFormat(tabDataModel.getFindPath());
            String findApi = CastUtils.stringJsonArrayFormat(tabDataModel.getFindApi());
            String pathToUrl = CastUtils.stringJsonArrayFormat(tabDataModel.getPathToUrl());
            String unvisitedUrl = CastUtils.stringJsonArrayFormat(tabDataModel.getUnvisitedUrl());

            findInfoTextPane.setText(findInfo);
            respFindUrlTEditor.setText(findUrl.getBytes());
            respFindPathTEditor.setText(findPath.getBytes());
            directPath2UrlTEditor.setText(findApi.getBytes());
            smartPath2UrlTEditor.setText(pathToUrl.getBytes());
            unvisitedUrlTEditor.setText(unvisitedUrl.getBytes());
        }
    }

}


