package ui;

import burp.*;
import database.*;
import model.*;
import utils.BurpHttpUtils;
import utils.CastUtils;
import utils.UiUtils;

import javax.swing.*;
import javax.swing.Timer;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.*;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutionException;

import static utils.BurpPrintUtils.*;

public class MainPanel extends JPanel implements IMessageEditorController {
    private static volatile MainPanel instance; //实现单例模式

    private static JTable table; //表格UI
    private static DefaultTableModel model; // 存储表格数据

    private static IMessageEditor requestTextEditor;  //请求消息面板
    private static IMessageEditor responseTextEditor; //响应消息面板

    private static JEditorPane findInfoTextPane;  //敏感信息文本面板

    private static ITextEditor findUrlTEditor; //显示找到的URL
    private static ITextEditor findPathTEditor; //显示找到的PATH
    private static ITextEditor findApiTEditor; //基于PATH计算出的URL
    private static ITextEditor pathToUrlTEditor; //基于树算法计算出的URL
    private static ITextEditor unvisitedUrlTEditor; //未访问过的URL

    private static byte[] requestsData; //请求数据,设置为全局变量,便于IMessageEditorController函数调用
    private static byte[] responseData; //响应数据,设置为全局变量,便于IMessageEditorController函数调用
    private static IHttpService iHttpService; //请求服务信息,设置为全局变量,便于IMessageEditorController函数调用

    public static Timer timer;  //定时器 为线程调度提供了一个简单的时间触发机制，广泛应用于需要定时执行某些操作的场景，
    public static LocalDateTime operationStartTime = LocalDateTime.now(); //操作开始时间

    public static MainPanel getInstance() {
        if (instance == null) {
            synchronized (MainPanel.class) {
                if (instance == null) {
                    instance = new MainPanel();
                }
            }
        }
        return instance;
    }

    public MainPanel() {
        // EmptyBorder 四周各有了5像素的空白边距
        setBorder(new EmptyBorder(5, 5, 5, 5));
        ////BorderLayout 将容器分为五个区域：北 南 东 西 中 每个区域可以放置一个组件，
        setLayout(new BorderLayout(0, 0));


        // 主分隔面板
        // JSplitPane可以包含两个（或更多）子组件，允许用户通过拖动分隔条来改变两个子组件的相对大小。
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        // 首行配置面板
        ConfigPanel configPanel = new ConfigPanel();

        // 数据表格
        initDataTableUI();

        // JScrollPane是一个可滚动的视图容器，通常用于包裹那些内容可能超出其显示区域的组件，比如表格(JTable)、文本区(JTextArea)等。
        // 这里，它包裹 table（一个JTable实例），使得当表格内容超出显示范围时，用户可以通过滚动条查看所有数据。
        JScrollPane upScrollPane = new JScrollPane(table);
        // 将upScrollPane作为mainSplitPane的上半部分
        //将包含table的滚动面板的upScrollPane 设置为另一个组件mainSplitPane的上半部分。
        mainSplitPane.setTopComponent(upScrollPane);

        //获取下方的消息面板
        JTabbedPane tabs = getMsgTabs();
        mainSplitPane.setBottomComponent(tabs);

        //组合最终的内容面板
        add(configPanel, BorderLayout.NORTH);
        add(mainSplitPane, BorderLayout.CENTER);

        //初始化表格数据
        initDataTableUIData();

        // 初始化定时刷新页面函数 单位是毫秒
        initTimer(ConfigPanel.timerDelay * 1000);
    }

    /**
     * 初始化 table 数据
     */
    private void initDataTableUIData() {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                //获取所有数据
                ArrayList<TableLineDataModel> allReqAnalyseData  = UnionTableSql.fetchTableLineDataAll();
                //将数据赋值给表模型
                UiUtils.populateModelFromJsonArray(model, allReqAnalyseData);
            }
        });
    }

    /**
     * 初始化Table
     */
    private void initDataTableUI() {
        // 数据展示面板
        model = new DefaultTableModel(new Object[]{
                "id",
                "msg_hash",
                "req_url",
                "req_method",
                "resp_status",
                "resp_length",
                "find_url_num",
                "find_path_num",
                "find_info_num",
                "find_api_num",
                "path_to_url_num",
                "unvisited_url_num",
                "run_status",
                "basic_path_num",
                "req_source"
        }, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                // This will make all cells of the table non-editable
                return false;
            }
        };

        table = new JTable(model){
            //通过匿名内部类创建JTable，用于在不单独创建一个子类的情况下，覆写或添加JTable的行为。
            //覆写JTable的getToolTipText(MouseEvent e)方法。这个方法决定了当鼠标悬停在表格的某个单元格上时，将显示的工具提示文本内容。
            @Override
            public String getToolTipText(MouseEvent e) {
                int row = rowAtPoint(e.getPoint());
                int col = columnAtPoint(e.getPoint());
                //通过调用rowAtPoint(e.getPoint())和columnAtPoint(e.getPoint())方法，根据鼠标事件的坐标找到对应的行号和列号。
                //检查行号和列号是否有效（大于-1），如果是，则获取该单元格的值
                if (row > -1 && col > -1) {
                    Object value = getValueAt(row, col);
                    return value == null ? null : value.toString();
                }
                //如果找不到有效的行或列，最终调用超类的getToolTipText(e)方法，保持默认行为
                return super.getToolTipText(e);
            }
        };

        // 设置列选中模式
        //  SINGLE_SELECTION：单行选择模式
        //  使用 int selectedRow = table.getSelectedRow(); 获取行号
        //  MULTIPLE_INTERVAL_SELECTION： 多行选定, 可以选择Shift连续|Ctrl不连续的区间。
        //  SINGLE_INTERVAL_SELECTION：   多行选定,但是必须选择连续的区间
        //  多选模式下调用应该调用 int[] rows = table.getSelectedRows(); 如果调用 getSelectedRow 只会获取第一个选项
        //int listSelectionModel = ListSelectionModel.SINGLE_SELECTION;
        int listSelectionModel = ListSelectionModel.MULTIPLE_INTERVAL_SELECTION;
        table.setSelectionMode(listSelectionModel);

        //添加表头排序功能
        tableAddActionSortByHeader();

        //设置表格每列的宽度
        tableSetColumnsWidth();

        //设置表格每列的对齐设置
        tableSetColumnsRender();

        //为表格添加点击显示下方的消息动作
        tableAddActionSetMsgTabData();

        //为表的每一行添加右键菜单
        tableAddRightClickMenu(listSelectionModel);
    }

    /**
     * 为 table 设置每一列的 右键菜单
     */
    private void tableAddRightClickMenu(int listSelectionModel) {
        // 创建右键菜单
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem copyUrlItem = new JMenuItem("复制请求URL", UiUtils.getImageIcon("/icon/urlIcon.png", 15, 15));
        JMenuItem deleteItem = new JMenuItem("删除数据行", UiUtils.getImageIcon("/icon/deleteButton.png", 15, 15));
        JMenuItem ClearUnVisitedItem = new JMenuItem("清空未访问URL列表", UiUtils.getImageIcon("/icon/deleteButton.png", 15, 15));
        JMenuItem IgnoreUnVisitedItem = new JMenuItem("写入未访问URL列表", UiUtils.getImageIcon("/icon/editButton.png", 15, 15));
        IgnoreUnVisitedItem.setToolTipText("当访问URL后依然无法过滤时使用");

        JMenuItem addUrlPathToRecordPathItem = new JMenuItem("添加PATH到PathTree", UiUtils.getImageIcon("/icon/customizeIcon.png", 15, 15));
        JMenuItem removeHostFromPathTreeItem = new JMenuItem("清空HOST对应PathTree", UiUtils.getImageIcon("/icon/customizeIcon.png", 15, 15));

        JMenuItem updateUnVisitedItem = new JMenuItem("更新未访问URL列表", UiUtils.getImageIcon("/icon/refreshButton2.png", 15, 15));
        JMenuItem addRootUrlToBlackItem = new JMenuItem("添加到RootUrl黑名单", UiUtils.getImageIcon("/icon/noFindUrlFromJS.png", 15, 15));

        popupMenu.add(copyUrlItem);
        popupMenu.add(deleteItem);
        popupMenu.add(ClearUnVisitedItem);
        popupMenu.add(IgnoreUnVisitedItem);
        popupMenu.add(addUrlPathToRecordPathItem);
        popupMenu.add(removeHostFromPathTreeItem);
        popupMenu.add(updateUnVisitedItem);
        popupMenu.add(addRootUrlToBlackItem);

        // 将右键菜单添加到表格
        table.setComponentPopupMenu(popupMenu);

        // 添加 copyUrlItem 事件监听器
        copyUrlItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //单行模式下的调用
                if (listSelectionModel == ListSelectionModel.SINGLE_SELECTION){
                    int selectedRow = table.getSelectedRow();
                    if (selectedRow != -1) {
                        String url = UiUtils.getUrlAtActualRow(table, selectedRow);
                        UiUtils.copyToSystemClipboard(url);
                    }
                }

                //多行模式下的调用
                if (listSelectionModel == ListSelectionModel.MULTIPLE_INTERVAL_SELECTION){
                    int[] selectedRows = table.getSelectedRows();
                    List<String> urls = UiUtils.getUrlsAtActualRows(table,selectedRows);
                    if (!urls.isEmpty())
                        UiUtils.copyToSystemClipboard(String.join("\n", urls));
                }
            }
        });

        // 添加 deleteItem 事件监听器
        deleteItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
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

                //多行选定模式
                if (listSelectionModel == ListSelectionModel.MULTIPLE_INTERVAL_SELECTION) {
                    int[] selectedRows = table.getSelectedRows();
                        List<Integer> ids = UiUtils.getIdsAtActualRows(table, selectedRows);

                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                UnionTableSql.deleteDataByIds(ids, ReqDataTable.tableName);
                                refreshTableModel(false);
                                return null;
                            }
                        }.execute();

                }
            }
        });

        // 添加 ClearUnVisitedItem 事件监听器
        ClearUnVisitedItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //行选择模式
                if (listSelectionModel == ListSelectionModel.SINGLE_SELECTION) {
                    int selectedRow = table.getSelectedRow();
                    if (selectedRow != -1) {
                        String msgHash = UiUtils.getMsgHashAtActualRow(table, selectedRow);
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                AnalyseResultTable.clearUnVisitedUrlsByMsgHash(msgHash);
                                refreshTableModel(false);
                                return null;
                            }
                        }.execute();
                    }
                }

                //多行选定模式
                if (listSelectionModel == ListSelectionModel.MULTIPLE_INTERVAL_SELECTION) {
                    int[] selectedRows = table.getSelectedRows();
                    List<String> msgHashList =  UiUtils.getMsgHashListAtActualRows(table, selectedRows);
                    if (!msgHashList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                AnalyseResultTable.clearUnVisitedUrlsByMsgHashList(msgHashList);
                                refreshTableModel(false);
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        // 添加 ClearUnVisitedItem 事件监听器
        IgnoreUnVisitedItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (listSelectionModel == ListSelectionModel.SINGLE_SELECTION) {
                    int selectedRow = table.getSelectedRow();
                    if (selectedRow != -1) {
                        String msgHash = UiUtils.getMsgHashAtActualRow(table, selectedRow);
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                UnVisitedUrlsModel unVisitedUrlsModel= AnalyseResultTable.fetchUnVisitedUrlsByMsgHash(msgHash);
                                List<String> unvisitedUrls = unVisitedUrlsModel.getUnvisitedUrls();
                                RecordUrlTable.batchInsertOrUpdateAccessedUrls(unvisitedUrls, 299);
                                AnalyseResultTable.clearUnVisitedUrlsByMsgHash(msgHash);
                                refreshTableModel(false);
                                return null;
                            }
                        }.execute();
                    }
                }

                //多行选定模式
                if (listSelectionModel == ListSelectionModel.MULTIPLE_INTERVAL_SELECTION) {
                    int[] selectedRows = table.getSelectedRows();
                    List<String> msgHashList =  UiUtils.getMsgHashListAtActualRows(table, selectedRows);
                    if (!msgHashList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                //获取所有msgHash相关的结果
                                List<UnVisitedUrlsModel> unVisitedUrlsModels = AnalyseResultTable.fetchUnVisitedUrlsByMsgHashList(msgHashList);

                                //整合所有结果URL到一个Set
                                Set<String> unvisitedUrlsSet = new HashSet<>();
                                for (UnVisitedUrlsModel unVisitedUrlsModel:unVisitedUrlsModels){
                                    List<String> unvisitedUrls = unVisitedUrlsModel.getUnvisitedUrls();
                                    unvisitedUrlsSet.addAll(unvisitedUrls);
                                }

                                //批量插入所有URL
                                RecordUrlTable.batchInsertOrUpdateAccessedUrls(new ArrayList<>(unvisitedUrlsSet), 299);
                                //批量删除所有msgHashList
                                AnalyseResultTable.clearUnVisitedUrlsByMsgHashList(msgHashList);
                                refreshTableModel(false);
                                return null;
                            }
                        }.execute();

                    }
                }
            }
        });

        // 添加 addUrlPathToRecordPathItem 事件监听器
        addUrlPathToRecordPathItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (listSelectionModel >= 0) {
                    int[] selectedRows = table.getSelectedRows();
                    List<String> urlList =  UiUtils.getUrlsAtActualRows(table, selectedRows);
                    if (!urlList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                RecordPathTable.batchInsertOrUpdateSuccessUrl(urlList, 299);
                                refreshTableModel(false);
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        // 添加 removeHostFromPathTreeItem 事件监听器
        removeHostFromPathTreeItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (listSelectionModel>=0) {
                    int[] selectedRows = table.getSelectedRows();
                    List<String> urlList =  UiUtils.getUrlsAtActualRows(table, selectedRows);
                    if (!urlList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                UnionTableSql.deleteDataByUrlToHosts(urlList, PathTreeTable.tableName);
                                UnionTableSql.deleteDataByUrlToHosts(urlList, RecordPathTable.tableName);
                                refreshTableModel(false);
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

        // 添加 updateUnVisitedItem 事件监听器
        updateUnVisitedItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (listSelectionModel >= 0) {
                    int[] selectedRows = table.getSelectedRows();
                    List<String> msgHashList =  UiUtils.getMsgHashListAtActualRows(table, selectedRows);
                    if (!msgHashList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                updateUnVisitedUrls(msgHashList);
                                refreshTableModel(false);
                                return null;
                            }
                        }.execute();

                    }
                }
            }
        });

        // 添加 removeHostFromPathTreeItem 事件监听器
        addRootUrlToBlackItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //多行选定模式
                if (listSelectionModel>=0) {
                    int[] selectedRows = table.getSelectedRows();
                    List<String> urlList =  UiUtils.getUrlsAtActualRows(table, selectedRows);
                    List<String> msgHashList =  UiUtils.getMsgHashListAtActualRows(table, selectedRows);
                    if (!urlList.isEmpty()){
                        // 使用SwingWorker来处理数据更新，避免阻塞EDT
                        new SwingWorker<Void, Void>() {
                            @Override
                            protected Void doInBackground() throws Exception {
                                //1、加入到黑名单列表
                                Set<String> rootUrlSet = new HashSet<String>();
                                for (String url:urlList){
                                    HttpUrlInfo urlInfo = new HttpUrlInfo(url);
                                    rootUrlSet.add(urlInfo.getRootUrl());
                                }
                                //合并原来的列表
                                rootUrlSet.addAll( BurpExtender.CONF_BLACK_URL_ROOT);
                                BurpExtender.CONF_BLACK_URL_ROOT = new ArrayList<>(rootUrlSet);
                                //不合并原来的列表
                                //BurpExtender.CONF_BLACK_URL_ROOT.addAll(rootUrlSet);

                                //保存Json
                                FingerConfigTab.autoSaveConfigJson();

/*
                                //2、删除对应的 结果数据 //TODO 不完善 应该用 HOST删除,但是没有HOST列
                                UnionTableSql.deleteDataByMsgHashList(msgHashList, ReqDataTable.tableName);
                                UnionTableSql.deleteDataByMsgHashList(msgHashList, AnalyseResultTable.tableName);
                                refreshTableModel(false);
*/
                                return null;
                            }
                        }.execute();
                    }
                }
            }
        });

    }


    /**
     * 为 table 设置每一列的 宽度
     */
    private void tableSetColumnsWidth() {
        //设置数据表的宽度 //前两列设置宽度 30px、60px
        tableSetColumnMaxWidth(0, 50);
        tableSetColumnMaxWidth(1, 100);
        tableSetColumnMinWidth(2, 300);
//        tableSetColumnMinWidth(11, 50);
//        tableSetColumnMinWidth(12, 50);
    }

    /**
     * 为 table 设置每一列的对齐方式
     */
    private void tableSetColumnsRender() {
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer(); //居中对齐的单元格渲染器
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);

        DefaultTableCellRenderer leftRenderer = new DefaultTableCellRenderer(); //左对齐的单元格渲染器
        leftRenderer.setHorizontalAlignment(JLabel.LEFT);

        List<Integer> leftColumns = Arrays.asList(0, 1, 2);
        tableSetColumnRenders(leftColumns, leftRenderer);

        List<Integer> centerColumns = Arrays.asList(3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14);
        tableSetColumnRenders(centerColumns, centerRenderer);

    }

    /**
     * 鼠标点击或键盘移动到行时,自动更新下方的msgTab
     */
    private void tableAddActionSetMsgTabData() {
        //为表格 添加 鼠标监听器
        //获取点击事件发生时鼠标所在行的索引 根据选中行的索引来更新其他组件的状态或内容。
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                SwingUtilities.invokeLater(new Runnable() {
                    public void run() {
                        try {
                            int row = table.rowAtPoint(e.getPoint());
                            if (row >= 0) {
                                updateComponentsBasedOnSelectedRow(row);
                            }
                        }catch (Exception ef) {
                            BurpExtender.getStderr().println("[-] Error click table: " + table.rowAtPoint(e.getPoint()));
                            ef.printStackTrace(BurpExtender.getStderr());
                        }
                    }
                });
            }
        });

        //为表格 添加 键盘按键释放事件监听器
        //获取按键事件发生时鼠标所在行的索引 根据选中行的索引来更新其他组件的状态或内容。
        table.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                //关注向上 和向下 的按键事件
                if (e.getKeyCode() == KeyEvent.VK_UP || e.getKeyCode() == KeyEvent.VK_DOWN) {
                    SwingUtilities.invokeLater(new Runnable() {
                        public void run() {
                            try {
                                int row = table.getSelectedRow();
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
     * 为表头添加点击排序功能
     */
    private void tableAddActionSortByHeader() {
        //为 table添加排序功能
        //创建并设置 TableRowSorter
        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(model);
        table.setRowSorter(sorter);

        // 设置列类型和比较器
        for (int i = 0; i < model.getColumnCount(); i++) {
            //Comparator.naturalOrder() 使用自然排序 是 Java 8 引入的一个实用方法，按字母顺序（对于字符串）或数值大小（对于数字类型）。
            Comparator<?> comparator = Comparator.naturalOrder();
            // 如果比较器不是 null，则设置该比较器
            sorter.setComparator(i, comparator);
        }

        // 监听表头点击事件
        table.getTableHeader().addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int viewIndex = table.columnAtPoint(e.getPoint());
                if (viewIndex >= 0) {
                    int modelIndex = table.convertColumnIndexToModel(viewIndex);
                    // 获取当前列的排序模式
                    List<? extends RowSorter.SortKey> currentSortKeys = sorter.getSortKeys();
                    RowSorter.SortKey currentSortKey = null;

                    // 遍历当前排序键列表，查找当前列的排序键
                    for (RowSorter.SortKey key : currentSortKeys) {
                        if (key.getColumn() == modelIndex) {
                            currentSortKey = key;
                            break;
                        }
                    }

                    // 确定新的排序类型
                    SortOrder newSortOrder;
                    if (currentSortKey == null) {
                        // 如果当前列未排序，则默认为升序
                        newSortOrder = SortOrder.ASCENDING;
                    } else {
                        // 如果当前列已排序，改变排序方向
                        newSortOrder = currentSortKey.getSortOrder() == SortOrder.ASCENDING ?
                                SortOrder.DESCENDING : SortOrder.ASCENDING;
                    }

                    // 清除旧的排序
                    sorter.setSortKeys(null);

                    // 应用新的排序
                    List<RowSorter.SortKey> newSortKeys = new ArrayList<>();
                    newSortKeys.add(new RowSorter.SortKey(modelIndex, newSortOrder));
                    sorter.setSortKeys(newSortKeys);
                }
            }
        });
    }

    /**
     * 设置 table 的指定列的最小宽度
     * @param columnIndex
     * @param minWidth
     */
    private void tableSetColumnMinWidth(int columnIndex, int minWidth) {
        table.getColumnModel().getColumn(columnIndex).setMinWidth(minWidth);
    }

    /**
     *  设置 table 的指定列的最大宽度
     * @param columnIndex
     * @param maxWidth
     */
    private void tableSetColumnMaxWidth(int columnIndex, int maxWidth) {
        table.getColumnModel().getColumn(columnIndex).setMaxWidth(maxWidth);
    }

    /**
     * 设置指定多列的样式
     * @param columns
     * @param renderer
     */
    private void tableSetColumnRenders(List<Integer> columns, DefaultTableCellRenderer renderer) {
        for (Integer column : columns) {
            table.getColumnModel().getColumn(column).setCellRenderer(renderer);
        }
    }

    /**
     * 初始化任务定时器
     * @param delay
     */
    private void initTimer(int delay) {
        // 创建一个每10秒触发一次的定时器
        //int delay = 10000; // 延迟时间，单位为毫秒
        timer = new Timer(delay, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (IProxyScanner.executorService == null || IProxyScanner.executorService.getActiveCount() < 3) {
                    //stdout_println(LOG_DEBUG, String.format(String.format("[*] 当前进程数量[%s]", IProxyScanner.executorService.getActiveCount())) );
                    boolean updateUnVisited = ConfigPanel.refreshUnvisitedButton.isSelected();
                    refreshAllUnVisitedUrlsAndTableUI(true, updateUnVisited);
                }
            }
        });

        // 启动定时器
        timer.start();
    }

    /**
     * 初始化创建表格下方的消息内容面板
     */
    private JTabbedPane getMsgTabs() {
        IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();

        // 将 结果消息面板 添加到窗口下方
        JTabbedPane tabs = new JTabbedPane();
        // 请求的面板
        requestTextEditor = callbacks.createMessageEditor(this, false);
        // 响应的面板
        responseTextEditor = callbacks.createMessageEditor(this, false);

        //可以滚动的结果面板
        findInfoTextPane = new JEditorPane("text/html", "");
        JScrollPane findInfoTextScrollPane = new JScrollPane(findInfoTextPane);

        // 提取到URL的面板
        findUrlTEditor = callbacks.createTextEditor();
        findPathTEditor = callbacks.createTextEditor();
        findApiTEditor = callbacks.createTextEditor();
        pathToUrlTEditor = callbacks.createTextEditor();
        unvisitedUrlTEditor = callbacks.createTextEditor();

        tabs.addTab("Request", requestTextEditor.getComponent()); //显示原始请求
        tabs.addTab("Response", responseTextEditor.getComponent()); //显示原始响应

        tabs.addTab("findInfo", findInfoTextScrollPane); //显示提取的信息

        tabs.addTab("findUrl", findUrlTEditor.getComponent()); //显示在这个URL中找到的PATH
        tabs.addTab("findPath", findPathTEditor.getComponent()); //显示在这个URL中找到的PATH
        tabs.addTab("findApi", findApiTEditor.getComponent()); //显示在这个URL中找到的PATH
        tabs.addTab("pathToUrl", pathToUrlTEditor.getComponent()); //显示在这个URL中找到的PATH

        tabs.addTab("unvisitedUrl", unvisitedUrlTEditor.getComponent()); //显示在这个URL中找到的Path 且还没有访问过的URL

        return tabs;
    }

    /**
     * 更新表格行对应的下方数据信息
     * @param row
     */
    private void updateComponentsBasedOnSelectedRow(int row) {
        clearTabsMsgData();

        //1、获取当前行的msgHash
        String msgHash = null;
        try {
            //msgHash = (String) table.getModel().getValueAt(row, 1);
            //stdout_println(String.format("当前点击第[%s]行 获取 msgHash [%s]",row, msgHash));

            //实现排序后 视图行 数据的正确获取
            msgHash = UiUtils.getMsgHashAtActualRow(table, row);
        } catch (Exception e) {
            stderr_println(String.format("[!] Table get Value At Row [%s] Error:%s", row, e.getMessage() ));
        }

        if (msgHash == null) return;

        //根据 msgHash值 查询对应的请求体响应体数据
        ReqMsgDataModel msgData = ReqMsgDataTable.fetchMsgDataByMsgHash(msgHash);
        String requestUrl = msgData.getReqUrl();
        requestsData = msgData.getReqBytes();
        responseData = msgData.getRespBytes();

        //显示在UI中
        iHttpService = BurpHttpUtils.getHttpService(requestUrl);
        requestTextEditor.setMessage(requestsData, true);
        responseTextEditor.setMessage(responseData, false);

        //根据 msgHash值 查询api分析结果数据
        TableTabDataModel tabDataModel = AnalyseResultTable.fetchAnalyseResultByMsgHash(msgHash);
        if (tabDataModel != null) {
            //String msgHash = analyseResult.getMsgHash();
            String findInfo = tabDataModel.getFindInfo();
            String findUrl = tabDataModel.getFindUrl();
            String findPath = tabDataModel.getFindPath();
            String findApi = tabDataModel.getFindApi();
            String pathToUrl = tabDataModel.getPathToUrl();
            String unvisitedUrl = tabDataModel.getUnvisitedUrl();

            //格式化为可输出的类型
            findInfo = CastUtils.infoJsonArrayFormatHtml(findInfo);
            findUrl = CastUtils.stringJsonArrayFormat(findUrl);
            findPath = CastUtils.stringJsonArrayFormat(findPath);
            findApi = CastUtils.stringJsonArrayFormat(findApi);
            pathToUrl = CastUtils.stringJsonArrayFormat(pathToUrl);
            unvisitedUrl = CastUtils.stringJsonArrayFormat(unvisitedUrl);

            findInfoTextPane.setText(findInfo);
            findUrlTEditor.setText(findUrl.getBytes());
            findPathTEditor.setText(findPath.getBytes());
            findApiTEditor.setText(findApi.getBytes());
            pathToUrlTEditor.setText(pathToUrl.getBytes());
            unvisitedUrlTEditor.setText(unvisitedUrl.getBytes());
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
                model.setRowCount(0);

                // 获取数据库中的所有ApiDataModels
                ArrayList<TableLineDataModel> apiDataModels =null;

                switch (selectOption) {
                    case "显示有效内容":
                        apiDataModels = UnionTableSql.fetchTableLineDataHasData();
                        break;
                    case "显示敏感内容":
                        apiDataModels = UnionTableSql.fetchTableLineDataHasInfo();
                        break;
                    case "显示未访问路径":
                        apiDataModels = UnionTableSql.fetchTableLineDataHasUnVisitedUrls();
                        break;
                    case "显示无效内容":
                        apiDataModels = UnionTableSql.fetchTableLineDataIsNull();
                        break;
                    case "显示全部内容":
                    default:
                        apiDataModels = UnionTableSql.fetchTableLineDataAll();
                        break;
                }

                // 遍历apiDataModelMap
                for (TableLineDataModel apiDataModel : apiDataModels) {
                    String url = apiDataModel.getReqUrl();
                    //是否包含关键字,当输入了关键字时,使用本函数再次进行过滤
                    if (url.toLowerCase().contains(searchText.toLowerCase())) {
                        Object[] rowData = apiDataModel.toRowDataArray();
                        //model.insertRow(0, rowData); //插入到首行
                        model.insertRow(model.getRowCount(), rowData); //插入到最后一行
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
     * 清理所有数据
     */
    public static void clearModelData(boolean clearAllTable){
        synchronized (model) {
            // 清空model
            model.setRowCount(0);

            //清空记录变量的内容
            IProxyScanner.urlScanRecordMap = new RecordHashMap();
            IProxyScanner.urlAutoRecordMap = new RecordHashMap();

            ConfigPanel.lbRequestCount.setText("0");
            ConfigPanel.lbTaskerCount.setText("0");
            ConfigPanel.lbAnalysisEndCount.setText("0/0");

            //清空数据库内容
            if (clearAllTable) {
                DBService.clearAllTables();
            } else {
                DBService.clearModelTables();
            }
            // 清空检索框的内容
            SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    ConfigPanel.searchField.setText("");
                }
            });

            // 还可以清空编辑器中的数据
            clearTabsMsgData();
        }
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
            instance.refreshTableModel(checkAutoRefreshButtonStatus);
        } catch (Exception ep){
            stderr_println(LOG_ERROR, String.format("[!] 刷新表格发生错误：%s", ep.getMessage()) );
        }

        //建议JVM清理内存
        System.gc();
    }


    private void updateAllUnVisitedUrls(){
        updateUnVisitedUrls(null);
    }
    /**
     * 查询所有UnVisitedUrls并逐个进行过滤, 费内存的操作
     * @param msgHashList updateUnVisitedUrls 目标列表, 为空 为Null时更新全部
     */
    private void updateUnVisitedUrls(List<String> msgHashList) {
        // 使用SwingWorker来处理数据更新，避免阻塞EDT
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                // 获取所有未访问URl 注意需要大于0
                List<UnVisitedUrlsModel> unVisitedUrlsModels;
                if (msgHashList == null || msgHashList.isEmpty()) {
                    //更新所有的结果
                    unVisitedUrlsModels = AnalyseResultTable.fetchAllUnVisitedUrls();
                }else {
                    //仅更新指定 msgHash 对应的未访问URL
                    unVisitedUrlsModels = AnalyseResultTable.fetchUnVisitedUrlsByMsgHashList(msgHashList);
                }

                if (unVisitedUrlsModels.size() > 0) {
                    // 获取所有 已经被访问过得URL列表
                    //List<String> accessedUrls = RecordUrlTable.fetchAllAccessedUrls();
                    //获取所有由reqHash组成的字符串
                    String accessedUrlHashes = UnionTableSql.fetchConcatColumnToString(RecordUrlTable.tableName, RecordUrlTable.urlHashName);
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
                        newUnVisitedUrls = AnalyseInfo.filterFindUrls(urlsModel.getReqUrl(), newUnVisitedUrls, BurpExtender.onlyScopeDomain);
                        urlsModel.setUnvisitedUrls(newUnVisitedUrls);

                        // 执行更新插入数据操作
                        try {
                            AnalyseResultTable.updateUnVisitedUrlsById(urlsModel);
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
        if (!BurpExtender.extensionIsLoading)
            return;

        //设置已加入数据库的数量
        ConfigPanel.lbTaskerCount.setText(String.valueOf(UnionTableSql.getTableCounts(ReqDataTable.tableName)));
        //设置成功分析的数量
        ConfigPanel.lbAnalysisEndCount.setText(String.valueOf(ReqDataTable.getReqDataCountWhereStatusIsEnd()));

        // 刷新页面, 如果自动更新关闭，则不刷新页面内容
        if (checkAutoRefreshButtonStatus && ConfigPanel.getAutoRefreshButtonStatus()) {
            if (Duration.between(operationStartTime, LocalDateTime.now()).getSeconds() > 600) {
                ConfigPanel.setAutoRefreshButtonTrue();
            }
            return;
        }

        // 获取搜索框和搜索选项
        final String searchText = ConfigPanel.searchField.getText();
        final String selectedOption = (String)ConfigPanel.choicesComboBox.getSelectedItem();

        // 使用SwingWorker来处理数据更新，避免阻塞EDT
        SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                try {
                    // 执行耗时的数据操作
                    MainPanel.showDataTableByFilter(selectedOption, searchText.isEmpty() ? "" : searchText);
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
                            model.fireTableDataChanged(); // 通知模型数据发生了变化
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

    /**
     * 清空当前Msg tabs中显示的数据
     */
    private static void clearTabsMsgData() {
        iHttpService = null; // 清空当前显示的项
        requestsData = null;
        responseData = null;

        requestTextEditor.setMessage(new byte[0], true); // 清空请求编辑器
        responseTextEditor.setMessage(new byte[0], false); // 清空响应编辑器

        findInfoTextPane.setText("");
        findUrlTEditor.setText(new byte[0]);
        findPathTEditor.setText(new byte[0]);
        findApiTEditor.setText(new byte[0]);
        pathToUrlTEditor.setText(new byte[0]);
        unvisitedUrlTEditor.setText(new byte[0]);
    }
}


