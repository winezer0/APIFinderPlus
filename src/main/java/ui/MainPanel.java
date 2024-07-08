package ui;

import burp.*;
import com.alibaba.fastjson2.JSONObject;
import database.*;
import model.RecordHashMap;
import model.TableLineDataModel;
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
    private static ITextEditor smartApiTEditor; //基于树算法计算出的URL
    private static ITextEditor unvisitedUrlTEditor; //未访问过的URL

    private static byte[] requestsData; //请求数据,设置为全局变量,便于IMessageEditorController函数调用
    private static byte[] responseData; //响应数据,设置为全局变量,便于IMessageEditorController函数调用
    private static IHttpService iHttpService; //请求服务信息,设置为全局变量,便于IMessageEditorController函数调用

    public static Timer timer;  //定时器 为线程调度提供了一个简单的时间触发机制，广泛应用于需要定时执行某些操作的场景，
    public static LocalDateTime operationStartTime = LocalDateTime.now(); //操作开始时间

    public static MainPanel getInstance(IBurpExtenderCallbacks callbacks) {
        if (instance == null) {
            synchronized (MainPanel.class) {
                if (instance == null) {
                    instance = new MainPanel(callbacks);
                }
            }
        }
        return instance;
    }

    public MainPanel(IBurpExtenderCallbacks callbacks) {
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
        JTabbedPane tabs = getMsgTabs(callbacks);
        mainSplitPane.setBottomComponent(tabs);

        //组合最终的内容面板
        add(configPanel, BorderLayout.NORTH);
        add(mainSplitPane, BorderLayout.CENTER);

        //初始化表格数据
        initDataTableUIData();

        // 初始化定时刷新页面函数
        initTimer(10000);
    }

    /**
     * 初始化 table 数据
     */
    private void initDataTableUIData() {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                //获取所有数据
                ArrayList<TableLineDataModel> allReqAnalyseData  = UnionTableSql.fetchAllReqDataLeftJoinAnalyseInfo();
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
                "msg_id",
                "msg_hash",
                "req_url",
                "req_method",
                "resp_status_code",
                "req_source",
                "find_url_num",
                "find_path_num",
                "find_info_num",
                "find_api_num",
                "smart_api_num",
                "unvisited_url_num",
                "run_status",
                "basic_path_num",
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

        // SINGLE_SELECTION 设置表格的选择模式为单选
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        //设置表格每列的宽度
        tableSetColumnsWidth();

        //设置表格每列的对齐设置
        tableSetColumnsRender();

        //添加表头排序功能
        tableAddActionSortByHeader();

        //为表格添加点击显示下方的消息动作
        tableAddActionSetMsgTabData();
    }

    /**
     * 为 table 设置每一列的 宽度
     */
    private void tableSetColumnsWidth() {
        //设置数据表的宽度 //前两列设置宽度 30px、60px
        tableSetColumnMaxWidth(0, 50);
        tableSetColumnMaxWidth(1, 100);
        tableSetColumnMinWidth(2, 300);
        tableSetColumnMinWidth(11, 50);
        tableSetColumnMinWidth(12, 50);
    }

    /**
     * 为 table 设置每一列的对齐方式
     */
    private void tableSetColumnsRender() {
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer(); //居中对齐的单元格渲染器
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);

        DefaultTableCellRenderer leftRenderer = new DefaultTableCellRenderer(); //左对齐的单元格渲染器
        leftRenderer.setHorizontalAlignment(JLabel.LEFT);

        List<Integer> leftColumns = Arrays.asList(0, 1, 2, 7, 8, 9, 10, 11, 12);
        tableSetColumnRenders(leftColumns, leftRenderer);

        List<Integer> centerColumns = Arrays.asList(3, 4, 5, 6);
        tableSetColumnRenders(centerColumns, centerRenderer);

        //创建 IsJsFindUrl的独特渲染器
        // IsJsFindUrlRenderer isJsFindUrlRenderer = new IsJsFindUrlRenderer();
        // table.getColumnModel().getColumn(6).setCellRenderer(isJsFindUrlRenderer);

        //创建 havingImportantRenderer的独特渲染器
        //IconTableCellRenderer havingImportantRenderer = new IconTableCellRenderer();
        //table.getColumnModel().getColumn(7).setCellRenderer(havingImportantRenderer);
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
                // 调用刷新表格的方法
                try{
                    instance.refreshTableModel();
                } catch (Exception ep){
                    BurpExtender.getStderr().println("[!] 刷新表格报错， 报错如下：");
                    ep.printStackTrace(BurpExtender.getStderr());
                }
            }
        });

        // 启动定时器
        timer.start();
    }

    /**
     * 初始化创建表格下方的消息内容面板
     * @param callbacks
     * @return
     */
    private JTabbedPane getMsgTabs(IBurpExtenderCallbacks callbacks) {
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
        smartApiTEditor = callbacks.createTextEditor();
        unvisitedUrlTEditor = callbacks.createTextEditor();

        tabs.addTab("Request", requestTextEditor.getComponent()); //显示原始请求
        tabs.addTab("Response", responseTextEditor.getComponent()); //显示原始响应

        tabs.addTab("findInfo", findInfoTextScrollPane); //显示提取的信息

        tabs.addTab("findUrl", findUrlTEditor.getComponent()); //显示在这个URL中找到的PATH
        tabs.addTab("findPath", findPathTEditor.getComponent()); //显示在这个URL中找到的PATH
        tabs.addTab("findApi", findApiTEditor.getComponent()); //显示在这个URL中找到的PATH
        tabs.addTab("smartApi", smartApiTEditor.getComponent()); //显示在这个URL中找到的PATH

        tabs.addTab("unvisitedUrl", unvisitedUrlTEditor.getComponent()); //显示在这个URL中找到的Path 且还没有访问过的URL

        return tabs;
    }

    /**
     * 更新表格行对应的下方数据信息
     * @param row
     */
    private void updateComponentsBasedOnSelectedRow(int row) {
        //1、获取当前行的msgHash
        String msgHash = (String) table.getModel().getValueAt(row, 1);

        //根据 msgHash值 查询对应的请求体响应体数据
        JSONObject msgData = ReqMsgDataTable.fetchMsgDataByMsgHash(msgHash);
        //String msgInfoHash = (String) msgData.get(Constants.MSG_HASH);
        String requestUrl = (String) msgData.get(Constants.REQ_URL);
        requestsData = (byte[]) msgData.get(Constants.REQ_BYTES);
        responseData = (byte[]) msgData.get(Constants.RESP_BYTES);

        //显示在UI中
        iHttpService = UiUtils.getIHttpService(requestUrl);
        requestTextEditor.setMessage(requestsData, true);
        responseTextEditor.setMessage(responseData, false);

        //根据 msgHash值 查询api分析结果数据
        JSONObject analyseResult =  InfoAnalyseTable.fetchAnalyseResultByMsgHash(msgHash);
        if(!analyseResult.isEmpty()){
            //analyseResult.get(Constants.MSG_HASH);
            String findInfo = (String) analyseResult.get(Constants.FIND_INFO);

            String findUrl = (String) analyseResult.get(Constants.FIND_URL);
            String findPath = (String) analyseResult.get(Constants.FIND_PATH);
            String findApi = (String) analyseResult.get(Constants.FIND_API);
            String smartApi = (String) analyseResult.get(Constants.SMART_API);
            String unvisitedUrl = (String) analyseResult.get(Constants.UNVISITED_URL);

            //格式化为可输出的类型
            findInfo = UiUtils.infoJsonArrayFormatHtml(findInfo);
            findUrl = UiUtils.stringJsonArrayFormat(findUrl);
            findPath = UiUtils.stringJsonArrayFormat(findPath);
            findApi = UiUtils.stringJsonArrayFormat(findApi);
            smartApi = UiUtils.stringJsonArrayFormat(smartApi);
            unvisitedUrl = UiUtils.stringJsonArrayFormat(unvisitedUrl);

            findInfoTextPane.setText(findInfo);
            findUrlTEditor.setText(findUrl.getBytes());
            findPathTEditor.setText(findPath.getBytes());
            findApiTEditor.setText(findApi.getBytes());
            smartApiTEditor.setText(smartApi.getBytes());
            unvisitedUrlTEditor.setText(unvisitedUrl.getBytes());
        } else {
            findInfoTextPane.setText("");
            findUrlTEditor.setText("".getBytes());
            findPathTEditor.setText("".getBytes());
            findApiTEditor.setText("".getBytes());
            smartApiTEditor.setText("".getBytes());
            unvisitedUrlTEditor.setText("".getBytes());
        }
    }

    /**
     * 基于过滤选项 和 搜索框内容 显示结果
     * @param selectOption
     * @param searchText
     */
    public static void showDataTableByFilter(String selectOption, String searchText) {
        // 在后台线程获取数据，避免冻结UI
        new SwingWorker<DefaultTableModel, Void>() {
            @Override
            protected DefaultTableModel doInBackground() throws Exception {
                // 构建一个新的表格模型
                model.setRowCount(0);

                // 获取数据库中的所有ApiDataModels
                ArrayList<TableLineDataModel> apiDataModels = UnionTableSql.fetchAllReqDataLeftJoinAnalyseInfo();

                // 遍历apiDataModelMap
                for (TableLineDataModel apiDataModel : apiDataModels) {
                    String url = apiDataModel.getReqUrl();
                    if (selectOption.equals("只看status为200") && !(apiDataModel.getRespStatusCode() == 200)){
                        continue;
//                    } else if (selectOption.equals("只看重点") &&  !apiDataModel.getHavingImportant()) {
//                        continue;
//                    } else if (selectOption.equals("只看敏感内容") && !apiDataModel.getResult().contains("敏感内容")){
//                        continue;
//                    } else if (selectOption.equals("只看敏感路径") && !apiDataModel.getResult().contains("敏感路径")) {
//                        continue;
                    }
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
                    BurpExtender.getStderr().println("[!] showFilter error:");
                    e.printStackTrace(BurpExtender.getStderr());
                }
            }
        }.execute();
    }

    /**
     * 清理所有数据
     */
    public static void clearAllData(){
        synchronized (model) {
            // 清空model
            model.setRowCount(0);

            //清空记录变量的内容
            IProxyScanner.urlScanRecordMap = new RecordHashMap();
            ConfigPanel.lbSuccessCount.setText("0");
            ConfigPanel.lbRequestCount.setText("0");
            ConfigPanel.jsCrawledCount.setText("0/0");
            ConfigPanel.urlCrawledCount.setText("0/0");

            //清空数据库内容
            DBService.clearAllTableData();

            // 清空检索框的内容
            SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    ConfigPanel.searchField.setText("");
                }
            });

            // 还可以清空编辑器中的数据
            MainPanel.requestTextEditor.setMessage(new byte[0], true); // 清空请求编辑器
            MainPanel.responseTextEditor.setMessage(new byte[0], false); // 清空响应编辑器

            MainPanel.findInfoTextPane.setText("");
            MainPanel.findUrlTEditor.setText(new byte[0]);
            MainPanel.findPathTEditor.setText(new byte[0]);
            MainPanel.findApiTEditor.setText(new byte[0]);
            MainPanel.smartApiTEditor.setText(new byte[0]);
            MainPanel.unvisitedUrlTEditor.setText(new byte[0]);

            MainPanel.iHttpService = null; // 清空当前显示的项
            MainPanel.requestsData = null;
            MainPanel.responseData = null;
        }
    }

    /**
     * 定时刷新表数据
     */
    public void refreshTableModel() {
        //设置成功数量
        int successCount = ReqDataTable.getReqDataCount();
        ConfigPanel.lbSuccessCount.setText(String.valueOf(successCount));

        // 刷新页面, 如果自动更新关闭，则不刷新页面内容
        if (ConfigPanel.getFlushButtonStatus()) {
            if (Duration.between(operationStartTime, LocalDateTime.now()).getSeconds() > 600) {
                ConfigPanel.setFlashButtonTrue();
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
                // 执行耗时的数据操作
                MainPanel.showDataTableByFilter(selectedOption, searchText.isEmpty() ? "" : searchText);
                return null;
            }

            @Override
            protected void done() {
                // 更新UI组件
                SwingUtilities.invokeLater(new Runnable() {
                    public void run() {
                        model.fireTableDataChanged(); // 通知模型数据发生了变化，而不是连续插入或删除行
                    }
                });
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


