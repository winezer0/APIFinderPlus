package utils;

import database.AnalyseHostResultTable;
import database.AnalyseUrlResultTable;
import model.FindPathModel;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URL;
import java.util.*;
import java.util.List;

import static utils.BurpPrintUtils.*;

public class UiUtils {
    public static ImageIcon getImageIcon(String iconPath, int xWidth, int yWidth){
        // 根据按钮的大小缩放图标
        URL iconURL = UiUtils.class.getResource(iconPath);
        ImageIcon originalIcon = new ImageIcon(iconURL);
        Image img = originalIcon.getImage();
        Image newImg = img.getScaledInstance(xWidth, yWidth, Image.SCALE_SMOOTH);
        return new ImageIcon(newImg);
    }

    public static ImageIcon getImageIcon(String iconPath){
        // 根据按钮的大小缩放图标
        URL iconURL = UiUtils.class.getResource(iconPath);
        ImageIcon originalIcon = new ImageIcon(iconURL);
        Image img = originalIcon.getImage();
        Image newImg = img.getScaledInstance(17, 17, Image.SCALE_SMOOTH);
        return new ImageIcon(newImg);
    }

    public static String encodeForHTML(String input) {
        if(input == null) {
            return "";
        }
        return input.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
                .replace("/", "&#x2F;");
    }

    /**
     * 获取当前显示行的 number
     */
    public static int getIdAtActualRow(JTable table, int row, int columnIndex) {
        TableRowSorter<DefaultTableModel> sorter = (TableRowSorter<DefaultTableModel>) table.getRowSorter();
        int modelRow = sorter.convertRowIndexToModel(row);
        int id = (int) table.getModel().getValueAt(modelRow, columnIndex);
        return id;
    }


    /**
     * 批量获取所有行列表相关的 numbers 列表 默认在第1列
     */
    public static List<Integer> getIdsAtActualRows(JTable table, int[] selectedRows, int columnIndex) {
        List<Integer> ids = new ArrayList<>();
        if (selectedRows.length > 0) {
            for (int selectedRow : selectedRows) {
                if (selectedRow != -1){
                    ids.add(getIdAtActualRow(table, selectedRow, columnIndex));
                }
            }
        }
        return ids;
    }

    /**
     * 获取当前显示行的 String
     */
    public static String getStringAtActualRow(JTable table, int row, int columnIndex) {
        // 获取实际的行索引，因为JTable的 getSelectedRows 返回的是视图索引
        TableRowSorter<DefaultTableModel> sorter = (TableRowSorter<DefaultTableModel>) table.getRowSorter();
        int modelRow = sorter.convertRowIndexToModel(row);
        String url = (String) table.getModel().getValueAt(modelRow, columnIndex);
        return url;
    }


    /**
     * 批量获取所有行列表相关的 String 列表
     */
    public static List<String> getStringListAtActualRows(JTable table, int[] selectedRows, int columnIndex) {
        List<String> urls = new ArrayList<>();
        if (selectedRows.length > 0){
            // 遍历所有选定的行
            for (int selectedRow : selectedRows) {
                if (selectedRow != -1)
                    urls.add(getStringAtActualRow(table, selectedRow, columnIndex));
            }
        }
        return urls;
    }



    /**
     * 把字符串传递到系统剪贴板
     * @param text
     */
    public static void copyToSystemClipboard(String text) {
        // 创建一个StringSelection对象，传入要复制的文本
        StringSelection stringSelection = new StringSelection(text);
        // 获取系统剪贴板
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        // 将数据放到剪贴板上
        clipboard.setContents(stringSelection, null);
        stdout_println(LOG_DEBUG, "Text copied to clipboard.");
    }

    /**
     * 显示消息到弹出框
     * @param text
     */
    public static void showOneMsgBoxToCopy(String text, String title) {
        // 创建一个JTextArea
        JTextArea textArea = new JTextArea(text);
        textArea.setLineWrap(true); // 自动换行
        textArea.setWrapStyleWord(true); // 断行不断字
        textArea.setEditable(true); // 设置为不可编辑
        textArea.setCaretPosition(0); // 将插入符号位置设置在文档开头，这样滚动条会滚动到顶部

        // 使JTextArea能够被复制
        textArea.setSelectionStart(0);
        textArea.setSelectionEnd(textArea.getText().length());

        // 将JTextArea放入JScrollPane
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setPreferredSize(new Dimension(350, 150)); // 设定尺寸

        // 弹出一个包含滚动条的消息窗口
        //String title = "提取url成功";
        JOptionPane.showMessageDialog(
                null,
                scrollPane,
                title,
                JOptionPane.INFORMATION_MESSAGE
        );
    }



    /**
     * 为 数据模型创建捆绑的 tableUI 支持内容悬浮提示
     */
    public static JTable creatTableUiWithTips(DefaultTableModel tableModel) {
        JTable tableUI = new JTable(tableModel) {
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

        return tableUI;
    }

    /**
     * 为表头添加点击排序功能
     */
    public static void tableAddActionSortByHeader(JTable tableUI,DefaultTableModel tableModel) {
        //为 table添加排序功能
        //创建并设置 TableRowSorter
        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(tableModel);
        tableUI.setRowSorter(sorter);

        // 设置列类型和比较器
        for (int i = 0; i < tableModel.getColumnCount(); i++) {
            //Comparator.naturalOrder() 使用自然排序 是 Java 8 引入的一个实用方法，按字母顺序（对于字符串）或数值大小（对于数字类型）。
            Comparator<?> comparator = Comparator.naturalOrder();
            // 如果比较器不是 null，则设置该比较器
            sorter.setComparator(i, comparator);
        }

        // 监听表头点击事件
        tableUI.getTableHeader().addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int viewIndex = tableUI.columnAtPoint(e.getPoint());
                if (viewIndex >= 0) {
                    int modelIndex = tableUI.convertColumnIndexToModel(viewIndex);
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
     *  设置 table 的指定列的最大宽度
     */
    public static void tableSetColumnMaxWidth(JTable tableUI, int columnIndex, int maxWidth) {
        // 获取表格的列数
        tableUI.getColumnModel().getColumn(columnIndex).setMaxWidth(maxWidth);
    }

    /**
     * 设置 table 的指定列的最小宽度
     */
    public static void tableSetColumnMinWidth(JTable tableUI, int columnIndex, int minWidth) {
        // 获取表格的列数
        tableUI.getColumnModel().getColumn(columnIndex).setMinWidth(minWidth);
    }

    /**
     * 为UI的指定列设置左对齐，其他的设置居中对齐
     */
    public static void tableSetColumnsAlignRender(JTable tableUI, List<Integer> leftColumns) {
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer(); //居中对齐的单元格渲染器
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);

        DefaultTableCellRenderer leftRenderer = new DefaultTableCellRenderer(); //左对齐的单元格渲染器
        leftRenderer.setHorizontalAlignment(JLabel.LEFT);

        // 获取表格的列数
        int columnCount = tableUI.getColumnCount();

        // 设置左对齐
        for (Integer leftColumn : leftColumns) {
            if (leftColumn < columnCount)
                tableUI.getColumnModel().getColumn(leftColumn).setCellRenderer(leftRenderer);
        }

        // 设置居中对齐
        for (int column = 0; column < columnCount; column++) {
            if (!leftColumns.contains(column)) {
                if (column < columnCount)
                    tableUI.getColumnModel().getColumn(column).setCellRenderer(centerRenderer);
            }
        }

    }

    /**
     * 弹框 读取用户输入 弹框 输出到用户
     * @param stringList
     * @param itemType
     * @param title
     */
    public static void showInputBoxAndHandle(List<String> stringList, String itemType, String title) {
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
                List<String> urlList = CastUtils.getUniqueLines(inputText);
                if (!urlList.isEmpty()){
                    // 使用SwingWorker来处理数据更新，避免阻塞EDT
                    new SwingWorker<Void, Void>() {
                        @Override
                        protected Void doInBackground() throws Exception {
                            List<FindPathModel> findPathModelList = new ArrayList<FindPathModel>();
                            Set<String> pathSet = new HashSet<>();
                            Set<String> urlSet;
                            switch (itemType){
                                case "calcSingleLayerNodeItemOnUrl":
                                    //基于pathSet和用户输入组合URL
                                    findPathModelList = AnalyseUrlResultTable.fetchPathDataByMsgHashList(stringList);
                                    pathSet = FindPathModel.getSingleLayerPathSet(findPathModelList);

                                    urlSet = new LinkedHashSet<>();
                                    for (String prefix : urlList) {
                                        List<String> urls = AnalyseInfoUtils.concatUrlAddPath(prefix, new ArrayList<>(pathSet));
                                        if (urls.size() > 0) urlSet.addAll(urls);
                                    }
                                    //直接复制到用户的粘贴板
                                    copyToSystemClipboard(String.join("\n", urlSet));
                                    //弹框让用户查看
                                    showOneMsgBoxToCopy(String.join("\n", urlSet), "单层路径生成URL");
                                    break;
                                case "calcSingleLayerNodeItemOnHost":
                                    //基于pathSet和用户输入组合URL
                                    findPathModelList = AnalyseHostResultTable.fetchPathDataByRootUrl(stringList);
                                    pathSet = FindPathModel.getSingleLayerPathSet(findPathModelList);

                                    urlSet = new LinkedHashSet<>();
                                    for (String prefix : urlList) {
                                        List<String> urls = AnalyseInfoUtils.concatUrlAddPath(prefix, new ArrayList<>(pathSet));
                                        if (urls.size() > 0) urlSet.addAll(urls);
                                    }
                                    //直接复制到用户的粘贴板
                                    copyToSystemClipboard(String.join("\n", urlSet));
                                    //弹框让用户查看
                                    showOneMsgBoxToCopy(String.join("\n", urlSet), "单层路径生成URL");
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
     * 创建常用的开关UI
     */
    public static JToggleButton getToggleButtonByDefaultValue(boolean IsOpenDefault) {
        JToggleButton toggleButton;
        //根据默认条件设置UI
        if (IsOpenDefault){
            toggleButton = new JToggleButton(UiUtils.getImageIcon("/icon/openButtonIcon.png", 40, 24));
            toggleButton.setSelectedIcon(UiUtils.getImageIcon("/icon/shutdownButtonIcon.png", 40, 24));
        }else {
            toggleButton = new JToggleButton(UiUtils.getImageIcon("/icon/shutdownButtonIcon.png", 40, 24));
            toggleButton.setSelectedIcon(UiUtils.getImageIcon("/icon/openButtonIcon.png", 40, 24));
        }

        toggleButton.setPreferredSize(new Dimension(50, 24));
        toggleButton.setBorder(null);  // 设置无边框
        toggleButton.setFocusPainted(false);  // 移除焦点边框
        toggleButton.setContentAreaFilled(false);  // 移除选中状态下的背景填充

        return toggleButton;
    }
}
