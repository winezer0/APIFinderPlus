package utils;

import model.TableLineDataModel;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static utils.BurpPrintUtils.*;
import static utils.CastUtils.isEmptyObj;

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
     * 把 jsonArray 赋值到 model 中
     * @param model
     * @param jsonArray
     */
    public static void populateModelFromJsonArray(DefaultTableModel model, ArrayList<TableLineDataModel> jsonArray) {
        if (isEmptyObj(jsonArray)) return;

        Iterator<TableLineDataModel> iterator = jsonArray.iterator();
        while (iterator.hasNext()) {
            TableLineDataModel apiDataModel = iterator.next();
            Object[] rowData = apiDataModel.toRowDataArray();
            model.addRow(rowData);
        }
        //刷新表数据模型
        model.fireTableDataChanged();
    }


    /**
     * 获取当前显示行的ID
     *
     * @param table
     * @param row
     * @return
     */
    public static int getIdAtActualRow(JTable table, int row) {
        TableRowSorter<DefaultTableModel> sorter = (TableRowSorter<DefaultTableModel>) table.getRowSorter();
        int modelRow = sorter.convertRowIndexToModel(row);
        int columnIndex = 0;
        int id = (int) table.getModel().getValueAt(modelRow, columnIndex);
        return id;
    }

    /**
     * 获取当前显示行的hash
     * @param row
     * @return
     */
    public static String getMsgHashAtActualRow(JTable table, int row) {
        TableRowSorter<DefaultTableModel> sorter = (TableRowSorter<DefaultTableModel>) table.getRowSorter();
        int modelRow = sorter.convertRowIndexToModel(row);
        int columnIndex = 2;
        String msgHash = (String) table.getModel().getValueAt(modelRow, columnIndex);
        return msgHash;
    }

    /**
     * 获取当前显示行的 url
     * @param row
     * @return
     */
    public static String getUrlAtActualRow(JTable table, int row) {
        // 获取实际的行索引，因为JTable的 getSelectedRows 返回的是视图索引
        TableRowSorter<DefaultTableModel> sorter = (TableRowSorter<DefaultTableModel>) table.getRowSorter();
        int modelRow = sorter.convertRowIndexToModel(row);
        int columnIndex = 3;
        String url = (String) table.getModel().getValueAt(modelRow, columnIndex);
        return url;
    }

    /**
     * 批量获取所有行列表相关的 Id 列表
     */
    public static List<Integer> getIdsAtActualRows(JTable table, int[] selectedRows) {
        List<Integer> ids = new ArrayList<>();
        if (selectedRows.length > 0) {
            for (int selectedRow : selectedRows) {
                if (selectedRow != -1){
                    ids.add(getIdAtActualRow(table, selectedRow));
                }
            }
        }
        return ids;
    }

    /**
     * 批量获取所有行列表相关的 URl 列表
     */
    public static List<String> getUrlsAtActualRows(JTable table, int[] selectedRows) {
        List<String> urls = new ArrayList<>();
        if (selectedRows.length > 0){
            // 遍历所有选定的行
            for (int selectedRow : selectedRows) {
                if (selectedRow != -1)
                    urls.add(getUrlAtActualRow(table, selectedRow));
            }
        }
        return urls;
    }

    /**
     * 批量获取所有行列表相关的 MsgHash 列表
     */
    public static List<String> getMsgHashListAtActualRows(JTable table, int[] selectedRows) {
        List<String> msgHashList = new ArrayList<>();
        if (selectedRows.length > 0){
            // 遍历所有选定的行
            for (int selectedRow : selectedRows) {
                if (selectedRow != -1)
                    msgHashList.add(getMsgHashAtActualRow(table, selectedRow));
            }
        }
        return msgHashList;
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
}
