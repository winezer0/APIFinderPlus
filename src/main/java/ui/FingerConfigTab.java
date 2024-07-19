package ui;

import burp.BurpExtender;
import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONWriter;
import database.Constants;
import model.FingerPrintRule;
import model.FingerPrintRulesWrapper;
import ui.FingerTabRender.ButtonRenderer;
import ui.FingerTabRender.CenterRenderer;
import ui.FingerTabRender.HeaderIconTypeRenderer;
import ui.FingerTabRender.LeftRenderer;
import utils.BurpFileUtils;
import utils.RegularUtils;
import utils.UiUtils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.*;

import static burp.BurpExtender.setActionByRuleInfo;
import static utils.BurpPrintUtils.*;
import static utils.CastUtils.isNotEmptyObj;


public class FingerConfigTab extends JPanel {
    private static DefaultTableModel tableModel;
    //DefaultTableModel 是 Java Swing 库中的一个类，通常用于表格组件（如 JTable）的数据模型。它管理着表格的数据、列名以及对数据的各种操作（如添加行、删除行等）。
    private JTable ruleTable;
    private JDialog editRulePanel;  // 新增：编辑面板
    public static Integer editingRow = null;
    //private JTextField keywordField;  // 新增：编辑面板的文本字段
    private JTextArea keywordField;
    private JTextField describeField;
    private JComboBox<Boolean> isImportantField;
    private JComboBox<String> searchMethodField, locationField, typeField, accuracyFiled;

    public static List<Integer> tableToModelIndexMap = new ArrayList<>();
    public Set<String> uniqueTypes = new LinkedHashSet<>();

    public static final String String_All_Type = "全部类型";


    private static volatile FingerConfigTab instance; //实现单例模式
    public static FingerConfigTab getInstance() {
        if (instance == null) {
            synchronized (FingerConfigTab.class) {
                if (instance == null) {
                    instance = new FingerConfigTab();
                }
            }
        }
        return instance;
    }

    public FingerConfigTab() {
        //在FingerConfigTab类中设置该容器的默认布局为BorderLayout，为后续向容器中添加组件并控制这些组件的布局奠定了基础。这一步是构建用户界面时组织和排列组件的关键步骤之一。
        setLayout(new BorderLayout());

        JPanel toolbar = new JPanel();
        toolbar.setLayout(new BorderLayout());

        // 创建一个面板来放置放在最左边的按钮
        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        // 新增按钮
        JButton addButton = new JButton("新增");
        addButton.setIcon(UiUtils.getImageIcon("/icon/addButtonIcon.png"));
        addButton.setToolTipText("新增指纹规则");
        leftPanel.add(addButton);

        // 居中，设置指纹识别的开关按钮
        JPanel centerPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        // 调整 centerPanel 的位置
        int leftPadding = 150;  // 调整这个值来改变左边距
        centerPanel.setBorder(new EmptyBorder(0, leftPadding, 0, 0));

        // 创建一个面板来放置放在最右边的按钮
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        // 所有指纹和重点指纹的选择
        // 全部按钮
        JButton showAllButton = new JButton("全部");
        showAllButton.setToolTipText("显示全部规则");

        // 检索框
        JTextField searchField = new JTextField(15);
        searchField.setToolTipText("筛选规则关键字");
        // 检索按钮
        JButton searchButton = new JButton();
        searchButton.setIcon(UiUtils.getImageIcon("/icon/searchButton.png"));
        searchButton.setToolTipText("开始筛选");

        // 便捷操作
        JButton convenientOperationButton = new JButton();
        convenientOperationButton.setIcon(UiUtils.getImageIcon("/icon/convenientOperationIcon.png"));
        convenientOperationButton.setToolTipText("便捷操作");
        // 便捷操作按钮点击后弹出选择菜单
        JPopupMenu convenientOperationMenu = new JPopupMenu("便捷操作");
        JMenuItem aboveHighItem = new JMenuItem("只开启精确率为高");
        JMenuItem aboveMediumItem = new JMenuItem("只开启精确率为高、中");
        JMenuItem aboveLowItem = new JMenuItem("只开启精确率为高、中、低");
        convenientOperationMenu.add(aboveHighItem);
        convenientOperationMenu.add(aboveMediumItem);
        convenientOperationMenu.add(aboveLowItem);

        // 更多功能按钮
        JButton moreFunctionsButton = new JButton();
        moreFunctionsButton.setIcon(UiUtils.getImageIcon("/icon/moreButton.png"));
        moreFunctionsButton.setToolTipText("更多功能");
        //更多功能按钮弹出的选项
        JPopupMenu popupMenu = new JPopupMenu("更多功能");
        JMenuItem saveItem = new JMenuItem("保存");
        saveItem.setIcon(UiUtils.getImageIcon("/icon/saveItem.png"));
        saveItem.setToolTipText("保存当前规则到文件");

        JMenuItem importItem = new JMenuItem("导入");
        importItem.setIcon(UiUtils.getImageIcon("/icon/importItem.png"));
        importItem.setToolTipText("从外部文件导入规则");

        JMenuItem exportItem = new JMenuItem("导出");
        exportItem.setIcon(UiUtils.getImageIcon("/icon/exportItem.png"));
        exportItem.setToolTipText("导出当前规则到文件");

        JMenuItem resetItem = new JMenuItem("重置");
        resetItem.setIcon(UiUtils.getImageIcon("/icon/resetItem.png"));
        resetItem.setToolTipText("初始为插件内置规则");
        popupMenu.add(saveItem);
        popupMenu.add(importItem);
        popupMenu.add(exportItem);
        popupMenu.add(resetItem);

        // 布局
        rightPanel.add(showAllButton);
        rightPanel.add(searchField);
        rightPanel.add(searchButton);
        rightPanel.add(convenientOperationButton);
        rightPanel.add(moreFunctionsButton);
        // 将左右面板添加到总的toolbar面板中
        toolbar.add(leftPanel, BorderLayout.WEST);
        toolbar.add(centerPanel, BorderLayout.CENTER);
        toolbar.add(rightPanel, BorderLayout.EAST);

        // 点击“全部“按钮的监听事件
        showAllButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 清除表格的所有行
                tableModel.setRowCount(0);
                // 清空映射
                tableToModelIndexMap.clear();
                // 重新添加匹配搜索文本的行，并更新映射
                int counter=1;
                for (int ruleIndex = 0; ruleIndex < BurpExtender.fingerprintRules.size(); ruleIndex++) {
                    FingerPrintRule rule = BurpExtender.fingerprintRules.get(ruleIndex);
                    // 保存当前规则在模型列表中的索引
                    tableToModelIndexMap.add(ruleIndex);
                    tableModel.addRow(new Object[]{
                            counter, //行号
                            rule.getType(), //规则类型
                            rule.getDescribe(),  //规则描述
                            rule.getIsImportant(),  //规则重要性
                            rule.getAccuracy(),  //危险级别
                            rule.getMatch(), // 获取method信息
                            rule.getLocation(), // 获取location信息
                            String.join(",", rule.getKeyword()),
                            new String[] {"IsOpen", "Edit", "Delete"} // 3个操作按钮
                    });
                    counter ++;
                }
            }
        });


        // 输入”检索区域“的监听事件
        searchField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String searchText = searchField.getText(); // 获取用户输入的搜索文本

                // 清除表格的所有行
                tableModel.setRowCount(0);
                // 清空映射
                tableToModelIndexMap.clear();
                // 重新添加匹配搜索文本的行，并更新映射
                int counter=1;
                for (int i = 0; i < BurpExtender.fingerprintRules.size(); i++) {
                    FingerPrintRule rule = BurpExtender.fingerprintRules.get(i);
                    String keywords = String.join(",", rule.getKeyword()).toLowerCase();
                    if (keywords.contains(searchText.toLowerCase())){
                        // 保存当前规则在模型列表中的索引
                        tableToModelIndexMap.add(i);
                        tableModel.addRow(new Object[]{
                                counter,
                                rule.getType(),
                                rule.getDescribe(),
                                rule.getIsImportant(),
                                rule.getAccuracy(),
                                rule.getMatch(), // 获取method信息
                                rule.getLocation(), // 获取location信息
                                String.join(",", rule.getKeyword()),
                                new String[] {"IsOpen", "Edit", "Delete"} // 操作按钮
                        });
                        counter ++;
                    }
                }
            }
        });

        //点击搜索按钮触发的事件
        searchButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                String searchText = searchField.getText(); // 获取用户输入的搜索文本
                // 清除表格的所有行
                tableModel.setRowCount(0);
                // 清空映射
                tableToModelIndexMap.clear();
                // 重新添加匹配搜索文本的行，并更新映射
                int counter=1;
                for (int i = 0; i < BurpExtender.fingerprintRules.size(); i++) {
                    FingerPrintRule rule = BurpExtender.fingerprintRules.get(i);
                    String keywords = String.join(",", rule.getKeyword()).toLowerCase();
                    if (keywords.contains(searchText.toLowerCase())){
                        // 保存当前规则在模型列表中的索引
                        tableToModelIndexMap.add(i);
                        tableModel.addRow(new Object[]{
                                counter,
                                rule.getType(),
                                rule.getDescribe(),
                                rule.getIsImportant(),
                                rule.getAccuracy(),
                                rule.getMatch(), // 获取method信息
                                rule.getLocation(), // 获取location信息
                                String.join(",", rule.getKeyword()),
                                new String[] {"IsOpen", "Edit", "Delete"} // 操作按钮
                        });
                        counter ++;
                    }
                }
            }
        });


        // 点击“快捷方式”的监听事件
        convenientOperationButton.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                convenientOperationMenu.show(e.getComponent(), e.getX(), e.getY());
            }
        });


        // "只看精确率为低级别以上"按钮的事件
        aboveLowItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 清除表格的所有行
                tableModel.setRowCount(0);
                // 重新添加匹配搜索文本的行
                int counter=1;
                // 清空映射
                tableToModelIndexMap.clear();
                // 重新添加匹配搜索文本的行，并更新映射
                for (int i = 0; i < BurpExtender.fingerprintRules.size(); i++) {
                    FingerPrintRule rule = BurpExtender.fingerprintRules.get(i);
                    // 保存当前规则在模型列表中的索引
                    tableToModelIndexMap.add(i);
                    //低级以上就等于开启所有规则
                    rule.setOpen(true);
                    tableModel.addRow(new Object[]{
                            counter,
                            rule.getType(),
                            rule.getDescribe(),
                            rule.getIsImportant(),
                            rule.getAccuracy(),
                            rule.getMatch(), // 获取method信息
                            rule.getLocation(), // 获取location信息
                            String.join(",", rule.getKeyword()),
                            new String[] {"IsOpen", "Edit", "Delete"} // 操作按钮
                    });
                    counter ++;
                }
                ruleTable.repaint();
            }
        });


        // "只看精确率为高、中"按钮的事件
        aboveMediumItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 清除表格的所有行
                tableModel.setRowCount(0);
                // 清空映射
                tableToModelIndexMap.clear();
                // 重新添加匹配搜索文本的行，并更新映射
                int counter=1;
                for (int i = 0; i < BurpExtender.fingerprintRules.size(); i++) {
                    FingerPrintRule rule = BurpExtender.fingerprintRules.get(i);
                    // 保存当前规则在模型列表中的索引
                    tableToModelIndexMap.add(i);
                    //设置lower级别规则为关闭
                    rule.setOpen(!rule.getAccuracy().equals("lower"));
                    tableModel.addRow(new Object[]{
                            counter,
                            rule.getType(),
                            rule.getDescribe(),
                            rule.getIsImportant(),
                            rule.getAccuracy(),
                            rule.getMatch(), // 获取method信息
                            rule.getLocation(), // 获取location信息
                            String.join(",", rule.getKeyword()),
                            new String[] {"IsOpen", "Edit", "Delete"} // 操作按钮
                    });
                    counter ++;
                }
                ruleTable.repaint();
            }
        });


        // "只看精确率为高"按钮的事件
        aboveHighItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 清除表格的所有行
                tableModel.setRowCount(0);
                // 重新添加匹配搜索文本的行
                int counter=1;
                // 清空映射
                tableToModelIndexMap.clear();

                // 重新添加匹配搜索文本的行，并更新映射
                for (int i = 0; i < BurpExtender.fingerprintRules.size(); i++) {
                    FingerPrintRule rule = BurpExtender.fingerprintRules.get(i);
                    // 保存当前规则在模型列表中的索引
                    tableToModelIndexMap.add(i);
                    //开启high级别的规则
                    rule.setOpen(rule.getAccuracy().equals("high"));
                    tableModel.addRow(new Object[]{
                            counter,
                            rule.getType(),
                            rule.getDescribe(),
                            rule.getIsImportant(),
                            rule.getAccuracy(),
                            rule.getMatch(), // 获取method信息
                            rule.getLocation(), // 获取location信息
                            String.join(",", rule.getKeyword()),
                            new String[] {"IsOpen", "Edit", "Delete"} // 操作按钮
                    });
                    counter ++;
                }
                ruleTable.repaint();
            }
        });
        
        // 在新增按钮的点击事件中添加以下代码来设置 typeField 的值
        addButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //初始化建立一个隐藏的配置编辑框
                if (editRulePanel == null)
                    initEditRulePanel();

                // 清空编辑面板的文本字段
                editRulePanel.setTitle("新增指纹");
                isImportantField.setSelectedItem(Boolean.TRUE); // 默认设置为重要
                searchMethodField.setSelectedItem("keyword"); // 默认方法设置为 keyword
                updateLocationField("keyword"); // 根据默认的方法更新 locationField
                keywordField.setText("");

                // 更新 typeField 下拉选项
                updateTypeField(); // 确保调用此方法以更新 JComboBox 的选项

                // 设置编辑面板的位置并显示
                Point locationOnScreen = ((Component)e.getSource()).getLocationOnScreen();
                editRulePanel.setLocation(locationOnScreen.x + 70, locationOnScreen.y);  // 设置编辑面板的位置
                editRulePanel.setVisible(true);  // 显示编辑面板
            }
        });


        // 点击”功能“的监听事件
        moreFunctionsButton.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                popupMenu.show(e.getComponent(), e.getX(), e.getY());
            }
        });

        // 点击导出按钮
        exportItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String configToJson = currentConfigToJsonString();

                // 弹出文件选择对话框，让用户选择保存位置
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("保存为");
                fileChooser.setFileFilter(new FileNameExtensionFilter("JSON文件 (*.json)", "json"));
                int userSelection = fileChooser.showSaveDialog(FingerConfigTab.this);

                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File fileToSave = fileChooser.getSelectedFile();
                    // 确保文件有.json扩展名
                    if (!fileToSave.getAbsolutePath().endsWith(".json")) {
                        fileToSave = new File(fileToSave + ".json");
                    }

                    try {
                        BurpFileUtils.writeToFile(fileToSave, configToJson);
                        JOptionPane.showMessageDialog(FingerConfigTab.this, "数据已导出至: " + fileToSave.getAbsolutePath(), "导出成功", JOptionPane.INFORMATION_MESSAGE);
                    } catch (IOException ex) {
                        JOptionPane.showMessageDialog(FingerConfigTab.this, "写入文件时发生错误: " + ex.getMessage(), "导出失败", JOptionPane.ERROR_MESSAGE);
                    }
                }
            }
        });


        // 点击导入按钮
        importItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 弹出文件选择对话框，让用户选择 JSON 文件
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("请选择规则配置文件");
                fileChooser.setFileFilter(new FileNameExtensionFilter("JSON文件 (*.json)", "json"));
                int userSelection = fileChooser.showOpenDialog(FingerConfigTab.this);

                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File fileToOpen = fileChooser.getSelectedFile();

                    try (FileInputStream fis = new FileInputStream(fileToOpen);
                         BufferedReader reader = new BufferedReader(new InputStreamReader(fis, StandardCharsets.UTF_8))) {
                        // Fastjson内部会处理好流的读取与关闭
                        FingerPrintRulesWrapper rulesWrapper = JSON.parseObject(reader, FingerPrintRulesWrapper.class);
                        List<FingerPrintRule> rules = rulesWrapper.getFingerprint();
                        rulesWrapper.setFingerprint(rules);

                        // 清空原列表，并将新数据添加到原列表
                        synchronized (BurpExtender.fingerprintRules) {
                            // 清空原列表，并将新数据添加到原列表
                            BurpExtender.fingerprintRules.clear();
                            BurpExtender.fingerprintRules.addAll(rulesWrapper.getFingerprint());
                        }

                        // 清除表格的所有行
                        tableModel.setRowCount(0);

                        // 添加所有的行
                        int counter = 1;
                        for (FingerPrintRule rule : BurpExtender.fingerprintRules){
                            tableModel.addRow(new Object[]{
                                    counter,
                                    rule.getType(),
                                    rule.getDescribe(),
                                    rule.getIsImportant(),
                                    rule.getAccuracy(),
                                    rule.getMatch(), // 获取 method 信息
                                    rule.getLocation(), // 获取 location 信息
                                    String.join(",", rule.getKeyword()),
                                    new String[] {"IsOpen", "Edit", "Delete"} // 操作按钮
                            });
                            counter ++;
                        }

                        JOptionPane.showMessageDialog(FingerConfigTab.this, "数据已从: " + fileToOpen.getAbsolutePath() + " 导入", "导入成功", JOptionPane.INFORMATION_MESSAGE);
                        tableModel.fireTableDataChanged();  //通知所有依赖于该数据模型的组件，特别是JTable，数据模型中的数据已经发生了改变，从而触发UI的更新。
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(FingerConfigTab.this, "读取文件或解析 JSON 数据时发生错误: " + ex.getMessage(), "导入失败", JOptionPane.ERROR_MESSAGE);
                        stderr_println(ex.getMessage());
                    }
                }
            }
        });


        // 点击重置按钮
        resetItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 获取类加载器
                ClassLoader classLoader = getClass().getClassLoader();
                InputStream inputStream = classLoader.getResourceAsStream("conf/finger-important.json");
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
                    FingerPrintRulesWrapper rulesWrapper  = JSON.parseObject(reader, FingerPrintRulesWrapper.class);
                    // 清空原列表，并将新数据添加到原列表
                    synchronized (BurpExtender.fingerprintRules) {
                        // 清空原列表，并将新数据添加到原列表
                        BurpExtender.fingerprintRules.clear();
                        BurpExtender.fingerprintRules.addAll(rulesWrapper.getFingerprint());
                    }

                    // 清除表格的所有行
                    tableModel.setRowCount(0);

                    // 添加所有的行
                    int counter = 1;
                    for (FingerPrintRule rule : BurpExtender.fingerprintRules){
                        tableModel.addRow(new Object[]{
                                counter,
                                rule.getType(),
                                rule.getDescribe(),
                                rule.getIsImportant(),
                                rule.getAccuracy(),
                                rule.getMatch(), // 获取 method 信息
                                rule.getLocation(), // 获取 location 信息
                                String.join(",", rule.getKeyword()),
                                new String[] {"IsOpen", "Edit", "Delete"} // 操作按钮
                        });
                        counter ++;
                    }

                    JOptionPane.showMessageDialog(FingerConfigTab.this, "数据已重置到最原始状态", "重置成功",  JOptionPane.INFORMATION_MESSAGE);
                    tableModel.fireTableDataChanged();
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(FingerConfigTab.this, "数据已重置失败： " + ex.getMessage(), "重置失败", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        // 点击保存按钮
        saveItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String json = currentConfigToJsonString();
                try {
                    // 使用UTF-8编码写入文件
                    BurpFileUtils.writeToPluginPathFile(BurpExtender.configName, json);
                    JOptionPane.showMessageDialog(FingerConfigTab.this, "指纹已保存，下次启动使用该指纹", "保存成功",  JOptionPane.INFORMATION_MESSAGE);
                } catch (IOException ex) {
                    JOptionPane.showMessageDialog(FingerConfigTab.this, "指纹保存失败： " + ex.getMessage(), "保存失败", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        //将工具行添加到窗口中
        add(toolbar, BorderLayout.NORTH);

        //初始化表格数据
        initTableContentModel();
        //创建了一个新的JTable对象，并将之前定义的tableModel 作为数据模型赋给这个表格。表格将根据数据模型中提供的数据来显示内容，包括行数、列数及每个单元格的具体数据。
        ruleTable = new JTable(tableModel);
        setRuleTableStyle(ruleTable);

        //add函数用于向容器（如JFrame, JPanel等）添加组件的方法。
        add(new JScrollPane(ruleTable), BorderLayout.CENTER);
    }


    /**
     * 保存指纹的函数,不进行弹框提示
     */
    public static void saveConfigToDefaultJson() {
        String json = currentConfigToJsonString();
        try {
            // 使用UTF-8编码写入文件
            BurpFileUtils.writeToPluginPathFile(BurpExtender.configName, json);
            stdout_println(LOG_ERROR, "更新保存规则文件完成...");
        } catch (IOException e) {
            stderr_println(LOG_ERROR, String.format("更新保存规则文件异常...%s", e.getMessage()));
        }
    }

    /**
     * 将当前内存中的配置规则转为Json字符串
     */
    private static String currentConfigToJsonString() {
        List<FingerPrintRule> rulesToExport = BurpExtender.fingerprintRules;
        // 创建一个新的 FingerPrintRulesWrapper 并设置 fingerprint 列表
        FingerPrintRulesWrapper wrapper = new FingerPrintRulesWrapper();
        wrapper.setFingerprint(rulesToExport);

        // 将 wrapper 对象转换为 JSON 格式
        String json = JSON.toJSONString(wrapper, JSONWriter.Feature.PrettyFormat);
        return json;
    }

    //设置规则表格的表样式和点击动作
    private void setRuleTableStyle(JTable ruleTable) {
        CenterRenderer centerRenderer = new CenterRenderer();

        LeftRenderer leftRenderer = new LeftRenderer();

        int minColumnWidth = 100;
        ruleTable.getColumnModel().getColumn(0).setCellRenderer(leftRenderer);
        ruleTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        ruleTable.getColumnModel().getColumn(0).setMaxWidth(50);

        ruleTable.getColumnModel().getColumn(1).setCellRenderer(leftRenderer);
        ruleTable.getColumnModel().getColumn(1).setPreferredWidth(200);
        ruleTable.getColumnModel().getColumn(1).setMaxWidth(300);

        ruleTable.getColumnModel().getColumn(2).setCellRenderer(leftRenderer);
        ruleTable.getColumnModel().getColumn(2).setPreferredWidth(200);
        ruleTable.getColumnModel().getColumn(2).setMaxWidth(300);

        ruleTable.getColumnModel().getColumn(3).setCellRenderer(centerRenderer);
        ruleTable.getColumnModel().getColumn(3).setPreferredWidth(minColumnWidth);
        ruleTable.getColumnModel().getColumn(3).setMaxWidth(minColumnWidth);

        ruleTable.getColumnModel().getColumn(4).setCellRenderer(centerRenderer);
        ruleTable.getColumnModel().getColumn(4).setPreferredWidth(minColumnWidth);
        ruleTable.getColumnModel().getColumn(4).setMaxWidth(minColumnWidth);

        ruleTable.getColumnModel().getColumn(5).setCellRenderer(centerRenderer);
        ruleTable.getColumnModel().getColumn(5).setPreferredWidth(minColumnWidth);
        ruleTable.getColumnModel().getColumn(5).setMaxWidth(minColumnWidth);

        ruleTable.getColumnModel().getColumn(6).setCellRenderer(centerRenderer);
        ruleTable.getColumnModel().getColumn(6).setPreferredWidth(minColumnWidth);
        ruleTable.getColumnModel().getColumn(6).setMaxWidth(minColumnWidth);

        ruleTable.getColumnModel().getColumn(7).setCellRenderer(leftRenderer);
        ruleTable.getColumnModel().getColumn(7).setPreferredWidth(300);

        // 设置操作列的宽度以适应两个按钮
        int actionColumnWidth = 100;  // 假设每个按钮宽度为70，中间间隔10
        ruleTable.getColumnModel().getColumn(8).setPreferredWidth(actionColumnWidth);
        ruleTable.getColumnModel().getColumn(8).setMaxWidth(actionColumnWidth);
        ruleTable.getColumnModel().getColumn(8).setCellRenderer(new ButtonRenderer());
        ruleTable.getColumnModel().getColumn(8).setCellEditor(new ButtonEditor(ruleTable));

        // 在FingerConfigTab构造函数中设置表头渲染器和监听器的代码
        //JTableHeader是JTable顶部显示列名的部分，允许用户对列进行排序、调整列宽等 自定义设置
        JTableHeader tableHeader = ruleTable.getTableHeader();
        //获取 type所在的列 // 假定类型列的索引是1
        TableColumn typeColumn = tableHeader.getColumnModel().getColumn(1);

        // 设置表头渲染器
        typeColumn.setHeaderRenderer(new HeaderIconTypeRenderer());

        // 在您的FingerConfigTab构造函数中 为数据表头添加操作函数
        tableHeader.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (ruleTable.getColumnModel().getColumnIndexAtX(e.getX()) == 1) { // 假设类型列的索引是1
                    //显示 表头 类型 点击动作
                    showFilterPopup(e.getComponent(), e.getX(), e.getY());
                }
            }
        });
    }

    // 初始化表格数据
    private void initTableContentModel() {
        // 表格数据
        tableModel = new DefaultTableModel(new Object[]{"#", "type", "describe", "isImportant", "accuracy", "Match", "location", "keyword", "Action"}, 0) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                switch (columnIndex) {
                    case 8:
                        return JButton.class;
                    default:
                        return super.getColumnClass(columnIndex);
                }
            }
        };
        //创建了一个新的DefaultTableModel实例，它将用于存储表格的数据和定义列的属性
        //指定列名分别是 "#", "type", "describe", "isImportant", "accuracy", "Match", "location", "keyword", "Action"，而0表示初始时不创建任何行。
        //匿名内部类的方式去扩展DefaultTableModel，目的是为了重写getColumnClass方法，实现自定义列的行为
        //表示第9列 Action 的数据类型被指定为JButton.class。这意味着这一列的每个单元格都可以显示一个按钮。 对于其他列，使用默认的行为，即根据数据的实际类型来决定。

        int counter = 1;
        tableToModelIndexMap.clear();
        for (int i = 0; i < BurpExtender.fingerprintRules.size(); i++) {
            FingerPrintRule rule = BurpExtender.fingerprintRules.get(i);
            tableToModelIndexMap.add(i);
            uniqueTypes.add(rule.getType());
            tableModel.addRow(new Object[]{
                    counter,
                    rule.getType(),
                    rule.getDescribe(),
                    rule.getIsImportant(),
                    rule.getAccuracy(),
                    rule.getMatch(), // 获取method信息
                    rule.getLocation(), // 获取location信息
                    String.join(",", rule.getKeyword()),
                    new String[] {"IsOpen", "Edit", "Delete"} // 操作按钮
            });
            counter ++;
        }
    }

    //初始化建立一个隐藏的配置编辑框
    private void initEditRulePanel() {
        // 编辑页面框
        editRulePanel = new JDialog();
        editRulePanel.setTitle("新增指纹");
        editRulePanel.setLayout(new GridBagLayout());  // 更改为 GridBagLayout
        editRulePanel.setSize(500, 450);
        editRulePanel.setDefaultCloseOperation(JDialog.HIDE_ON_CLOSE);
        editRulePanel.setModal(false);
        editRulePanel.setResizable(true);

        typeField = new JComboBox<>();
        typeField.setEditable(true);
        isImportantField = new JComboBox<>(new Boolean[]{true, false});
        searchMethodField = new JComboBox<>(new String[]{"keyword", "regular"});
        accuracyFiled = new JComboBox<>(new String[]{"high", "medium", "lower"});
        locationField = new JComboBox<>();
        keywordField = new JTextArea(5, 20); // 5行，20列
        describeField = new JTextField("-");
        searchMethodField.setSelectedItem("keyword");
        updateLocationField("keyword");

        // 创建 GridBagConstraints 对象来控制每个组件的布局
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.anchor = GridBagConstraints.WEST;  // 紧靠左边
        constraints.fill = GridBagConstraints.HORIZONTAL;  // 水平填充
        constraints.insets = new Insets(10, 10, 10, 10);  // 设置内边距为10像素

        // 添加 "Type" 标签
        constraints.gridx = 0;  // 在网格的第一列添加组件
        constraints.gridy = 0;  // 在网格的第一行添加组件
        constraints.weightx = 0;  // 不允许横向扩展
        editRulePanel.add(new JLabel("Type:"), constraints);

        // 添加 "Type" 输入框
        constraints.gridx = 1;  // 在网格的第二列添加组件
        constraints.weightx = 1.0;  // 允许横向扩展
        editRulePanel.add(typeField, constraints);

        // 添加 "describeField" 标签
        constraints.gridx = 0;  // 在网格的第一列添加组件
        constraints.gridy = 2;  // 在网格的第一行添加组件
        constraints.weightx = 0;  // 不允许横向扩展
        editRulePanel.add(new JLabel("Describe:"), constraints);

        // 添加 "describeField" 输入框
        constraints.gridx = 1;  // 在网格的第二列添加组件
        constraints.weightx = 1.0;  // 允许横向扩展
        editRulePanel.add(describeField, constraints);

        // 添加 "isImportant" 标签
        constraints.gridx = 0;  // 在网格的第一列添加组件
        constraints.gridy = 3;  // 在网格的第一行添加组件
        constraints.weightx = 0;  // 不允许横向扩展
        editRulePanel.add(new JLabel("IsImportant:"), constraints);

        // 添加 "isImportant" 输入框
        constraints.gridx = 1;  // 在网格的第二列添加组件
        constraints.weightx = 1.0;  // 允许横向扩展
        editRulePanel.add(isImportantField, constraints);

        // 添加 "accuracyFiled" 标签
        constraints.gridx = 0;  // 在网格的第一列添加组件
        constraints.gridy = 4;  // 在网格的第一行添加组件
        constraints.weightx = 0;  // 不允许横向扩展
        editRulePanel.add(new JLabel("accuracyFiled:"), constraints);

        // 添加 "accuracyFiled" 输入框
        constraints.gridx = 1;  // 在网格的第二列添加组件
        constraints.weightx = 1.0;  // 允许横向扩展
        editRulePanel.add(accuracyFiled, constraints);

        // 添加 "Method" 标签
        constraints.gridx = 0;  // 在网格的第一列添加组件
        constraints.gridy = 5;  // 在网格的第二行添加组件
        constraints.weightx = 0;  // 不允许横向扩展
        editRulePanel.add(new JLabel("Match:"), constraints);

        // 添加 "Method" 输入框
        constraints.gridx = 1;  // 在网格的第二列添加组件
        constraints.weightx = 1.0;  // 允许横向扩展
        editRulePanel.add(searchMethodField, constraints);

        // 添加 "Location" 标签
        constraints.gridx = 0;  // 在网格的第一列添加组件
        constraints.gridy = 6;  // 在网格的第三行添加组件
        constraints.weightx = 0;  // 不允许横向扩展
        editRulePanel.add(new JLabel("Location:"), constraints);

        // 添加 "Location" 输入框
        constraints.gridx = 1;  // 在网格的第二列添加组件
        constraints.weightx = 1.0;  // 允许横向扩展
        editRulePanel.add(locationField, constraints);

        // 添加 "Keyword" 标签
        constraints.gridx = 0;  // 在网格的第一列添加组件
        constraints.gridy = 7;  // 在网格的第四行添加组件
        constraints.weightx = 0;  // 不允许横向扩展
        editRulePanel.add(new JLabel("Keyword:"), constraints);

        // 添加 "Keyword" 输入框
        constraints.gridx = 1;  // 在网格的第二列添加组件
        constraints.weightx = 1.0;  // 允许横向扩展
        // 设置 GridBagConstraints 来跨越多行和列
        constraints.gridy = 7;  // 在网格的第四行开始添加组件
        constraints.gridwidth = 1; // 占据一列
        //constraints.weighty = 0;  // 允许在垂直方向上伸展
        JScrollPane keywordFieldScrollPane = new JScrollPane(keywordField); // 包装 JTextArea 到 JScrollPane 中
        editRulePanel.add(keywordFieldScrollPane, constraints);


        // 根据需要，为 Location 和 Keyword 输入框设置首选大小
        typeField.setPreferredSize(new Dimension(100, typeField.getPreferredSize().height));
        isImportantField.setPreferredSize(new Dimension(100, isImportantField.getPreferredSize().height));
        searchMethodField.setPreferredSize(new Dimension(100, searchMethodField.getPreferredSize().height));
        locationField.setPreferredSize(new Dimension(100, locationField.getPreferredSize().height));

        JButton saveButton = new JButton("Save");
        saveButton.setIcon(UiUtils.getImageIcon("/icon/saveItem.png"));

        // 在构造函数中为 methodField 添加事件监听器，以便动态更新 locationField 的选项
        searchMethodField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JComboBox<String> methodCombo = (JComboBox<String>) e.getSource();
                String selectedMethod = (String) methodCombo.getSelectedItem();
                updateLocationField(selectedMethod); // 根据选择更新 locationField
            }
        });

        // 修改保存按钮的点击事件监听器
        saveButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 获取用户选择或输入的type值
                String type = (String) typeField.getEditor().getItem(); // 对于可编辑的JComboBox，使用getEditor().getItem()来获取文本字段中的值
                uniqueTypes.add(type);
                if (type != null) {
                    type = type.trim(); // 清除前后空格
                }
                Boolean isImportant = (Boolean) isImportantField.getSelectedItem();
                String accuracy = (String) accuracyFiled.getSelectedItem();
                String method = (String) searchMethodField.getSelectedItem();
                String location = (String) locationField.getSelectedItem();
                String describe = describeField.getText();
                List<String> keyword;
//                if (method.equals("regular")){
//                    keyword = Collections.singletonList(keywordField.getText());
//                }else{
//                    keyword = Arrays.asList(keywordField.getText().split(","));
//                }
                keyword = Arrays.asList(keywordField.getText().split("\n"));
                if (type.trim().isEmpty() || method.trim().isEmpty() ||
                        location.trim().isEmpty() || keyword.stream().allMatch(String::isEmpty)) {
                    JOptionPane.showMessageDialog(editRulePanel, "所有输入框都必须填写。", "输入错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                if (editingRow != null) {
                    // 如果是编辑现有规则，更新数据源和表格模型中的数据
                    FingerPrintRule rule = BurpExtender.fingerprintRules.get(editingRow);
                    rule.setType(type);
                    rule.setDescribe(describe);
                    rule.setIsImportant(isImportant);
                    rule.setAccuracy(accuracy);
                    rule.setMatch(method);
                    rule.setLocation(location);
                    rule.setKeyword(keyword);

                    // 更新表格模型
                    tableModel.setValueAt(type, ruleTable.getSelectedRow(), 1);
                    tableModel.setValueAt(describe, ruleTable.getSelectedRow(), 2);
                    tableModel.setValueAt(isImportant, ruleTable.getSelectedRow(), 3);
                    tableModel.setValueAt(accuracy, ruleTable.getSelectedRow(), 4);
                    tableModel.setValueAt(method, ruleTable.getSelectedRow(), 5); // 假设Method列是第3列
                    tableModel.setValueAt(location, ruleTable.getSelectedRow(), 6); // 假设Location列是第4列
                    tableModel.setValueAt(String.join(",", keyword), ruleTable.getSelectedRow(), 7); // 假设Keyword列是第5列

                    // 通知模型数据已更新，触发表格重绘
                    tableModel.fireTableRowsUpdated(ruleTable.getSelectedRow(), ruleTable.getSelectedRow());
                    // 关闭编辑面板
                    editRulePanel.setVisible(false);

                    // 重置编辑行索引
                    editingRow = null;
                } else {
                    // 创建新的 FingerPrintRule 对象
                    FingerPrintRule newRule = new FingerPrintRule(type, describe, isImportant, method, location, keyword, true, accuracy);
                    synchronized (BurpExtender.fingerprintRules) {
                        // 将新规则添加到数据源的开始位置
                        BurpExtender.fingerprintRules.add(0, newRule);
                        // 更新表格模型
                        ((DefaultTableModel) ruleTable.getModel()).insertRow(0, new Object[]{
                                1, // 新行的序号始终为1
                                newRule.getType(),
                                newRule.getDescribe(),
                                newRule.getIsImportant(),
                                newRule.getAccuracy(),
                                newRule.getMatch(),
                                newRule.getLocation(),
                                String.join(",", newRule.getKeyword()),
                                new String[]{"Edit", "Delete"} // 操作按钮
                        });
                        // 更新映射列表，因为添加了新的数据项
                        tableToModelIndexMap.add(0, 0); // 在映射列表的开始位置添加新项
                        // 由于添加了新元素，更新所有行的序号
                        for (int i = 1; i < ruleTable.getRowCount(); i++) {
                            ruleTable.getModel().setValueAt(i + 1, i, 0);
                        }
                        // 更新后续映射的索引
                        for (int i = 1; i < tableToModelIndexMap.size(); i++) {
                            tableToModelIndexMap.set(i, tableToModelIndexMap.get(i) + 1);
                        }
                    }

                    // 关闭编辑面板
                    editRulePanel.setVisible(false);
                    // 通知模型数据已更新，触发表格重绘
                    tableModel.fireTableDataChanged();
                }

                //重新加载配置文件中的CONF_列
                reloadConfFromRules(BurpExtender.fingerprintRules);
            }
        });
        editRulePanel.add(saveButton);
    }

    //从规则里面重新提取全部配置
    private void reloadConfFromRules(List<FingerPrintRule> fingerprintRules) {
        BurpExtender.CONF_WHITE_URL_ROOT = new ArrayList<>(); //仅扫描的URL
        BurpExtender.CONF_ALLOW_RECORD_STATUS = new ArrayList<>(); //作为正常访问结果的状态码
        BurpExtender.CONF_NOT_AUTO_RECORD = new ArrayList<>(); //不自动记录PATH的URL域名
        BurpExtender.CONF_NOT_AUTO_RECURSE = new ArrayList<>(); //不自动进行递归扫描的URL域名

        BurpExtender.CONF_BLACK_URL_EXT = new ArrayList<>(); //不检查的URL后缀
        BurpExtender.CONF_BLACK_URL_PATH = new ArrayList<>(); //不检查的URL路径
        BurpExtender.CONF_BLACK_URL_ROOT = new ArrayList<>(); //不检查的URL域名
        BurpExtender.CONF_BLACK_PATH_KEYS = new ArrayList<>();  //需要忽略的响应提取路径 关键字
        BurpExtender.CONF_BLACK_PATH_EQUALS = new ArrayList<>();  //需要忽略的响应提取路径 完整路径
        BurpExtender.CONF_EXTRACT_SUFFIX = new ArrayList<>(); //需要提取API的URL后缀类型
        BurpExtender.CONF_BLACK_INFO_KEYS = new ArrayList<>();
        BurpExtender.CONF_URI_MATCH_REGULAR = new ArrayList<>();
        if (isNotEmptyObj(fingerprintRules)){
            for (int i = 0 ; i < fingerprintRules.size(); i ++){
                FingerPrintRule rule = fingerprintRules.get(i);
                setActionByRuleInfo(rule);
            }
        }

        BurpExtender.URI_MATCH_REGULAR_COMPILE = RegularUtils.compileUriMatchRegular(BurpExtender.CONF_URI_MATCH_REGULAR);

        stdout_println("[+] CONF_WHITE_URL_ROOT: " + BurpExtender.CONF_WHITE_URL_ROOT);

        stdout_println("[+] CONF_ALLOW_RECORD_STATUS: " + BurpExtender.CONF_ALLOW_RECORD_STATUS);
        stdout_println("[+] CONF_NOT_RECORD_TITLE: " + BurpExtender.CONF_NOT_RECORD_TITLE);

        stdout_println("[+] CONF_NOT_AUTO_RECORD: " + BurpExtender.CONF_NOT_AUTO_RECORD);
        stdout_println("[+] CONF_NOT_AUTO_RECURSE: " + BurpExtender.CONF_NOT_AUTO_RECURSE);

        stdout_println("[+] CONF_BLACK_URL_EXT: " + BurpExtender.CONF_BLACK_URL_EXT);
        stdout_println("[+] CONF_BLACK_URL_PATH: " + BurpExtender.CONF_BLACK_URL_PATH);
        stdout_println("[+] CONF_BLACK_URL_ROOT: " + BurpExtender.CONF_BLACK_URL_ROOT);
        stdout_println("[+] CONF_BLACK_PATH_KEYS: " + BurpExtender.CONF_BLACK_PATH_KEYS);
        stdout_println("[+] CONF_BLACK_PATH_EQUALS: " + BurpExtender.CONF_BLACK_PATH_EQUALS);
        stdout_println("[+] CONF_EXTRACT_SUFFIX: " + BurpExtender.CONF_EXTRACT_SUFFIX);

        stdout_println("[+] CONF_BLACK_INFO_KEYS: " + BurpExtender.CONF_BLACK_INFO_KEYS);
        stdout_println("[+] CONF_URI_MATCH_REGULAR: " + BurpExtender.CONF_URI_MATCH_REGULAR);

    }

    // 添加一个新的方法来更新 locationField 的选项
    private void updateLocationField(String method) {
        locationField.removeAllItems(); // 清除之前的选项
        if ("keyword".equals(method)) {
            locationField.addItem("body");
            locationField.addItem("urlPath");
        } else if ("regular".equals(method)) {
            locationField.addItem("body");
            locationField.addItem("urlPath");
        }
        locationField.setSelectedItem("body"); // 默认选中 "body"
    }

    /**
     * 过滤新增指纹允许的类型不包含 配置规则
     * @param types
     * @return
     */
    private String[] filterConfItems(String[] types) {
        List<String> confItems = new ArrayList<>();

        // 遍历数组并检查每个元素
        for (String type : types) {
            if (!type.startsWith(Constants.RULE_CONF_PREFIX)) {
                // 如果元素以"CONF_"开头，则不添加到confItems列表中
                confItems.add(type);
            }
        }
        // 将过滤后的List转换为数组并返回
        return confItems.toArray(new String[0]);
    }

    // 创建或更新typeField下拉框的方法
    public void updateTypeField() {
        // 将集合转换为数组
        String[] defaultTypes = uniqueTypes.toArray(new String[0]);
        //排除配置规则
        defaultTypes = filterConfItems(defaultTypes);

        // 如果typeField已经存在，那么更新它的模型
        if (typeField != null) {
            typeField.setModel(new DefaultComboBoxModel<>(defaultTypes));
        } else {
            // 否则创建新的typeField
            typeField = new JComboBox<>(defaultTypes);
            typeField.setEditable(true);
        }
    }

    //基于选定的类型过滤规则
    private void filterTableByType(String type) {
        tableModel.setRowCount(0); // 清空表格
        tableToModelIndexMap.clear(); // 清空索引映射

        int counter = 1;
        for (int i = 0; i < BurpExtender.fingerprintRules.size(); i++) {
            FingerPrintRule rule = BurpExtender.fingerprintRules.get(i);
            // 如果type为null或者与规则类型匹配，添加到表格中
            if (type == null || String_All_Type.equals(type) || rule.getType().equals(type)) {
                tableModel.addRow(new Object[]{
                        counter++,
                        rule.getType(),
                        rule.getDescribe(),
                        rule.getIsImportant(),
                        rule.getAccuracy(),
                        rule.getMatch(),
                        rule.getLocation(),
                        String.join(",", rule.getKeyword()),
                        new String[]{"Edit", "Delete"}
                });
                tableToModelIndexMap.add(i); // 将原始列表的索引添加到映射中
            }
        }
    }

    //显示规则过滤的选项框
    private void showFilterPopup(Component invoker, int x, int y) {
        JPopupMenu filterMenu = new JPopupMenu();

        // “全部”选项用于移除过滤
        JMenuItem showAllItem = new JMenuItem(String_All_Type);
        showAllItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                filterTableByType(null); // 移除过滤，显示全部
            }
        });
        filterMenu.add(showAllItem);
        filterMenu.add(new JSeparator()); // 分隔线

        // 为每个独特的类型创建菜单项
        for (String type : uniqueTypes) {
            JMenuItem menuItem = new JMenuItem(type);
            menuItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    filterTableByType(type); // 根据选中的类型过滤表格
                }
            });
            filterMenu.add(menuItem);
        }
        filterMenu.show(invoker, x, y); // 显示菜单
    }

    class ButtonEditor extends AbstractCellEditor implements TableCellEditor {
        private final JPanel panel;
        private final JButton editButton;
        private final JButton deleteButton;
        private final JButton toggleButton;
        private final Icon EDIT_ICON = UiUtils.getImageIcon("/icon/editButton.png");
        private final Icon DELETE_ICON = UiUtils.getImageIcon("/icon/deleteButton.png");
        private final Icon openIcon = UiUtils.getImageIcon("/icon/openButtonIcon.png");
        private final Icon closeIcon = UiUtils.getImageIcon("/icon/shutdownButtonIcon.png");
        private JTable fromTable;
        private int row;

        public ButtonEditor(JTable fromTable) {
            this.fromTable = fromTable;
            panel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 0));
            toggleButton = new JButton(); //开关按钮
            toggleButton.setIcon(openIcon);

            editButton = new JButton(); //编辑按钮
            editButton.setIcon(EDIT_ICON);

            deleteButton = new JButton(); //删除按钮
            deleteButton.setIcon(DELETE_ICON);

            editButton.setPreferredSize(new Dimension(17, 17));
            deleteButton.setPreferredSize(new Dimension(17, 17));
            toggleButton.setPreferredSize(new Dimension(17, 17));

            toggleButton.addActionListener(new ActionListener() {
               @Override
               public void actionPerformed(ActionEvent e) {
                   int viewRow = fromTable.getSelectedRow(); // 获取视图中选中的行
                   if (viewRow < 0) {
                       return; // 如果没有选中任何行，就不执行编辑操作
                   }
                   int modelRow = fromTable.convertRowIndexToModel(viewRow); // 转换为模型索引
                   int dataIndex = tableToModelIndexMap.get(modelRow); // 使用模型索引查找原始数据列表中的索引

                   editingRow = dataIndex; // 更新编辑行索引为原始数据列表中的索引
                   FingerPrintRule rule = BurpExtender.fingerprintRules.get(dataIndex);
                   if (rule.getIsOpen()){
                       toggleButton.setIcon(closeIcon);
                       rule.setOpen(false);
                   } else {
                       toggleButton.setIcon(openIcon);
                       rule.setOpen(true);
                   }
                   fireEditingStopped();
                   fromTable.repaint();
               }
           });

            // 在编辑按钮的 ActionListener 中添加以下代码来设置 keywordField 的值
            editButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    int viewRow = fromTable.getSelectedRow(); // 获取视图中选中的行
                    if (viewRow < 0) {
                        return; // 如果没有选中任何行，就不执行编辑操作
                    }
                    int modelRow = fromTable.convertRowIndexToModel(viewRow); // 转换为模型索引
                    int dataIndex = tableToModelIndexMap.get(modelRow); // 使用模型索引查找原始数据列表中的索引

                    // 使用原始数据列表中的索引来获取和编辑正确的规则
                    editingRow = dataIndex; // 更新编辑行索引为原始数据列表中的索引
                    FingerPrintRule rule = BurpExtender.fingerprintRules.get(dataIndex);

                    if (editRulePanel == null)
                        initEditRulePanel();

                    // 填充编辑面板的字段
                    editRulePanel.setTitle("编辑指纹");
                    typeField.getEditor().setItem(rule.getType());
                    isImportantField.setSelectedItem(rule.getIsImportant());
                    accuracyFiled.setSelectedItem(rule.getAccuracy());
                    searchMethodField.setSelectedItem(rule.getMatch());
                    locationField.setSelectedItem(rule.getLocation());
                    describeField.setText(rule.getDescribe()); // 根据 rule 的 method 更新 locationField
                    keywordField.setText(String.join("\n", rule.getKeyword())); // 设置 keywordField 的值

                    // 显示编辑面板
                    Point btnLocation = ((JButton) e.getSource()).getLocationOnScreen();
                    editRulePanel.setLocation(btnLocation.x - editRulePanel.getWidth() / 2, btnLocation.y + ((JButton) e.getSource()).getHeight());
                    editRulePanel.setVisible(true);

                    // 停止表格的编辑状态
                    fireEditingStopped();
                }
            });


            deleteButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    fireEditingStopped(); // 确保停止编辑状态
                    int viewRow = fromTable.getSelectedRow(); // 获取视图中选中的行
                    if (viewRow < 0) {
                        return; // 如果没有选中任何行，就不执行删除操作
                    }
                    int modelRow = fromTable.convertRowIndexToModel(viewRow); // 转换为模型索引
                    int dataIndex = tableToModelIndexMap.get(modelRow); // 获取实际数据索引

                    // 删除数据源中的数据
                    BurpExtender.fingerprintRules.remove(dataIndex);

                    // 更新映射
                    tableToModelIndexMap.remove(modelRow);

                    // 由于删除了一个元素，需要更新所有后续元素的索引
                    for (int i = modelRow; i < tableToModelIndexMap.size(); i++) {
                        tableToModelIndexMap.set(i, tableToModelIndexMap.get(i) - 1);
                    }

                    // 删除表格模型中的数据
                    ((DefaultTableModel) fromTable.getModel()).removeRow(viewRow);

                    // 在删除行之后，重新验证和重绘表格
                    fromTable.revalidate();
                    fromTable.repaint();

                    //重新加载系统CONF_配置
                    reloadConfFromRules(BurpExtender.fingerprintRules);
                }
            });

            panel.add(toggleButton);
            panel.add(editButton);
            panel.add(deleteButton);
            panel.setBorder(BorderFactory.createEmptyBorder());
        }

        @Override
        public Object getCellEditorValue() {
            return null;
        }

        @Override
        public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected, int row, int column) {
            this.row = table.convertRowIndexToModel(row); // 转换为模型索引，以防有排序
            return panel;
        }
    }
}