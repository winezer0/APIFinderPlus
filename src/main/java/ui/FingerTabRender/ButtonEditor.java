package ui.FingerTabRender;

import burp.BurpExtender;
import model.FingerPrintRule;
import ui.RuleConfigPanel;
import utils.UiUtils;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellEditor;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class ButtonEditor extends AbstractCellEditor implements TableCellEditor {
    private final JPanel buttonsPanel;
    private final JButton editButton;
    private final JButton deleteButton;
    private final JButton toggleButton;
    private final Icon EDIT_ICON = UiUtils.getImageIcon("/icon/editButton.png");
    private final Icon DELETE_ICON = UiUtils.getImageIcon("/icon/deleteButton.png");
    private final Icon openIcon = UiUtils.getImageIcon("/icon/openButtonIcon.png");
    private final Icon closeIcon = UiUtils.getImageIcon("/icon/shutdownButtonIcon.png");

    public ButtonEditor(JTable sourceTable) {
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
                int viewRow = sourceTable.getSelectedRow(); // 获取视图中选中的行
                if (viewRow < 0) {
                    return; // 如果没有选中任何行，就不执行编辑操作
                }
                int modelRow = sourceTable.convertRowIndexToModel(viewRow); // 转换为模型索引
                int dataIndex = RuleConfigPanel.tableToModelIndexMap.get(modelRow); // 使用模型索引查找原始数据列表中的索引

                RuleConfigPanel.editingRow = dataIndex; // 更新编辑行索引为原始数据列表中的索引
                FingerPrintRule rule = BurpExtender.fingerprintRules.get(dataIndex);
                if (rule.getIsOpen()) {
                    toggleButton.setIcon(closeIcon);
                    rule.setOpen(false);
                } else {
                    toggleButton.setIcon(openIcon);
                    rule.setOpen(true);
                }
                fireEditingStopped();
                sourceTable.repaint();
            }
        });

        // 在编辑按钮的 ActionListener 中添加以下代码来设置 keywordField 的值
        editButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                int viewRow = sourceTable.getSelectedRow(); // 获取视图中选中的行
                if (viewRow < 0) {
                    return; // 如果没有选中任何行，就不执行编辑操作
                }
                int modelRow = sourceTable.convertRowIndexToModel(viewRow); // 转换为模型索引

                //加载规则编辑面板
                RuleConfigPanel.showRuleEditorPanel(modelRow);

/*
                //跟随标签显示 优化版本
                Point btnLocation = ((JButton) e.getSource()).getLocationOnScreen();
                // 计算面板的左上角新位置
                int newX = btnLocation.x - fingerConfigTab.editRulePanel.getWidth() - 20; //水平方向，从左向右增加。
                int newY = btnLocation.y + ((JButton) e.getSource()).getHeight(); //垂直方向，从上向下增加。
                // 获取容器的大小
                Dimension containerSize = sourceTable.getSize();
                // 获取面板的大小
                Dimension panelSize = fingerConfigTab.editRulePanel.getPreferredSize();
                // 检查面板是否会超出容器的底部边界
                if (newY + panelSize.height > containerSize.height){
                // 如果会超出底部边界，则将面板移到按钮上方
                    newY = btnLocation.y - panelSize.height - 50;
                }
*/

                fireEditingStopped(); // 停止表格的编辑状态
            }
        });

        deleteButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                fireEditingStopped(); // 确保停止编辑状态
                int viewRow = sourceTable.getSelectedRow(); // 获取视图中选中的行
                if (viewRow < 0) {
                    return; // 如果没有选中任何行，就不执行删除操作
                }
                int modelRow = sourceTable.convertRowIndexToModel(viewRow); // 转换为模型索引
                int dataIndex = RuleConfigPanel.tableToModelIndexMap.get(modelRow); // 获取实际数据索引

                // 删除数据源中的数据
                BurpExtender.fingerprintRules.remove(dataIndex);

                // 更新映射
                RuleConfigPanel.tableToModelIndexMap.remove(modelRow);

                // 由于删除了一个元素，需要更新所有后续元素的索引
                for (int i = modelRow; i < RuleConfigPanel.tableToModelIndexMap.size(); i++) {
                    RuleConfigPanel.tableToModelIndexMap.set(i, RuleConfigPanel.tableToModelIndexMap.get(i) - 1);
                }

                // 删除表格模型中的数据
                ((DefaultTableModel) sourceTable.getModel()).removeRow(viewRow);

                // 在删除行之后，重新验证和重绘表格
                sourceTable.revalidate();
                sourceTable.repaint();

                //重新加载系统CONF_配置
                RuleConfigPanel.reloadConfFromRules(BurpExtender.fingerprintRules);
            }
        });

        //把三个按钮放在一个小面板中
        buttonsPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 0));
        buttonsPanel.add(toggleButton);
        buttonsPanel.add(editButton);
        buttonsPanel.add(deleteButton);
        buttonsPanel.setBorder(BorderFactory.createEmptyBorder());
    }

    @Override
    public Object getCellEditorValue() {
        return null;
    }

    @Override
    public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected, int row, int column) {
        return buttonsPanel;
    }
}
