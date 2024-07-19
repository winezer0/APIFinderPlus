package ui.MainTabRender;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

// 自定义渲染器类
public class StatusCellRenderer extends DefaultTableCellRenderer {

    private static final long serialVersionUID = 1L;

    public StatusCellRenderer() {
        setHorizontalAlignment(CENTER); // 设置居中
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        Integer infoNum = (Integer) value;

        if (infoNum != null) {
            if (infoNum > 0) {
                setBackground(Color.GREEN); // 状态为 true 时的背景颜色
            } else {
                setBackground(Color.RED);   // 状态为 false 时的背景颜色
            }
        } else {
            setBackground(table.getBackground()); // 如果值为空或不是布尔值，则使用默认背景色
        }

        return this;
    }
}